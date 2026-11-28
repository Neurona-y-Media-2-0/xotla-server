use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    Json,
};
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;
use crate::{
    db::sha256_hex,
    modules::enterprise::{
        dto::{
            AllocateCompanyRequest, BindTokenRequest, EnterpriseClientToken,
            GenerateTempPasswordRequest, IssueClientTokenRequest, PortalCreateUserTokenRequest,
            PortalLoginRequest, RevokeTokenRequest, ToggleAccountStatusRequest,
            UpdateCompanySitePolicyRequest,
        },
        service::{
            create_enterprise_account_with_pool, generate_company_token_id, generate_temp_password,
            get_enterprise_account, issue_or_activate_client_token, update_company_quota,
            DEFAULT_COMPANY_ID,
        },
    },
    state::AppState,
};

pub async fn enterprise_admin_page_handler() -> Html<&'static str> {
    Html(include_str!("admin_tokens.html"))
}

pub async fn company_portal_page_handler() -> impl IntoResponse {
    (
        [
            (header::CACHE_CONTROL, "no-store, no-cache, must-revalidate, max-age=0"),
            (header::PRAGMA, "no-cache"),
            (header::EXPIRES, "0"),
        ],
        Html(include_str!("company_portal.html")),
    )
}

fn resolve_portal_company(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<Value>)> {
    let tok = headers
        .get("x-portal-token")
        .or_else(|| headers.get(header::AUTHORIZATION))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_start_matches("Bearer ").trim().to_string())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Inicia sesion en el portal de empresa" })),
            )
        })?;

    if let Some(entry) = state.portal_sessions.get(&tok) {
        return Ok(entry.value().clone());
    }

    if let Some(cid) = state.db.lookup_portal_session(&tok) {
        state.portal_sessions.insert(tok.clone(), cid.clone());
        return Ok(cid);
    }

    Err((
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "Sesion expirada, vuelve a iniciar sesion" })),
    ))
}

pub async fn portal_login_handler(
    State(state): State<AppState>,
    Json(req): Json<PortalLoginRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let pw_hash = sha256_hex(req.password.trim());
    let account = state
        .db
        .authenticate_company_login(&req.email, &pw_hash)
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Correo o contrasena invalidos (o cuenta inhabilitada)" })),
            )
        })?;

    let portal_token = format!("portal_sess_{}", Uuid::new_v4().simple());
    state
        .portal_sessions
        .insert(portal_token.clone(), account.company_id.clone());
    state
        .db
        .save_portal_session(&portal_token, &account.company_id, &account.master_account_email);

    Ok(Json(json!({
        "status": "AUTHENTICATED",
        "portal_token": portal_token,
        "enterprise_account": account
    })))
}

pub async fn portal_logout_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<Value> {
    if let Some(tok) = headers
        .get("x-portal-token")
        .and_then(|v| v.to_str().ok())
    {
        let t = tok.trim();
        state.portal_sessions.remove(t);
        state.db.delete_portal_session(t);
    }
    Json(json!({ "status": "LOGGED_OUT" }))
}

pub async fn portal_me_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let cid = resolve_portal_company(&state, &headers)?;
    let account = state.db.load_enterprise_account(&cid);
    let tokens = state.db.load_enterprise_tokens(&cid);
    let site_policy = state.db.load_company_site_policy(&cid);
    let total_tokens_created = state.db.count_company_non_revoked_tokens(&cid);

    let all_registered_devices = state.db.load_all_devices();
    let mut company_device_ids = std::collections::HashSet::new();
    for t in &tokens {
        if let Some(ref d1) = t.assigned_device_id {
            company_device_ids.insert(d1.clone());
        }
        if let Some(ref d2) = t.secondary_device_id {
            company_device_ids.insert(d2.clone());
        }
    }
    let company_devices: Vec<_> = all_registered_devices
        .into_iter()
        .filter(|d| company_device_ids.contains(&d.device_id) || company_device_ids.contains(&d.hardware_id))
        .collect();

    Ok(Json(json!({
        "enterprise_account": account,
        "total_tokens_in_pool": total_tokens_created,
        "can_create_more": total_tokens_created < account.total_allocated_tokens,
        "tokens": tokens,
        "devices": company_devices,
        "site_policy": site_policy
    })))
}

pub async fn portal_delete_token_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let cid = resolve_portal_company(&state, &headers)?;
    state.db.delete_company_token(&cid, &token_id);
    let account = state.db.load_enterprise_account(&cid);
    let tokens = state.db.load_enterprise_tokens(&cid);
    let total_tokens_created = state.db.count_company_non_revoked_tokens(&cid);

    Ok(Json(json!({
        "status": "TOKEN_DELETED",
        "enterprise_account": account,
        "total_tokens_in_pool": total_tokens_created,
        "tokens": tokens
    })))
}

pub async fn portal_create_token_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Option<Json<PortalCreateUserTokenRequest>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let cid = resolve_portal_company(&state, &headers)?;
    let account = state.db.load_enterprise_account(&cid);
    let current_count = state.db.count_company_non_revoked_tokens(&cid);

    if current_count >= account.total_allocated_tokens {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": format!(
                    "Ya alcanzaste tu limite contratado ({}/{} tokens). Elimina uno existente para generar otro.",
                    current_count, account.total_allocated_tokens
                )
            })),
        ));
    }

    let emp_id = body
        .as_ref()
        .and_then(|b| b.employee_id.clone())
        .filter(|s| !s.trim().is_empty());
    let label = body
        .as_ref()
        .and_then(|b| b.client_label.clone())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("Licencia #{}", current_count + 1));

    let seed = format!("{}:regen:{}", cid, Uuid::new_v4());
    let (tok_id, tok_sha) = generate_company_token_id(
        &account.company_name,
        &seed,
    );
    let now = Utc::now().to_rfc3339();

    let new_tok = EnterpriseClientToken {
        token_id: tok_id,
        company_id: cid.clone(),
        token_sha256: tok_sha,
        assigned_device_id: None,
        secondary_device_id: None,
        assigned_employee_id: emp_id,
        max_devices: 2,
        used_devices_count: 0,
        client_label: label,
        platform: "UNASSIGNED".to_string(),
        status: "AVAILABLE".to_string(),
        activated_at: now.clone(),
        last_used_at: now,
        hardware_id: None,
    };

    state.db.insert_enterprise_token(&new_tok);

    let updated_acc = state.db.load_enterprise_account(&cid);
    let tokens = state.db.load_enterprise_tokens(&cid);
    let total_tokens_created = state.db.count_company_non_revoked_tokens(&cid);

    Ok(Json(json!({
        "status": "NEW_TOKEN_CREATED",
        "new_token": new_tok,
        "enterprise_account": updated_acc,
        "total_tokens_in_pool": total_tokens_created,
        "tokens": tokens
    })))
}

pub async fn portal_update_sites_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<UpdateCompanySitePolicyRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let cid = resolve_portal_company(&state, &headers)?;

    let clean_allowed: Vec<String> = req
        .allowed_sites
        .into_iter()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| s.len() >= 3 && s.contains('.'))
        .collect();

    let clean_blacklisted: Vec<String> = req
        .blacklisted_sites
        .into_iter()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| s.len() >= 3 && s.contains('.'))
        .collect();

    let saved = state
        .db
        .save_company_site_policy(&cid, &clean_allowed, &clean_blacklisted);

    {
        let mut global_policy = state.policy.write().await;
        global_policy.trusted_download_hosts = clean_allowed.clone();
        global_policy.blacklisted_sites = clean_blacklisted.clone();
        global_policy.blocked_domains = clean_blacklisted.clone();
        global_policy
            .protected_domains
            .retain(|d| !clean_blacklisted.iter().any(|b| b == d || d.ends_with(&format!(".{}", b))));
        global_policy.version = saved.version;
    }

    Ok(Json(json!({
        "status": "SITE_POLICY_UPDATED",
        "site_policy": saved
    })))
}

pub async fn portal_incidents_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let cid = resolve_portal_company(&state, &headers)?;
    let company_tokens = state.db.load_enterprise_tokens(&cid);
    let mut dev_set = std::collections::HashSet::new();
    let mut emp_set = std::collections::HashSet::new();
    for t in &company_tokens {
        if let Some(ref d1) = t.assigned_device_id {
            dev_set.insert(d1.clone());
        }
        if let Some(ref d2) = t.secondary_device_id {
            dev_set.insert(d2.clone());
        }
        if let Some(ref emp) = t.assigned_employee_id {
            emp_set.insert(emp.clone());
        }
    }

    let all_events = state.events.read().await.clone();
    let artifacts = state.db.load_scanned_artifacts();

    let filtered_events: Vec<_> = all_events
        .into_iter()
        .filter(|e| dev_set.contains(&e.device_id) || emp_set.contains(&e.employee_id) || (cid == DEFAULT_COMPANY_ID && dev_set.is_empty()))
        .collect();

    let filtered_artifacts: Vec<_> = artifacts
        .into_iter()
        .filter(|a| dev_set.contains(&a.device_id) || emp_set.contains(&a.employee_id) || (cid == DEFAULT_COMPANY_ID && dev_set.is_empty()))
        .collect();

    Ok(Json(json!({
        "status": "OK",
        "company_id": cid,
        "total_events": filtered_events.len(),
        "total_artifacts": filtered_artifacts.len(),
        "events": filtered_events,
        "artifacts": filtered_artifacts
    })))
}

/// Incidentes por token: lee de la BD (telemetry_events + scanned_artifacts)
/// vinculados a los dispositivos asignados al token o a su empleado.
pub async fn portal_token_incidents_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let cid = resolve_portal_company(&state, &headers)?;

    let tokens = state.db.load_enterprise_tokens(&cid);
    let token = tokens
        .iter()
        .find(|t| t.token_id == token_id)
        .cloned()
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "Token no encontrado en esta cuenta" })),
            )
        })?;

    let mut devices: Vec<String> = Vec::new();
    let push_dev = |d: &str, list: &mut Vec<String>| {
        let d = d.trim();
        if !d.is_empty() && !list.iter().any(|x| x == d) {
            list.push(d.to_string());
        }
    };
    if let Some(ref d1) = token.assigned_device_id {
        push_dev(d1, &mut devices);
    }
    if let Some(ref d2) = token.secondary_device_id {
        push_dev(d2, &mut devices);
    }

    // Identificador unico de hardware (MAC/hardware_id), persistido en el token o en el registro del dispositivo
    let mut hardware: Option<String> = token.hardware_id.clone().filter(|s| !s.trim().is_empty());
    if hardware.is_none() {
        for d in devices.clone() {
            if let Some(hw) = state.db.hardware_id_for_device(&d) {
                hardware = Some(hw);
                break;
            }
        }
    }
    if let Some(ref hw) = hardware {
        push_dev(hw, &mut devices);
        // device_id canonico derivado del hardware (misma regla que el registro de dispositivos)
        let canonical = crate::modules::devices::service::build_device_id(hw);
        push_dev(&canonical, &mut devices);
    }

    let employee = token.assigned_employee_id.as_deref();

    // Incidentes directamente de la base de datos
    let events = state.db.load_events_for_token(&devices, employee);
    let artifacts = state.db.load_artifacts_for_token(&devices, employee);

    let total_events = events.len();
    let total_artifacts = artifacts.len();
    let total_incidents = total_events + total_artifacts;

    let mut by_risk_level: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    let mut by_event_type: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    let mut max_threat_score: f32 = 0.0;
    let mut max_current_risk_score: f32 = 0.0;

    let mut first_seen: Option<chrono::DateTime<Utc>> = None;
    let mut last_seen: Option<chrono::DateTime<Utc>> = None;
    let bump = |ts: chrono::DateTime<Utc>,
                    first: &mut Option<chrono::DateTime<Utc>>,
                    last: &mut Option<chrono::DateTime<Utc>>| {
        *first = Some(match first {
            Some(f) if *f <= ts => *f,
            _ => ts,
        });
        *last = Some(match last {
            Some(l) if *l >= ts => *l,
            _ => ts,
        });
    };

    for e in &events {
        *by_risk_level.entry(e.risk_level.clone()).or_insert(0) += 1;
        *by_event_type.entry(e.event_type.clone()).or_insert(0) += 1;
        if e.threat_score > max_threat_score {
            max_threat_score = e.threat_score;
        }
        if e.current_risk_score > max_current_risk_score {
            max_current_risk_score = e.current_risk_score;
        }
        bump(e.received_at, &mut first_seen, &mut last_seen);
    }

    let mut malicious_artifacts: u32 = 0;
    for a in &artifacts {
        if a.verdict.to_uppercase() != "CLEAN" && a.verdict.to_uppercase() != "BENIGN" {
            malicious_artifacts += 1;
        }
        if a.threat_score > max_threat_score {
            max_threat_score = a.threat_score;
        }
        bump(a.scanned_at, &mut first_seen, &mut last_seen);
    }

    Ok(Json(json!({
        "status": "OK",
        "company_id": cid,
        "token": token,
        "devices": devices,
        "hardware_id": hardware,
        "employee_id": employee,
        "summary": {
            "total_incidents": total_incidents,
            "total_events": total_events,
            "total_artifacts": total_artifacts,
            "malicious_artifacts": malicious_artifacts,
            "by_risk_level": by_risk_level,
            "by_event_type": by_event_type,
            "max_threat_score": max_threat_score,
            "max_current_risk_score": max_current_risk_score,
            "first_seen": first_seen.map(|d| d.to_rfc3339()),
            "last_seen": last_seen.map(|d| d.to_rfc3339()),
        },
        "events": events,
        "artifacts": artifacts,
    })))
}

pub async fn get_enterprise_overview_handler(
    State(state): State<AppState>,
) -> Json<Value> {
    let account = get_enterprise_account(&state, DEFAULT_COMPANY_ID);
    let accounts = state.db.load_all_enterprise_accounts();
    let mut all_tokens = Vec::new();
    for a in &accounts {
        all_tokens.extend(state.db.load_enterprise_tokens(&a.company_id));
    }

    Json(json!({
        "enterprise_account": account,
        "accounts": accounts,
        "client_tokens": all_tokens
    }))
}

pub async fn create_enterprise_account_handler(
    State(state): State<AppState>,
    Json(req): Json<AllocateCompanyRequest>,
) -> Json<Value> {
    let (acc, plain_pw, tokens) = create_enterprise_account_with_pool(&state, req);
    Json(json!({
        "status": "ACCOUNT_CREATED_WITH_TOKENS",
        "enterprise_account": acc,
        "temp_password": plain_pw,
        "generated_tokens": tokens
    }))
}

pub async fn edit_enterprise_account_handler(
    State(state): State<AppState>,
    Path(company_id): Path<String>,
    Json(mut req): Json<AllocateCompanyRequest>,
) -> Json<Value> {
    req.company_id = Some(company_id);
    let has_new_pw = req
        .temp_password
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);

    if has_new_pw {
        let (acc, plain_pw, tokens) = create_enterprise_account_with_pool(&state, req);
        return Json(json!({
            "status": "ACCOUNT_UPDATED",
            "enterprise_account": acc,
            "temp_password": plain_pw,
            "client_tokens": tokens
        }));
    }

    let updated = update_company_quota(&state, req);
    let tokens = state.db.load_enterprise_tokens(&updated.company_id);
    Json(json!({
        "status": "ACCOUNT_UPDATED",
        "enterprise_account": updated,
        "client_tokens": tokens
    }))
}

pub async fn toggle_enterprise_status_handler(
    State(state): State<AppState>,
    Path(company_id): Path<String>,
    Json(req): Json<ToggleAccountStatusRequest>,
) -> Json<Value> {
    let current = state.db.load_enterprise_account(&company_id);
    let next_status = req.status.unwrap_or_else(|| {
        if current.account_status == "ACTIVE" {
            "DISABLED".to_string()
        } else {
            "ACTIVE".to_string()
        }
    });
    state
        .db
        .set_enterprise_account_status(&company_id, &next_status);
    let updated = state.db.load_enterprise_account(&company_id);
    Json(json!({
        "status": "ACCOUNT_STATUS_CHANGED",
        "enterprise_account": updated
    }))
}

pub async fn delete_enterprise_account_handler(
    State(state): State<AppState>,
    Path(company_id): Path<String>,
) -> Json<Value> {
    state.db.delete_enterprise_account(&company_id);
    Json(json!({
        "status": "ACCOUNT_DELETED",
        "deleted_company_id": company_id
    }))
}

pub async fn update_enterprise_quota_handler(
    State(state): State<AppState>,
    Json(req): Json<AllocateCompanyRequest>,
) -> Json<Value> {
    let updated = update_company_quota(&state, req);
    let tokens = state.db.load_enterprise_tokens(&updated.company_id);
    Json(json!({
        "status": "QUOTA_UPDATED",
        "enterprise_account": updated,
        "client_tokens": tokens
    }))
}

pub async fn issue_enterprise_token_handler(
    State(state): State<AppState>,
    Json(req): Json<IssueClientTokenRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match issue_or_activate_client_token(&state, req) {
        Ok((tok, acc)) => Ok(Json(json!({
            "status": "TOKEN_ISSUED_AND_ACTIVE",
            "token": tok,
            "enterprise_account": acc
        }))),
        Err(msg) => Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "status": "TOKEN_QUOTA_EXCEEDED",
                "error": msg
            })),
        )),
    }
}

pub async fn generate_temp_password_handler(
    State(state): State<AppState>,
    Json(req): Json<GenerateTempPasswordRequest>,
) -> Json<Value> {
    let (plain_password, password_sha256, expires_at, account) =
        generate_temp_password(&state, req);
    Json(json!({
        "status": "TEMP_PASSWORD_CREATED",
        "temp_password": plain_password,
        "password_sha256": password_sha256,
        "expires_at": expires_at,
        "enterprise_account": account
    }))
}

pub async fn bind_enterprise_token_handler(
    State(state): State<AppState>,
    Json(req): Json<BindTokenRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let platform = req.platform.as_deref().unwrap_or("browser");
    match state.db.bind_device_to_specific_token(
        &req.token_id,
        &req.device_id,
        req.employee_id.as_deref(),
        req.client_label.as_deref(),
        platform,
    ) {
        Ok(tok) => {
            // Persistir identificador unico (MAC/hardware) del dispositivo en el token
            let hw = req
                .hardware_id
                .clone()
                .or_else(|| req.mac.clone())
                .filter(|s| !s.trim().is_empty())
                .or_else(|| state.db.hardware_id_for_device(&req.device_id));
            if let Some(hw) = hw {
                state.db.set_token_hardware_id(&tok.token_id, &hw);
            }
            let tok = state.db.find_enterprise_token_by_id(&tok.token_id).unwrap_or(tok);
            let acc = state.db.load_enterprise_account(&tok.company_id);
            Ok(Json(json!({
                "status": "TOKEN_BOUND",
                "token": tok,
                "enterprise_account": acc
            })))
        }
        Err(msg) => Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "status": "TOKEN_BIND_REJECTED",
                "error": msg
            })),
        )),
    }
}

pub async fn revoke_enterprise_token_handler(
    State(state): State<AppState>,
    Json(req): Json<RevokeTokenRequest>,
) -> Json<Value> {
    state.db.revoke_enterprise_token(&req.token_id);
    let account = get_enterprise_account(&state, DEFAULT_COMPANY_ID);
    let tokens = state.db.load_enterprise_tokens(DEFAULT_COMPANY_ID);
    Json(json!({
        "status": "TOKEN_REVOKED",
        "revoked_token_id": req.token_id,
        "enterprise_account": account,
        "client_tokens": tokens
    }))
}
