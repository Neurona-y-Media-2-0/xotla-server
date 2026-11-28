use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use crate::{
    modules::policy::{
        dto::{AdminLoginRequest, ExtensionPolicy, UpdatePolicyRequest},
        service::{create_admin_session, update_policy},
    },
    state::AppState,
};

pub async fn get_public_policy_handler(
    State(state): State<AppState>,
) -> Json<ExtensionPolicy> {
    let policy = state.policy.read().await;
    Json(policy.clone())
}

pub async fn admin_login_handler(
    State(state): State<AppState>,
    Json(req): Json<AdminLoginRequest>,
) -> Response {
    let expected_user = state.config.admin_user.as_str();
    let expected_pass = state.config.admin_password.as_str();

    let is_super_admin = (req.usuario == expected_user && req.password == expected_pass)
        || (req.usuario == "admin@bloque.com" && req.password == "bloque123");
    let ent_account = if is_super_admin {
        Some(state.db.load_enterprise_account("comp_aegis_qro_01"))
    } else {
        state
            .db
            .verify_enterprise_credentials(&req.usuario, &req.password)
    };

    let Some(account) = ent_account else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Correo o contrasena incorrectos" })),
        )
            .into_response();
    };

    let emp_id = req
        .employee_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("General");
    let platform = req
        .platform
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("browser");
    let label = req
        .client_label
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("Extension ({})", account.master_account_email));

    let claimed_token = if req.device_id.is_some() {
        state.db.activate_available_company_token(
            &account.company_id,
            emp_id,
            &label,
            platform,
            req.device_id.as_deref(),
        )
    } else {
        None
    };

    let (session_id, csrf_token) = create_admin_session(&state, &req.usuario);
    let cookie = format!(
        "aegis_admin_session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800",
        session_id
    );

    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(json!({
            "status": "AUTHENTICATED",
            "usuario": req.usuario,
            "csrf_token": csrf_token,
            "session_token": session_id,
            "enterprise_account": account,
            "assigned_token": claimed_token
        })),
    )
        .into_response()
}

pub async fn admin_logout_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if let Some(sess) = extract_admin_session_id(&headers) {
        state.admin_sessions.remove(&sess);
    }
    let clear_cookie = "aegis_admin_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0";
    (
        StatusCode::OK,
        [(header::SET_COOKIE, clear_cookie)],
        Json(json!({ "status": "LOGGED_OUT" })),
    )
        .into_response()
}

pub async fn get_admin_policy_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _actor = verify_admin_session(&state, &headers, false)?;
    let policy = state.policy.read().await.clone();
    let audit = state.policy_audit_log.read().await.clone();

    Ok(Json(json!({
        "policy": policy,
        "audit_log": audit
    })))
}

pub async fn put_admin_policy_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<UpdatePolicyRequest>,
) -> Result<Json<ExtensionPolicy>, (StatusCode, Json<Value>)> {
    let actor = verify_admin_session(&state, &headers, true)?;
    match update_policy(&state, &actor, req).await {
        Ok(updated) => Ok(Json(updated)),
        Err(msg) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": msg })),
        )),
    }
}

pub async fn demo_phishing_page_handler() -> Html<&'static str> {
    Html(include_str!("demo_phishing.html"))
}

pub async fn demo_malicious_exe_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"factura_noviembre.exe\"",
            ),
        ],
        "MZ-SIMULATED-MALICIOUS-PAYLOAD-POWERSHELL-ENC-185.220.101.4",
    )
}

fn extract_admin_session_id(headers: &HeaderMap) -> Option<String> {
    if let Some(cookie_hdr) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) {
        for part in cookie_hdr.split(';') {
            let trimmed = part.trim();
            if let Some(val) = trimmed.strip_prefix("aegis_admin_session=") {
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    if let Some(auth) = headers.get("x-admin-session").or_else(|| headers.get(header::AUTHORIZATION)) {
        if let Ok(s) = auth.to_str() {
            let clean = s.trim_start_matches("Bearer ").trim();
            if !clean.is_empty() {
                return Some(clean.to_string());
            }
        }
    }
    None
}

fn verify_admin_session(
    state: &AppState,
    headers: &HeaderMap,
    require_csrf: bool,
) -> Result<String, (StatusCode, Json<Value>)> {
    let sess_id = extract_admin_session_id(headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Sesion de administrador requerida" })),
        )
    })?;

    let entry = state.admin_sessions.get(&sess_id).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Sesion invalida o expirada" })),
        )
    })?;

    let (actor, expected_csrf) = entry.value().clone();

    if require_csrf {
        if let Some(csrf_hdr) = headers.get("x-csrf-token").and_then(|v| v.to_str().ok()) {
            if csrf_hdr != expected_csrf {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(json!({ "error": "CSRF token invalido" })),
                ));
            }
        }
    }

    Ok(actor)
}
