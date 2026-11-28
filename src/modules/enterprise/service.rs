use chrono::{Duration, Utc};
use uuid::Uuid;
use crate::{
    db::sha256_hex,
    modules::enterprise::dto::{
        AllocateCompanyRequest, EnterpriseAccount, EnterpriseClientToken,
        GenerateTempPasswordRequest, IssueClientTokenRequest,
    },
    state::AppState,
};

pub const DEFAULT_COMPANY_ID: &str = "comp_aegis_qro_01";

pub fn company_token_prefix(company_name: &str) -> String {
    let clean: String = company_name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == ' ')
        .collect::<String>()
        .to_lowercase();
    let first = clean.split_whitespace().next().unwrap_or("empresa");
    let slug = if first.len() > 14 {
        &first[..14]
    } else if first.is_empty() {
        "empresa"
    } else {
        first
    };
    format!("{}_tok", slug)
}

pub fn generate_company_token_id(company_name: &str, seed: &str) -> (String, String) {
    let tok_sha = sha256_hex(seed);
    let prefix = company_token_prefix(company_name);
    let tok_id = format!("{}_{}", prefix, &tok_sha[..16]);
    (tok_id, tok_sha)
}

pub fn get_enterprise_account(state: &AppState, company_id: &str) -> EnterpriseAccount {
    state.db.load_enterprise_account(company_id)
}

pub fn create_enterprise_account_with_pool(
    state: &AppState,
    req: AllocateCompanyRequest,
) -> (EnterpriseAccount, Option<String>, Vec<EnterpriseClientToken>) {
    let cid = req
        .company_id
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("comp_{}", &Uuid::new_v4().simple().to_string()[..8]));

    state.db.upsert_enterprise_account(
        &cid,
        &req.company_name,
        &req.master_account_email,
        req.total_allocated_tokens,
    );

    let plain_pw = req
        .temp_password
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| {
            let short = &Uuid::new_v4().simple().to_string()[..8].to_uppercase();
            format!("AEGIS-{}-{}", &short[..4], &short[4..8])
        });

    let hours = req.expires_in_hours.unwrap_or(72).clamp(1, 720) as i64;
    let expires_at = (Utc::now() + Duration::hours(hours)).to_rfc3339();
    let pw_hash = sha256_hex(&plain_pw);
    state
        .db
        .set_enterprise_temp_password(&cid, &pw_hash, &expires_at);

    let existing_tokens = state.db.load_enterprise_tokens(&cid);
    let current_count = existing_tokens.len() as u32;
    let needed = req.total_allocated_tokens.saturating_sub(current_count);
    let now = Utc::now().to_rfc3339();

    for idx in 0..needed {
        let seed = format!("{}:slot_{}:{}", cid, current_count + idx + 1, Uuid::new_v4());
        let (tok_id, tok_sha) = generate_company_token_id(&req.company_name, &seed);
        let tok = EnterpriseClientToken {
            token_id: tok_id,
            company_id: cid.clone(),
            token_sha256: tok_sha,
            assigned_device_id: None,
            secondary_device_id: None,
            assigned_employee_id: None,
            max_devices: 2,
            used_devices_count: 0,
            client_label: format!("Licencia #{}", current_count + idx + 1),
            platform: "UNASSIGNED".to_string(),
            status: "AVAILABLE".to_string(),
            activated_at: now.clone(),
            last_used_at: now.clone(),
        };
        state.db.insert_enterprise_token(&tok);
    }

    let acc = state.db.load_enterprise_account(&cid);
    let all_tokens = state.db.load_enterprise_tokens(&cid);
    (acc, Some(plain_pw), all_tokens)
}

pub fn update_company_quota(
    state: &AppState,
    req: AllocateCompanyRequest,
) -> EnterpriseAccount {
    let cid = req
        .company_id
        .unwrap_or_else(|| DEFAULT_COMPANY_ID.to_string());
    state.db.upsert_enterprise_account(
        &cid,
        &req.company_name,
        &req.master_account_email,
        req.total_allocated_tokens,
    );

    if let Some(ref raw_pw) = req.temp_password {
        if !raw_pw.trim().is_empty() {
            let hours = req.expires_in_hours.unwrap_or(24).clamp(1, 720) as i64;
            let expires_at = (Utc::now() + Duration::hours(hours)).to_rfc3339();
            let pw_hash = sha256_hex(raw_pw.trim());
            state.db.set_enterprise_temp_password(&cid, &pw_hash, &expires_at);
        }
    }

    state.db.load_enterprise_account(&cid)
}

pub fn generate_temp_password(
    state: &AppState,
    req: GenerateTempPasswordRequest,
) -> (String, String, String, EnterpriseAccount) {
    let cid = req
        .company_id
        .unwrap_or_else(|| DEFAULT_COMPANY_ID.to_string());

    let plain_pw = req
        .custom_password
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| {
            let short = &Uuid::new_v4().simple().to_string()[..8].to_uppercase();
            format!("AEGIS-{}-{}", &short[..4], &short[4..8])
        });

    let hours = req.expires_in_hours.unwrap_or(24).clamp(1, 720) as i64;
    let expires_at = (Utc::now() + Duration::hours(hours)).to_rfc3339();
    let pw_sha256 = sha256_hex(&plain_pw);

    state
        .db
        .set_enterprise_temp_password(&cid, &pw_sha256, &expires_at);
    let updated = state.db.load_enterprise_account(&cid);

    (plain_pw, pw_sha256, expires_at, updated)
}

pub fn issue_or_activate_client_token(
    state: &AppState,
    req: IssueClientTokenRequest,
) -> Result<(EnterpriseClientToken, EnterpriseAccount), String> {
    let cid = req
        .company_id
        .unwrap_or_else(|| DEFAULT_COMPANY_ID.to_string());

    if let Some(ref dev_id) = req.device_id {
        if let Some(existing) = state.db.find_token_by_device(&cid, dev_id) {
            let acc = state.db.load_enterprise_account(&cid);
            return Ok((existing, acc));
        }
    }

    let account = state.db.load_enterprise_account(&cid);
    if account.active_tokens_used >= account.total_allocated_tokens {
        return Err(format!(
            "Limite de tokens agotado para la cuenta empresarial {} ({}/{} tokens activos)",
            account.company_name, account.active_tokens_used, account.total_allocated_tokens
        ));
    }

    let raw_seed = format!(
        "{}:{}:{}:{}",
        cid,
        req.employee_id,
        req.device_id.as_deref().unwrap_or("unassigned"),
        Uuid::new_v4()
    );
    let (token_id, token_sha256) = generate_company_token_id(&account.company_name, &raw_seed);
    let now = Utc::now().to_rfc3339();

    let used_count = u32::from(req.device_id.is_some());
    let token = EnterpriseClientToken {
        token_id,
        company_id: cid.clone(),
        token_sha256,
        assigned_device_id: req.device_id,
        secondary_device_id: None,
        assigned_employee_id: Some(req.employee_id),
        max_devices: 2,
        used_devices_count: used_count,
        client_label: req.client_label,
        platform: req.platform.unwrap_or_else(|| "multi-platform".to_string()),
        status: "ACTIVE".to_string(),
        activated_at: now.clone(),
        last_used_at: now,
    };

    state.db.insert_enterprise_token(&token);
    let updated_acc = state.db.load_enterprise_account(&cid);
    Ok((token, updated_acc))
}

pub fn auto_bind_device_to_company_token(
    state: &AppState,
    device_id: &str,
    employee_id: &str,
    hostname: &str,
    platform: &str,
    session_token: &str,
) {
    let cid = DEFAULT_COMPANY_ID;
    if state.db.find_token_by_device(cid, device_id).is_some() {
        state.db.touch_device_token(cid, device_id);
        return;
    }

    if state
        .db
        .bind_device_to_existing_user_token(cid, employee_id, device_id, platform)
    {
        return;
    }

    let account = state.db.load_enterprise_account(cid);
    if account.active_tokens_used >= account.total_allocated_tokens {
        return;
    }

    let now = Utc::now().to_rfc3339();
    let (token_id, token_sha256) = if session_token.contains("_tok_") {
        (session_token.to_string(), sha256_hex(session_token))
    } else {
        generate_company_token_id(&account.company_name, session_token)
    };
    let token = EnterpriseClientToken {
        token_id,
        company_id: cid.to_string(),
        token_sha256,
        assigned_device_id: Some(device_id.to_string()),
        secondary_device_id: None,
        assigned_employee_id: Some(employee_id.to_string()),
        max_devices: 2,
        used_devices_count: 1,
        client_label: hostname.to_string(),
        platform: platform.to_string(),
        status: "ACTIVE".to_string(),
        activated_at: now.clone(),
        last_used_at: now,
    };

    state.db.insert_enterprise_token(&token);
}
