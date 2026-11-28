use chrono::Utc;
use uuid::Uuid;
use crate::{
    db::sha256_hex,
    modules::enterprise::dto::{
        AllocateCompanyRequest, EnterpriseAccount, EnterpriseClientToken, IssueClientTokenRequest,
    },
    state::AppState,
};

pub const DEFAULT_COMPANY_ID: &str = "comp_aegis_qro_01";

pub fn get_enterprise_account(state: &AppState, company_id: &str) -> EnterpriseAccount {
    state.db.load_enterprise_account(company_id)
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
    state.db.load_enterprise_account(&cid)
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
    let token_sha256 = sha256_hex(&raw_seed);
    let token_id = format!("aegis_lic_{}", &token_sha256[..20]);
    let now = Utc::now().to_rfc3339();

    let token = EnterpriseClientToken {
        token_id,
        company_id: cid.clone(),
        token_sha256,
        assigned_device_id: req.device_id,
        assigned_employee_id: Some(req.employee_id),
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

    let account = state.db.load_enterprise_account(cid);
    if account.active_tokens_used >= account.total_allocated_tokens {
        return;
    }

    let now = Utc::now().to_rfc3339();
    let token = EnterpriseClientToken {
        token_id: session_token.to_string(),
        company_id: cid.to_string(),
        token_sha256: sha256_hex(session_token),
        assigned_device_id: Some(device_id.to_string()),
        assigned_employee_id: Some(employee_id.to_string()),
        client_label: hostname.to_string(),
        platform: platform.to_string(),
        status: "ACTIVE".to_string(),
        activated_at: now.clone(),
        last_used_at: now,
    };

    state.db.insert_enterprise_token(&token);
}
