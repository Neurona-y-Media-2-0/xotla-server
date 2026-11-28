use chrono::Utc;
use uuid::Uuid;
use crate::{
    modules::policy::dto::{ExtensionPolicy, PolicyAuditEntry, UpdatePolicyRequest},
    state::AppState,
};

fn is_valid_hostname(host: &str) -> bool {
    let h = host.trim().to_lowercase();
    if h.len() < 3 || h.len() > 253 || !h.contains('.') {
        return false;
    }
    h.split('.').all(|part| {
        !part.is_empty()
            && !part.starts_with('-')
            && !part.ends_with('-')
            && part.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    })
}

fn is_valid_extension(ext: &str) -> bool {
    let e = ext.trim().to_lowercase();
    if !e.starts_with('.') || e.len() < 2 || e.len() > 11 {
        return false;
    }
    e[1..].chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

fn sanitize_list(list: &[String], validator: fn(&str) -> bool, allow_empty: bool) -> Option<Vec<String>> {
    if list.len() > 500 {
        return None;
    }
    let cleaned: Vec<String> = list
        .iter()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| validator(s))
        .collect();

    if cleaned.is_empty() && !(allow_empty && list.is_empty()) {
        return None;
    }
    Some(cleaned)
}

pub async fn update_policy(
    state: &AppState,
    actor: &str,
    req: UpdatePolicyRequest,
) -> Result<ExtensionPolicy, String> {
    let mut current = state.policy.write().await;
    let mut changed = false;

    if let Some(ref trusted) = req.trusted_download_hosts {
        let valid = sanitize_list(trusted, is_valid_hostname, true)
            .ok_or_else(|| "Invalid trusted_download_hosts list".to_string())?;
        current.trusted_download_hosts = valid;
        changed = true;
    }

    if let Some(ref protected) = req.protected_domains {
        let valid = sanitize_list(protected, is_valid_hostname, false)
            .ok_or_else(|| "Invalid protected_domains list".to_string())?;
        current.protected_domains = valid;
        changed = true;
    }

    if let Some(ref extensions) = req.dangerous_extensions {
        let valid = sanitize_list(extensions, is_valid_extension, false)
            .ok_or_else(|| "Invalid dangerous_extensions list".to_string())?;
        current.dangerous_extensions = valid;
        changed = true;
    }

    if let Some(ref blacklisted) = req.blacklisted_sites.as_ref().or(req.blocked_domains.as_ref()) {
        let valid = sanitize_list(blacklisted, is_valid_hostname, true)
            .ok_or_else(|| "Invalid blacklisted_sites list".to_string())?;
        current.blacklisted_sites = valid.clone();
        current.blocked_domains = valid;
        changed = true;
    }

    if !changed {
        return Err("No valid policy fields provided".to_string());
    }

    current.version += 1;
    let updated = current.clone();
    drop(current);

    let mut audit = state.policy_audit_log.write().await;
    audit.push(PolicyAuditEntry {
        version: updated.version,
        actor: actor.to_string(),
        updated_at: Utc::now(),
        summary: format!(
            "trusted={}, protected={}, extensions={}",
            updated.trusted_download_hosts.len(),
            updated.protected_domains.len(),
            updated.dangerous_extensions.len()
        ),
    });

    Ok(updated)
}

pub fn create_admin_session(state: &AppState, usuario: &str) -> (String, String) {
    let session_id = format!("adm_sess_{}", Uuid::new_v4().simple());
    let csrf_token = format!("csrf_{}", Uuid::new_v4().simple());
    state.admin_sessions.insert(
        session_id.clone(),
        (usuario.to_string(), csrf_token.clone()),
    );
    (session_id, csrf_token)
}
