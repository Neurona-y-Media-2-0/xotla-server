// src/modules/telemetry/middleware.rs
use axum::http::HeaderMap;
use chrono::Utc;
use crate::{
    db::sha256_hex,
    modules::devices::{
        dto::{AgentKind, HandshakeRequest, RegisteredDevice},
        service::{
            build_device_id, register_or_recognize_device, resolve_device_by_id,
            resolve_device_by_token,
        },
    },
    state::AppState,
};

fn agent_kind_platform(kind: &AgentKind) -> &'static str {
    match kind {
        AgentKind::BrowserExt => "browser",
        AgentKind::AndroidAgent => "android",
        AgentKind::WindowsOs => "windows",
    }
}

pub fn resolve_authenticated_device(
    state: &AppState,
    headers: &HeaderMap,
    fallback_device_id: Option<&str>,
    fallback_employee_id: Option<&str>,
    default_kind: AgentKind,
) -> RegisteredDevice {
    let platform_str = agent_kind_platform(&default_kind);
    let preferred_dev_id = fallback_device_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(build_device_id);

    if let Some(token) = extract_token(headers) {
        if let Some(ent_tok) = state.db.find_enterprise_token_by_id(&token) {
            let dev_id = preferred_dev_id
                .clone()
                .or_else(|| ent_tok.assigned_device_id.clone())
                .unwrap_or_else(|| build_device_id(&token));

            let _ = state.db.bind_device_to_specific_token(
                &token,
                &dev_id,
                fallback_employee_id,
                None,
                platform_str,
            );

            if let Some(existing) = resolve_device_by_id(state, &dev_id) {
                return existing;
            }

            let now = Utc::now();
            let hw_id = sha256_hex(&dev_id);
            let emp_id = ent_tok
                .assigned_employee_id
                .filter(|s| !s.trim().is_empty())
                .or_else(|| fallback_employee_id.map(str::to_string))
                .unwrap_or_else(|| "emp_042".to_string());

            let registered = RegisteredDevice {
                hardware_id: hw_id.clone(),
                device_id: dev_id.clone(),
                employee_id: emp_id,
                department: "Contabilidad".to_string(),
                agent_kind: default_kind,
                platform: platform_str.to_string(),
                os_version: "OS-Corporate".to_string(),
                device_model: "Corporate-Device".to_string(),
                agent_version: "1.4.0".to_string(),
                hostname: ent_tok.client_label,
                session_token: token.clone(),
                approved: true,
                online: true,
                registered_at: now,
                last_seen: now,
            };

            state.db.upsert_device(&registered);
            state
                .devices_by_hw
                .insert(hw_id.clone(), registered.clone());
            state.devices_by_id.insert(dev_id, hw_id.clone());
            state.token_to_hw.insert(token, hw_id);
            return registered;
        }

        if let Some(device) = resolve_device_by_token(state, &token) {
            return device;
        }
    }

    if let Some(dev_id) = fallback_device_id {
        if let Some(device) = resolve_device_by_id(state, dev_id) {
            return device;
        }
        if let Some(device) = state.devices_by_hw.get(dev_id) {
            return device.clone();
        }
    }

    let hw_id = fallback_device_id.unwrap_or("auto_hw_qro").to_string();
    let emp_id = fallback_employee_id.unwrap_or("emp_042").to_string();

    let resp = register_or_recognize_device(
        state,
        HandshakeRequest {
            hardware_id: hw_id,
            employee_id: Some(emp_id),
            department: Some("Contabilidad".to_string()),
            agent_kind: Some(default_kind),
            platform: None,
            os_version: None,
            device_model: None,
            agent_version: None,
            hostname: Some("auto-enrolled-endpoint".to_string()),
        },
    );

    resolve_device_by_token(state, &resp.session_token).expect("Device was just registered")
}

fn extract_token(headers: &HeaderMap) -> Option<String> {
    for key in ["x-session-token", "x-api-key", "authorization"] {
        if let Some(val) = headers.get(key) {
            if let Ok(raw) = val.to_str() {
                let clean = raw.trim_start_matches("Bearer ").trim();
                if !clean.is_empty() {
                    return Some(clean.to_string());
                }
            }
        }
    }
    None
}
