use axum::http::HeaderMap;
use crate::{
    modules::devices::{
        dto::{AgentKind, HandshakeRequest, RegisteredDevice},
        service::{register_or_recognize_device, resolve_device_by_id, resolve_device_by_token},
    },
    state::AppState,
};

pub fn resolve_authenticated_device(
    state: &AppState,
    headers: &HeaderMap,
    fallback_device_id: Option<&str>,
    fallback_employee_id: Option<&str>,
    default_kind: AgentKind,
) -> RegisteredDevice {
    if let Some(token) = extract_token(headers) {
        if let Some(device) = resolve_device_by_token(state, &token) {
            return device;
        }
    }

    if let Some(dev_id) = fallback_device_id {
        if let Some(device) = resolve_device_by_id(state, dev_id) {
            return device;
        }
    }

    let hw_id = fallback_device_id.unwrap_or("auto_hw_qro").to_string();
    let emp_id = fallback_employee_id.unwrap_or("emp_042").to_string();

    let resp = register_or_recognize_device(
        state,
        HandshakeRequest {
            hardware_id: hw_id,
            employee_id: emp_id,
            department: Some("Contabilidad".to_string()),
            agent_kind: default_kind,
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
