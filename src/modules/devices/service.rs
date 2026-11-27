use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use crate::{
    modules::devices::dto::{HandshakeRequest, HandshakeResponse, RegisteredDevice},
    state::AppState,
};

pub fn build_device_id(hardware_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(hardware_id.as_bytes());
    let hex_hash = hex::encode(hasher.finalize());
    format!("dev_{}", &hex_hash[..12])
}

pub fn build_session_token() -> String {
    format!("xotla_tok_{}", Uuid::new_v4().simple())
}

pub fn register_or_recognize_device(
    state: &AppState,
    req: HandshakeRequest,
) -> HandshakeResponse {
    if let Some(mut known) = state.devices_by_hw.get_mut(&req.hardware_id) {
        known.last_seen = Utc::now();
        let ws_url = format!("{}/v1/ws?token={}", state.config.public_ws_base, known.session_token);
        return HandshakeResponse {
            status: "KNOWN_DEVICE_RECOGNIZED".to_string(),
            is_new_device: false,
            device_id: known.device_id.clone(),
            employee_id: known.employee_id.clone(),
            session_token: known.session_token.clone(),
            approved: known.approved,
            ws_url,
        };
    }

    let device_id = build_device_id(&req.hardware_id);
    let session_token = build_session_token();
    let now = Utc::now();

    let registered = RegisteredDevice {
        hardware_id: req.hardware_id.clone(),
        device_id: device_id.clone(),
        employee_id: req.employee_id.clone(),
        department: req.department.unwrap_or_else(|| "Contabilidad".to_string()),
        agent_kind: req.agent_kind,
        hostname: req.hostname.unwrap_or_else(|| "endpoint-qro".to_string()),
        session_token: session_token.clone(),
        approved: true,
        online: false,
        registered_at: now,
        last_seen: now,
    };

    state.devices_by_hw.insert(req.hardware_id.clone(), registered);
    state.devices_by_id.insert(device_id.clone(), req.hardware_id.clone());
    state.token_to_hw.insert(session_token.clone(), req.hardware_id);

    let ws_url = format!("{}/v1/ws?token={}", state.config.public_ws_base, session_token);

    HandshakeResponse {
        status: "NEW_DEVICE_REGISTERED".to_string(),
        is_new_device: true,
        device_id,
        employee_id: req.employee_id,
        session_token,
        approved: true,
        ws_url,
    }
}

pub fn resolve_device_by_token(state: &AppState, token: &str) -> Option<RegisteredDevice> {
    let hw_id = state.token_to_hw.get(token)?.clone();
    let mut device = state.devices_by_hw.get_mut(&hw_id)?;
    if !device.approved {
        return None;
    }
    device.last_seen = Utc::now();
    Some(device.clone())
}

pub fn resolve_device_by_id(state: &AppState, device_id: &str) -> Option<RegisteredDevice> {
    let hw_id = state.devices_by_id.get(device_id)?.clone();
    let mut device = state.devices_by_hw.get_mut(&hw_id)?;
    device.last_seen = Utc::now();
    Some(device.clone())
}
