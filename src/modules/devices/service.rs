use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use crate::{
    modules::devices::dto::{AgentKind, HandshakeRequest, HandshakeResponse, RegisteredDevice},
    state::AppState,
};

pub fn build_device_id(hardware_id: &str) -> String {
    let trimmed = hardware_id.trim();
    if trimmed.len() >= 8 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return format!("dev_qro_{}", &trimmed[..8].to_lowercase());
    }
    let mut hasher = Sha256::new();
    hasher.update(trimmed.as_bytes());
    let hex_hash = hex::encode(hasher.finalize());
    format!("dev_qro_{}", &hex_hash[..8])
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
        let risk = state
            .profiles
            .get(&known.employee_id)
            .map(|p| p.current_risk_score)
            .unwrap_or(0.10);
        let ws_url = format!("{}/v1/ws?token={}", state.config.public_ws_base, known.session_token);
        return HandshakeResponse {
            status: "ENROLLED_EXISTING".to_string(),
            is_new_device: false,
            device_id: known.device_id.clone(),
            internal_device_id: known.device_id.clone(),
            employee_id: known.employee_id.clone(),
            assigned_profile: if risk >= 0.80 {
                "high_risk_quarantine".to_string()
            } else {
                "standard_employee".to_string()
            },
            current_risk_score: risk,
            sync_interval_sec: 30,
            session_token: known.session_token.clone(),
            approved: known.approved,
            ws_url,
        };
    }

    let device_id = build_device_id(&req.hardware_id);
    let session_token = build_session_token();
    let now = Utc::now();

    let platform = req.platform.clone().unwrap_or_else(|| "windows".to_string());
    let inferred_kind = req.agent_kind.unwrap_or_else(|| {
        if platform.to_lowercase().contains("android") {
            AgentKind::AndroidAgent
        } else if platform.to_lowercase().contains("browser") {
            AgentKind::BrowserExt
        } else {
            AgentKind::WindowsOs
        }
    });

    let employee_id = req.employee_id.unwrap_or_else(|| "emp_042".to_string());

    let registered = RegisteredDevice {
        hardware_id: req.hardware_id.clone(),
        device_id: device_id.clone(),
        employee_id: employee_id.clone(),
        department: req.department.unwrap_or_else(|| "Contabilidad".to_string()),
        agent_kind: inferred_kind,
        platform,
        os_version: req.os_version.unwrap_or_else(|| "OS-Corporate".to_string()),
        device_model: req.device_model.clone().unwrap_or_else(|| "Corporate-Device".to_string()),
        agent_version: req.agent_version.unwrap_or_else(|| "0.1.0-hackathon".to_string()),
        hostname: req
            .hostname
            .or(req.device_model)
            .unwrap_or_else(|| "endpoint-qro".to_string()),
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
        status: "ENROLLED_NEW".to_string(),
        is_new_device: true,
        device_id: device_id.clone(),
        internal_device_id: device_id,
        employee_id,
        assigned_profile: "standard_employee".to_string(),
        current_risk_score: 0.10,
        sync_interval_sec: 30,
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
