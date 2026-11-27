use serde::Deserialize;
use serde_json::Value;
use crate::{
    modules::devices::dto::RegisteredDevice,
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct WsQueryParams {
    pub token: Option<String>,
    pub hardware_id: Option<String>,
    pub employee_id: Option<String>,
    pub role: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct WsIncomingMessage {
    pub source: Option<String>,
    pub event_type: Option<String>,
    pub threat_score: Option<f32>,
    pub anomaly: Option<String>,
    #[serde(default)]
    pub payload: Value,
}

pub fn mark_device_connection(state: &AppState, device: &RegisteredDevice, connected: bool) {
    if let Some(mut dev) = state.devices_by_hw.get_mut(&device.hardware_id) {
        dev.online = connected;
        dev.last_seen = chrono::Utc::now();
    }
    if connected {
        *state
            .active_ws_sessions
            .entry(device.device_id.clone())
            .or_insert(0) += 1;
    } else if let Some(mut count) = state.active_ws_sessions.get_mut(&device.device_id) {
        if *count > 0 {
            *count -= 1;
        }
    }
}
