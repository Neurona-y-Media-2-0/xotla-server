use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgentKind {
    BrowserExt,
    WindowsOs,
    AndroidAgent,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HandshakeRequest {
    #[serde(alias = "hardware_uid")]
    pub hardware_id: String,
    pub employee_id: Option<String>,
    pub department: Option<String>,
    pub agent_kind: Option<AgentKind>,
    pub platform: Option<String>,
    pub os_version: Option<String>,
    pub device_model: Option<String>,
    pub agent_version: Option<String>,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HandshakeResponse {
    pub status: String,
    pub is_new_device: bool,
    pub device_id: String,
    pub internal_device_id: String,
    pub employee_id: String,
    pub assigned_profile: String,
    pub current_risk_score: f32,
    pub sync_interval_sec: u64,
    pub session_token: String,
    pub approved: bool,
    pub ws_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredDevice {
    pub hardware_id: String,
    pub device_id: String,
    pub employee_id: String,
    pub department: String,
    pub agent_kind: AgentKind,
    pub platform: String,
    pub os_version: String,
    pub device_model: String,
    pub agent_version: String,
    pub hostname: String,
    pub session_token: String,
    pub approved: bool,
    pub online: bool,
    pub registered_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}
