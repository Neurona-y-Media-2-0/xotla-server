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
    pub hardware_id: String,
    pub employee_id: String,
    pub department: Option<String>,
    pub agent_kind: AgentKind,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HandshakeResponse {
    pub status: String,
    pub is_new_device: bool,
    pub device_id: String,
    pub employee_id: String,
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
    pub hostname: String,
    pub session_token: String,
    pub approved: bool,
    pub online: bool,
    pub registered_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}
