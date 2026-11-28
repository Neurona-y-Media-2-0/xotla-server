use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserDownloadFileMeta {
    pub name: Option<String>,
    pub ext: Option<String>,
    #[serde(default)]
    pub double_extension: bool,
    pub mime: Option<String>,
    pub referrer_host: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserDetails {
    pub original_url: String,
    pub punycode_url: String,
    pub detected_script: String,
    pub similarity_score: f32,
    pub action_taken: String,
    pub host: Option<String>,
    pub indicator: Option<String>,
    pub file: Option<BrowserDownloadFileMeta>,
    pub alerts_in_log: Option<u32>,
    pub unread_alerts: Option<u32>,
    pub pending_events: Option<u32>,
    pub policy_age_min: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserTelemetryPayload {
    pub event_id: Option<String>,
    pub session_id: Option<String>,
    pub install_id: Option<String>,
    pub extension_version: Option<String>,
    pub policy_version: Option<u64>,
    pub utc_offset_min: Option<i32>,
    pub severity: Option<String>,
    pub rule: Option<String>,
    pub employee_id: Option<String>,
    pub device_id: Option<String>,
    pub timestamp: Option<String>,
    pub event_type: String,
    pub details: BrowserDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsFileInfo {
    pub filename: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsSandboxDetails {
    pub execution_time_ms: u64,
    #[serde(default)]
    pub spawned_processes: Vec<String>,
    #[serde(default)]
    pub modified_registry_keys: Vec<String>,
    #[serde(default)]
    pub network_attempts: Vec<String>,
    #[serde(default)]
    pub files_created: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsSandboxPayload {
    pub employee_id: Option<String>,
    pub device_id: Option<String>,
    pub timestamp: Option<String>,
    pub file_info: WindowsFileInfo,
    pub sandbox_telemetry: WindowsSandboxDetails,
    pub verdict: String,
    pub threat_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidApkInfo {
    pub package_name: String,
    pub sha256: String,
    #[serde(default)]
    pub requested_permissions: Vec<String>,
    #[serde(default)]
    pub suspicious_urls_in_dex: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidSandboxPayload {
    pub employee_id: Option<String>,
    pub device_id: Option<String>,
    pub timestamp: Option<String>,
    pub apk_info: AndroidApkInfo,
    pub verdict: String,
    pub threat_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchTelemetryEvent {
    pub event_id: String,
    pub occurred_at: String,
    #[serde(default)]
    pub was_offline: bool,
    pub category: String,
    pub artifact_sha256: String,
    pub local_verdict: String,
    pub local_risk_score: f32,
    #[serde(default)]
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryBatchRequest {
    pub hardware_uid: String,
    pub internal_device_id: String,
    pub batch_timestamp: String,
    pub events: Vec<BatchTelemetryEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryBatchResponse {
    pub status: String,
    pub processed_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTelemetryEvent {
    pub event_id: String,
    pub device_id: String,
    pub employee_id: String,
    pub source: String,
    pub event_type: String,
    pub threat_score: f32,
    pub current_risk_score: f32,
    pub risk_level: String,
    pub raw_payload: Value,
    pub received_at: DateTime<Utc>,
}
