use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct FileScanRequest {
    pub filename: String,
    pub device_id: Option<String>,
    pub employee_id: Option<String>,
    pub content_base64: Option<String>,
    pub sha256: Option<String>,
    #[serde(default)]
    pub reported_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedArtifactRecord {
    pub artifact_sha256: String,
    pub file_type: String,
    pub detected_magic: String,
    pub verdict: String,
    pub threat_score: f32,
    pub detection_method: String,
    pub detection_reasons: Vec<String>,
    pub device_id: String,
    pub employee_id: String,
    pub ephemeral_purged: bool,
    pub scanned_at: DateTime<Utc>,
}
