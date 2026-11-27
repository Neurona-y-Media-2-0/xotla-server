// src/modules/security/dto.rs
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedThreatRecord {
    pub threat_id: String,
    pub client_key: String,
    pub path: String,
    pub category: String,
    pub reason: String,
    pub blocked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityShieldStats {
    pub status: String,
    pub max_body_bytes: usize,
    pub max_json_depth: usize,
    pub max_batch_items: usize,
    pub rate_limit_per_min: u32,
    pub total_blocked_requests: u64,
    pub total_sanitized_payloads: u64,
    pub recent_blocked: Vec<BlockedThreatRecord>,
}
