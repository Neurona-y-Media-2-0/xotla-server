// src/modules/security/rate_limit.rs
use std::time::{Duration, Instant};
use axum::http::HeaderMap;
use chrono::Utc;
use uuid::Uuid;
use crate::{
    modules::security::dto::BlockedThreatRecord,
    state::AppState,
};

pub const DEFAULT_RATE_LIMIT_PER_MIN: u32 = 180;
pub const LOGIN_RATE_LIMIT_PER_MIN: u32 = 15;
const WINDOW_DURATION: Duration = Duration::from_secs(60);

pub fn extract_client_key(headers: &HeaderMap) -> String {
    for hdr in ["x-forwarded-for", "x-real-ip", "x-session-token", "x-device-id"] {
        if let Some(val) = headers.get(hdr).and_then(|v| v.to_str().ok()) {
            let first = val.split(',').next().unwrap_or("").trim();
            if !first.is_empty() && first.len() <= 128 {
                return first.to_string();
            }
        }
    }
    "local_client".to_string()
}

pub fn check_rate_limit(state: &AppState, client_key: &str, path: &str) -> bool {
    let is_login = path.contains("/admin/login");
    let limit = if is_login {
        LOGIN_RATE_LIMIT_PER_MIN
    } else {
        DEFAULT_RATE_LIMIT_PER_MIN
    };

    let bucket_key = if is_login {
        format!("login:{}", client_key)
    } else {
        format!("api:{}", client_key)
    };

    let now = Instant::now();
    let mut entry = state
        .rate_limits
        .entry(bucket_key)
        .or_insert((0, now));

    if now.duration_since(entry.1) >= WINDOW_DURATION {
        entry.0 = 1;
        entry.1 = now;
        return true;
    }

    entry.0 += 1;
    entry.0 <= limit
}

pub async fn record_blocked_threat(
    state: &AppState,
    client_key: &str,
    path: &str,
    category: &str,
    reason: &str,
) {
    state
        .blocked_requests_count
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let record = BlockedThreatRecord {
        threat_id: format!("blk_{}", &Uuid::new_v4().simple().to_string()[..12]),
        client_key: client_key.to_string(),
        path: path.to_string(),
        category: category.to_string(),
        reason: reason.to_string(),
        blocked_at: Utc::now(),
    };

    let mut log = state.blocked_threats.write().await;
    log.push(record);
    if log.len() > 200 {
        log.remove(0);
    }
}
