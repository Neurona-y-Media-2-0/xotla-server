// src/modules/security/controller.rs
use std::sync::atomic::Ordering;
use axum::{extract::State, Json};
use crate::{
    modules::security::{
        dto::SecurityShieldStats,
        inspector::{MAX_ARRAY_LEN, MAX_BODY_BYTES, MAX_JSON_DEPTH},
        rate_limit::DEFAULT_RATE_LIMIT_PER_MIN,
    },
    state::AppState,
};

pub async fn security_status_handler(
    State(state): State<AppState>,
) -> Json<SecurityShieldStats> {
    let blocked = state.blocked_threats.read().await.clone();
    Json(SecurityShieldStats {
        status: "ACTIVE_ENFORCING".to_string(),
        max_body_bytes: MAX_BODY_BYTES,
        max_json_depth: MAX_JSON_DEPTH,
        max_batch_items: MAX_ARRAY_LEN,
        rate_limit_per_min: DEFAULT_RATE_LIMIT_PER_MIN,
        total_blocked_requests: state.blocked_requests_count.load(Ordering::Relaxed),
        total_sanitized_payloads: state.sanitized_payloads_count.load(Ordering::Relaxed),
        recent_blocked: blocked,
    })
}
