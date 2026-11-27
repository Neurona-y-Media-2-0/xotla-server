// src/modules/security/controller.rs
use std::sync::atomic::Ordering;
use axum::{extract::State, http::HeaderMap, Json};
use crate::{
    modules::security::{
        antivirus::{scan_payload_request, AntivirusScanRequest, AntivirusScanResult},
        dto::SecurityShieldStats,
        inspector::{MAX_ARRAY_LEN, MAX_BODY_BYTES, MAX_JSON_DEPTH},
        rate_limit::{
             extract_client_key, record_blocked_threat, DEFAULT_RATE_LIMIT_PER_MIN,
        },
    },
    state::AppState,
};

pub async fn security_status_handler(
    State(state): State<AppState>,
) -> Json<SecurityShieldStats> {
    let blocked = state.blocked_threats.read().await.clone();
    Json(SecurityShieldStats {
        status: "ANTIVIRUS_AND_WAF_ACTIVE".to_string(),
        max_body_bytes: MAX_BODY_BYTES,
        max_json_depth: MAX_JSON_DEPTH,
        max_batch_items: MAX_ARRAY_LEN,
        rate_limit_per_min: DEFAULT_RATE_LIMIT_PER_MIN,
        total_blocked_requests: state.blocked_requests_count.load(Ordering::Relaxed),
        total_sanitized_payloads: state.sanitized_payloads_count.load(Ordering::Relaxed),
        recent_blocked: blocked,
    })
}

pub async fn antivirus_scan_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AntivirusScanRequest>,
) -> Json<AntivirusScanResult> {
    let result = scan_payload_request(&req);
    if !result.clean {
        let client_key = extract_client_key(&headers);
        let sig = result
            .signature_matched
            .clone()
            .unwrap_or_else(|| "UNKNOWN_VIRUS".to_string());
        record_blocked_threat(
            &state,
            &client_key,
            "/v1/security/scan",
            "ANTIVIRUS_QUARANTINE",
            &sig,
        )
        .await;
    }
    Json(result)
}
