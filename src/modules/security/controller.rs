// src/modules/security/controller.rs
use std::sync::atomic::Ordering;
use axum::{extract::State, http::HeaderMap, Json};
use chrono::Utc;
use crate::{
    modules::{
        scanner::{dto::ScannedArtifactRecord, service::classify_file_extension},
        security::{
            antivirus::{scan_payload_request, AntivirusScanRequest, AntivirusScanResult},
            dto::SecurityShieldStats,
            inspector::{MAX_ARRAY_LEN, MAX_BODY_BYTES, MAX_JSON_DEPTH},
            rate_limit::{
                extract_client_key, record_blocked_threat, DEFAULT_RATE_LIMIT_PER_MIN,
            },
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
    let fname = req.filename.as_deref().unwrap_or("memory_buffer.bin");

    state.db.upsert_scanned_artifact(&ScannedArtifactRecord {
        artifact_sha256: result.computed_sha256.clone(),
        file_type: classify_file_extension(fname),
        detected_magic: result
            .signature_matched
            .clone()
            .unwrap_or_else(|| "CLEAN_STREAM".to_string()),
        verdict: if result.clean {
            "CLEAN".to_string()
        } else {
            "MALICIOUS".to_string()
        },
        threat_score: if result.clean { 0.05 } else { 0.98 },
        detection_method: result
            .signature_matched
            .clone()
            .unwrap_or_else(|| "ANTIVIRUS_MEMORY_SCAN".to_string()),
        detection_reasons: vec![result.details.clone()],
        device_id: "dev_qro_antivirus".to_string(),
        employee_id: "emp_042".to_string(),
        ephemeral_purged: true,
        scanned_at: Utc::now(),
    });

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
