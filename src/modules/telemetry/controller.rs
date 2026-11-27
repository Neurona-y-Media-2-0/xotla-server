use axum::{extract::State, http::HeaderMap, Json};
use serde_json::{json, Value};
use crate::{
    db::{purge_ephemeral_artifact, sha256_hex},
    modules::{
        devices::dto::AgentKind,
        telemetry::{
            dto::{
                AndroidSandboxPayload, BrowserTelemetryPayload, StoredTelemetryEvent,
                TelemetryBatchRequest, TelemetryBatchResponse, WindowsSandboxPayload,
            },
            middleware::resolve_authenticated_device,
        },
        ueba::engine::evaluate_and_record_event,
    },
    state::AppState,
};

pub async fn browser_telemetry_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<BrowserTelemetryPayload>,
) -> Json<Value> {
    let device = resolve_authenticated_device(
        &state,
        &headers,
        payload.device_id.as_deref(),
        payload.employee_id.as_deref(),
        AgentKind::BrowserExt,
    );

    let url_sha256 = sha256_hex(&payload.details.original_url);
    let is_web_image = payload.details.original_url.ends_with(".png")
        || payload.details.original_url.ends_with(".jpg")
        || payload.details.original_url.ends_with(".jpeg")
        || payload.details.original_url.ends_with(".webp")
        || payload.details.original_url.ends_with(".gif");

    if is_web_image {
        purge_ephemeral_artifact(&payload.details.original_url);
    }

    let anomaly = format!(
        "Intento de acceso a dominio con caracteres {} ({}) [sha256:{}]",
        payload.details.detected_script,
        payload.details.original_url,
        &url_sha256[..12]
    );

    let mut raw = serde_json::to_value(&payload).unwrap_or(Value::Null);
    if let Some(obj) = raw.as_object_mut() {
        obj.insert("url_sha256".to_string(), json!(url_sha256));
        obj.insert("ephemeral_file_purged".to_string(), json!(is_web_image));
    }

    let (event, profile) = evaluate_and_record_event(
        &state,
        &device,
        "BROWSER_EXTENSION",
        &payload.event_type,
        payload.details.similarity_score,
        Some(anomaly),
        raw,
    )
    .await;

    Json(json!({
        "status": "ok",
        "event_ingested": true,
        "device_id": device.device_id,
        "event_id": event.event_id,
        "sha256": url_sha256,
        "current_risk_score": profile.current_risk_score,
        "risk_level": profile.risk_level,
        "ueba_profile": profile
    }))
}

pub async fn windows_sandbox_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<WindowsSandboxPayload>,
) -> Json<Value> {
    let device = resolve_authenticated_device(
        &state,
        &headers,
        payload.device_id.as_deref(),
        payload.employee_id.as_deref(),
        AgentKind::WindowsOs,
    );

    let spawned_ps = payload
        .sandbox_telemetry
        .spawned_processes
        .iter()
        .any(|p| p.to_lowercase().contains("powershell"));

    let anomaly = if spawned_ps {
        format!(
            "Ejecucion de PowerShell por {} fuera del perfil del departamento de {}",
            payload.file_info.filename, device.department
        )
    } else {
        format!(
            "Detonacion sospechosa en Windows Sandbox: {} (veredicto: {})",
            payload.file_info.filename, payload.verdict
        )
    };

    let raw = serde_json::to_value(&payload).unwrap_or(Value::Null);
    let (event, profile) = evaluate_and_record_event(
        &state,
        &device,
        "WINDOWS_SANDBOX",
        &payload.verdict,
        payload.threat_score,
        Some(anomaly),
        raw,
    )
    .await;

    Json(json!({
        "status": "ok",
        "sandbox_ingested": true,
        "device_id": device.device_id,
        "event_id": event.event_id,
        "current_risk_score": profile.current_risk_score,
        "risk_level": profile.risk_level,
        "ueba_profile": profile
    }))
}

pub async fn android_sandbox_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<AndroidSandboxPayload>,
) -> Json<Value> {
    let device = resolve_authenticated_device(
        &state,
        &headers,
        payload.device_id.as_deref(),
        payload.employee_id.as_deref(),
        AgentKind::AndroidAgent,
    );

    let filename = payload.apk_info.package_name.clone();
    let is_image = filename.ends_with(".png")
        || filename.ends_with(".jpg")
        || filename.ends_with(".jpeg")
        || filename.ends_with(".webp")
        || filename.ends_with(".gif");

    let artifact_sha256 = if payload.apk_info.sha256.len() == 64 {
        payload.apk_info.sha256.clone()
    } else {
        sha256_hex(&payload.apk_info.sha256)
    };

    let purged = purge_ephemeral_artifact(&filename);

    let anomaly = if payload.threat_score >= 0.45 {
        Some(format!(
            "Archivo/APK ({}) analizado con SHA-256 [{}]: permisos {}",
            filename,
            &artifact_sha256[..12],
            payload.apk_info.requested_permissions.join(", ")
        ))
    } else {
        None
    };

    let sanitized_meta = json!({
        "artifact_name": filename,
        "artifact_type": if is_image { "EPHEMERAL_IMAGE" } else { "ANDROID_ARTIFACT" },
        "sha256": artifact_sha256,
        "requested_permissions": payload.apk_info.requested_permissions,
        "suspicious_urls_in_dex": payload.apk_info.suspicious_urls_in_dex,
        "verdict": payload.verdict,
        "threat_score": payload.threat_score,
        "ephemeral_file_purged": purged
    });

    let (event, profile) = evaluate_and_record_event(
        &state,
        &device,
        "ANDROID_SANDBOX",
        &payload.verdict,
        payload.threat_score,
        anomaly,
        sanitized_meta,
    )
    .await;

    Json(json!({
        "status": "ok",
        "sandbox_ingested": true,
        "device_id": device.device_id,
        "event_id": event.event_id,
        "sha256": artifact_sha256,
        "ephemeral_file_purged": purged,
        "current_risk_score": profile.current_risk_score,
        "risk_level": profile.risk_level,
        "ueba_profile": profile
    }))
}

pub async fn telemetry_batch_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(batch): Json<TelemetryBatchRequest>,
) -> Json<TelemetryBatchResponse> {
    let device = resolve_authenticated_device(
        &state,
        &headers,
        Some(&batch.hardware_uid),
        Some("emp_042"),
        AgentKind::AndroidAgent,
    );

    let count = batch.events.len();

    for evt in batch.events {
        let anomaly = format!(
            "[{}] Veredicto {} (score {:.2})",
            evt.category, evt.local_verdict, evt.local_risk_score
        );
        let raw = serde_json::to_value(&evt).unwrap_or(Value::Null);
        evaluate_and_record_event(
            &state,
            &device,
            &evt.category,
            &evt.local_verdict,
            evt.local_risk_score,
            Some(anomaly),
            raw,
        )
        .await;
    }

    Json(TelemetryBatchResponse {
        status: "PROCESSED".to_string(),
        processed_count: count,
    })
}

pub async fn list_events_handler(
    State(state): State<AppState>,
) -> Json<Vec<StoredTelemetryEvent>> {
    let events = state.events.read().await;
    Json(events.clone())
}
