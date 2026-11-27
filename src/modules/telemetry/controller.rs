use axum::{extract::State, http::HeaderMap, Json};
use serde_json::{json, Value};
use crate::{
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

    let anomaly = format!(
        "Intento de acceso a dominio con caracteres {} ({})",
        payload.details.detected_script, payload.details.original_url
    );

    let raw = serde_json::to_value(&payload).unwrap_or(Value::Null);
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

    let anomaly = format!(
        "Descarga de APK ({}) con permisos de alto riesgo: {}",
        payload.apk_info.package_name,
        payload.apk_info.requested_permissions.join(", ")
    );

    let raw = serde_json::to_value(&payload).unwrap_or(Value::Null);
    let (event, profile) = evaluate_and_record_event(
        &state,
        &device,
        "ANDROID_SANDBOX",
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
