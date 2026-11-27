use axum::{extract::State, http::HeaderMap, Json};
use serde_json::{json, Value};
use crate::{
    modules::{
        devices::dto::AgentKind,
        telemetry::{
            dto::{
                AndroidSandboxPayload, BrowserTelemetryPayload, StoredTelemetryEvent,
                WindowsSandboxPayload,
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
        "status": "PROCESSED",
        "device_id": device.device_id,
        "event_id": event.event_id,
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
        "status": "PROCESSED",
        "device_id": device.device_id,
        "event_id": event.event_id,
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
        "status": "PROCESSED",
        "device_id": device.device_id,
        "event_id": event.event_id,
        "ueba_profile": profile
    }))
}

pub async fn list_events_handler(
    State(state): State<AppState>,
) -> Json<Vec<StoredTelemetryEvent>> {
    let events = state.events.read().await;
    Json(events.clone())
}
