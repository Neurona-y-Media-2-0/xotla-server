use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;
use crate::{
    modules::{
        devices::dto::RegisteredDevice,
        telemetry::dto::StoredTelemetryEvent,
        ueba::model::EmployeeRiskProfile,
    },
    state::AppState,
};

pub async fn evaluate_and_record_event(
    state: &AppState,
    device: &RegisteredDevice,
    source: &str,
    event_type: &str,
    threat_score: f32,
    anomaly_description: Option<String>,
    raw_payload: Value,
) -> (StoredTelemetryEvent, EmployeeRiskProfile) {
    let mut profile = state
        .profiles
        .entry(device.employee_id.clone())
        .or_insert_with(|| EmployeeRiskProfile {
            employee_id: device.employee_id.clone(),
            department: device.department.clone(),
            baseline_risk: 0.12,
            current_risk_score: 0.12,
            risk_level: "LOW".to_string(),
            anomalies_detected: Vec::new(),
            recommended_action: "MONITOR".to_string(),
            total_events: 0,
            updated_at: Utc::now(),
        })
        .clone();

    let weight = match source {
        "WINDOWS_SANDBOX" => 0.34,
        "ANDROID_SANDBOX" => 0.28,
        "BROWSER_EXTENSION" => 0.24,
        _ => 0.18,
    };

    let delta = threat_score.clamp(0.0, 1.0) * weight;
    profile.current_risk_score = ((profile.current_risk_score + delta) * 100.0).round() / 100.0;
    profile.current_risk_score = profile.current_risk_score.clamp(0.12, 0.99);
    profile.total_events += 1;

    if let Some(desc) = anomaly_description {
        if threat_score >= 0.45 && !profile.anomalies_detected.contains(&desc) {
            profile.anomalies_detected.push(desc);
        }
    }

    let (level, action) = match profile.current_risk_score {
        s if s >= 0.80 => ("CRITICAL", "ISOLATE_HOST_AND_REVOKE_SESSION"),
        s if s >= 0.55 => ("HIGH", "QUARANTINE_AND_STEP_UP_MFA"),
        s if s >= 0.30 => ("MEDIUM", "ALERT_SOC_ANALYST"),
        _ => ("LOW", "MONITOR"),
    };

    profile.risk_level = level.to_string();
    profile.recommended_action = action.to_string();
    profile.updated_at = Utc::now();

    state
        .profiles
        .insert(device.employee_id.clone(), profile.clone());

    let stored = StoredTelemetryEvent {
        event_id: format!("evt_{}", Uuid::new_v4().simple()),
        device_id: device.device_id.clone(),
        employee_id: device.employee_id.clone(),
        source: source.to_string(),
        event_type: event_type.to_string(),
        threat_score,
        current_risk_score: profile.current_risk_score,
        risk_level: profile.risk_level.clone(),
        raw_payload,
        received_at: Utc::now(),
    };

    {
        let mut events = state.events.write().await;
        events.push(stored.clone());
        if events.len() > 500 {
            events.remove(0);
        }
    }

    if let Ok(broadcast_msg) = serde_json::to_string(&json!({
        "type": "UEBA_EVENT_UPDATE",
        "device_id": device.device_id,
        "event": &stored,
        "profile": &profile
    })) {
        let _ = state.ws_broadcaster.send(broadcast_msg);
    }

    (stored, profile)
}
