use chrono::Utc;
use serde_json::{json, Value};
use crate::{
    db::sha256_hex,
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

    let is_minor_flag = event_type.eq_ignore_ascii_case("INSECURE_COOKIE_DETECTED")
        || raw_payload
            .pointer("/details/action_taken")
            .and_then(|v| v.as_str())
            .map(|a| a.eq_ignore_ascii_case("FLAGGED"))
            .unwrap_or(false);

    let weight = if is_minor_flag {
        0.04
    } else {
        match source {
            "WINDOWS_SANDBOX" => 0.34,
            "ANDROID_SANDBOX" => 0.28,
            "BROWSER_EXTENSION" => 0.24,
            _ => 0.18,
        }
    };

    let target_hint = raw_payload
        .pointer("/details/original_url")
        .or_else(|| raw_payload.pointer("/sha256"))
        .or_else(|| raw_payload.pointer("/file_info/sha256"))
        .or_else(|| raw_payload.pointer("/artifact_sha256"))
        .and_then(|v| v.as_str())
        .unwrap_or("generic");

    let dedup_fingerprint = format!(
        "{}:{}:{}:{}",
        device.device_id, source, event_type, target_hint
    );
    let event_hash = sha256_hex(&dedup_fingerprint);
    let deterministic_id = format!("evt_{}", &event_hash[..24]);

    let already_recorded = {
        let events = state.events.read().await;
        events.iter().any(|e| e.event_id == deterministic_id)
    };

    if !already_recorded {
        let delta = threat_score.clamp(0.0, 1.0) * weight;
        profile.current_risk_score =
            ((profile.current_risk_score + delta) * 100.0).round() / 100.0;
        profile.current_risk_score = profile.current_risk_score.clamp(0.12, 0.99);
        profile.total_events += 1;
    }

    if let Some(desc) = anomaly_description {
        if !is_minor_flag && threat_score >= 0.45 && !profile.anomalies_detected.contains(&desc) {
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
        event_id: deterministic_id.clone(),
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

    state.db.insert_telemetry_event(&stored, &dedup_fingerprint);

    {
        let mut events = state.events.write().await;
        if let Some(existing) = events.iter_mut().find(|e| e.event_id == deterministic_id) {
            *existing = stored.clone();
        } else {
            events.push(stored.clone());
            if events.len() > 500 {
                events.remove(0);
            }
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
