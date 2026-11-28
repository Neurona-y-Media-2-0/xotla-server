use chrono::{Timelike, Utc};
use serde_json::{json, Value};
use crate::{
    db::sha256_hex,
    modules::{
        devices::dto::RegisteredDevice,
        scanner::dto::ScannedArtifactRecord,
        telemetry::dto::StoredTelemetryEvent,
        ueba::model::{BehavioralBreakdown, EmployeeRiskProfile, UebaFeatureVector},
    },
    state::AppState,
};

fn map_department_id(dept: &str) -> u8 {
    match dept.to_lowercase().as_str() {
        "contabilidad" | "finanzas" => 1,
        "ti" | "sistemas" => 2,
        "rh" | "recursos humanos" => 3,
        "operaciones" => 4,
        _ => 1,
    }
}

fn compute_isolation_forest_score(f: &UebaFeatureVector) -> f32 {
    let mut e_h: f32 = 11.2;

    if f.powershell_spawned > 0 && f.department_id == 1 {
        e_h -= 4.2;
    }
    if f.homograph_attempts > 0 {
        e_h -= (f.homograph_attempts as f32 * 1.4).min(3.5);
    }
    if f.sandbox_threat_score >= 0.80 {
        e_h -= f.sandbox_threat_score * 3.1;
    }
    if f.apk_high_risk_perms > 0 {
        e_h -= (f.apk_high_risk_perms as f32 * 1.1).min(2.8);
    }
    if f.external_ip_connections > 0 {
        e_h -= (f.external_ip_connections as f32 * 0.9).min(2.2);
    }
    if f.hour_of_day < 6 || f.hour_of_day > 21 {
        e_h -= 1.2;
    }

    let e_h_clamped = e_h.clamp(1.1, 11.5);
    let c_n: f32 = 10.24;
    let s_x = 2.0_f32.powf(-(e_h_clamped / c_n));
    ((s_x.clamp(0.12, 0.99)) * 100.0).round() / 100.0
}

pub fn build_profile_from_stored_data(
    employee_id: &str,
    department: &str,
    devices_count: usize,
    events: &[StoredTelemetryEvent],
    artifacts: &[ScannedArtifactRecord],
) -> EmployeeRiskProfile {
    let emp_events: Vec<&StoredTelemetryEvent> = events
        .iter()
        .filter(|e| e.employee_id == employee_id)
        .collect();
    let emp_artifacts: Vec<&ScannedArtifactRecord> = artifacts
        .iter()
        .filter(|a| a.employee_id == employee_id)
        .collect();

    let mut powershell_spawned: u8 = 0;
    let mut homograph_attempts: u32 = 0;
    let mut max_sandbox_score: f32 = 0.0;
    let mut apk_high_risk_perms: u32 = 0;
    let mut external_ip_connections: u32 = 0;

    let mut web_phishing_incidents: u32 = 0;
    let mut android_malicious_apks: u32 = 0;
    let mut spoofed_documents_or_images: u32 = 0;
    let mut clean_files_inspected: u32 = 0;
    let mut anomalies = Vec::new();

    for art in &emp_artifacts {
        let reasons_joined = art.detection_reasons.join(" ").to_lowercase();
        let is_bad = art.verdict.contains("MALICIOUS")
            || art.verdict.contains("HIGH_RISK")
            || art.verdict.contains("BLOCKED")
            || art.verdict.contains("PHISHING")
            || art.verdict.contains("MEDIUM_RISK");

        if is_bad {
            max_sandbox_score = max_sandbox_score.max(art.threat_score);
        } else if art.verdict == "CLEAN" || art.verdict == "LEGITIMATE" {
            clean_files_inspected += 1;
        }

        if reasons_joined.contains("powershell") || reasons_joined.contains("cmd.exe") {
            powershell_spawned = 1;
        }
        if reasons_joined.contains("xn--")
            || reasons_joined.contains("cirilic")
            || reasons_joined.contains("homograph")
            || reasons_joined.contains("spoof")
        {
            homograph_attempts += 1;
        }
        if reasons_joined.contains("permission.") {
            apk_high_risk_perms += art
                .detection_reasons
                .iter()
                .filter(|r| r.contains("permission."))
                .count() as u32;
        }
        if reasons_joined.contains("c2.") || reasons_joined.contains("xn--") {
            external_ip_connections += 1;
        }

        match art.file_type.as_str() {
            "ANDROID_APK" if is_bad => android_malicious_apks += 1,
            "DOCUMENT_PDF" | "IMAGE_PNG" | "IMAGE_JPEG" if is_bad => {
                spoofed_documents_or_images += 1
            }
            "WEB_URL" | "LLM_ANALYZED_CONTENT" | "EMAIL_OR_MESSAGE_TEXT" if is_bad => {
                web_phishing_incidents += 1
            }
            _ => {}
        }

        if is_bad {
            for r in &art.detection_reasons {
                if !anomalies.contains(r) && anomalies.len() < 8 {
                    anomalies.push(r.clone());
                }
            }
        }
    }

    for evt in &emp_events {
        if evt.source == "BROWSER_EXTENSION" && evt.threat_score >= 0.85 {
            web_phishing_incidents += 1;
            homograph_attempts += 1;
        }
        max_sandbox_score = max_sandbox_score.max(evt.threat_score);
    }

    let now_utc = Utc::now();
    let qro_hour = ((now_utc.hour() + 18) % 24) as u8;

    let features = UebaFeatureVector {
        department_id: map_department_id(department),
        hour_of_day: qro_hour,
        powershell_spawned,
        homograph_attempts,
        sandbox_threat_score: (max_sandbox_score * 100.0).round() / 100.0,
        apk_high_risk_perms: apk_high_risk_perms.max(if android_malicious_apks > 0 { 2 } else { 0 }),
        external_ip_connections,
    };

    let iforest_score = compute_isolation_forest_score(&features);
    let baseline: f32 = 0.12;
    let current_risk_score = if emp_artifacts.is_empty() && emp_events.is_empty() {
        baseline
    } else {
        iforest_score
    };

    let (risk_level, recommended_action) = match current_risk_score {
        s if s >= 0.80 => ("CRITICAL", "ISOLATE_HOST_AND_REVOKE_SESSION"),
        s if s >= 0.55 => ("HIGH", "QUARANTINE_AND_STEP_UP_MFA"),
        s if s >= 0.30 => ("MEDIUM", "ALERT_SOC_ANALYST"),
        _ => ("LOW", "MONITOR"),
    };

    let primary_attack_vector = if android_malicious_apks > 0 && spoofed_documents_or_images > 0 {
        "Ataque Multi-Vector (Troyano Bancario Android + Documentos/Imagenes con Spoofing y PowerShell)".to_string()
    } else if android_malicious_apks > 0 {
        "Compromiso Movil Android (APK con permisos de Accesibilidad y SMS)".to_string()
    } else if spoofed_documents_or_images > 0 {
        "Ejecucion de Payloads Ocultos en Documentos PDF / Imagenes (MIME & Magic Bytes Spoofing)".to_string()
    } else if web_phishing_incidents > 0 {
        "Ingenieria Social y Phishing Homografo / Suplantacion SAT".to_string()
    } else {
        "Comportamiento dentro del perfil base del departamento".to_string()
    };

    let deviation_pct = (((current_risk_score - baseline).max(0.0) / baseline) * 100.0).round();

    let llm_behavioral_summary = format!(
        "Perfil de Conducta UEBA ({} - Depto. {}): El empleado presenta una desviacion conductual del +{:.0}% respecto a su linea base ({:.2} -> {:.2} {}). Se correlacionaron {} artefactos/eventos en {} dispositivos activos: {} APKs maliciosos con abuso de Accesibilidad/SMS, {} documentos/imagenes con spoofing de binarios/JS/PowerShell y {} incidentes de phishing/cookies web. Vector dominante: {}. Accion Zero-Trust: {}.",
        employee_id,
        department,
        deviation_pct,
        baseline,
        current_risk_score,
        risk_level,
        emp_artifacts.len().max(emp_events.len()),
        devices_count.max(1),
        android_malicious_apks,
        spoofed_documents_or_images,
        web_phishing_incidents,
        primary_attack_vector,
        recommended_action
    );

    let total_events = (emp_artifacts.len() + emp_events.len()) as u32;

    EmployeeRiskProfile {
        employee_id: employee_id.to_string(),
        department: department.to_string(),
        baseline_risk: baseline,
        current_risk_score,
        isolation_forest_score: iforest_score,
        risk_level: risk_level.to_string(),
        anomalies_detected: anomalies,
        recommended_action: recommended_action.to_string(),
        total_events,
        features,
        behavioral_breakdown: BehavioralBreakdown {
            web_phishing_incidents,
            android_malicious_apks,
            spoofed_documents_or_images,
            clean_files_inspected,
            active_devices_count: devices_count,
            primary_attack_vector,
            behavior_deviation_percent: deviation_pct,
        },
        llm_behavioral_summary,
        updated_at: now_utc,
    }
}

pub async fn evaluate_and_record_event(
    state: &AppState,
    device: &RegisteredDevice,
    source: &str,
    event_type: &str,
    threat_score: f32,
    anomaly_description: Option<String>,
    raw_payload: Value,
) -> (StoredTelemetryEvent, EmployeeRiskProfile) {
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

    let mut temp_stored = StoredTelemetryEvent {
        event_id: deterministic_id.clone(),
        device_id: device.device_id.clone(),
        employee_id: device.employee_id.clone(),
        source: source.to_string(),
        event_type: event_type.to_string(),
        threat_score,
        current_risk_score: 0.50,
        risk_level: "MEDIUM".to_string(),
        raw_payload,
        received_at: Utc::now(),
    };

    {
        let mut events = state.events.write().await;
        if let Some(existing) = events.iter_mut().find(|e| e.event_id == deterministic_id) {
            *existing = temp_stored.clone();
        } else {
            events.push(temp_stored.clone());
            if events.len() > 500 {
                events.remove(0);
            }
        }
    }

    let events_snapshot = state.events.read().await.clone();
    let artifacts_snapshot = state.db.load_scanned_artifacts();
    let devices_count = state.devices_by_hw.len();

    let mut profile = build_profile_from_stored_data(
        &device.employee_id,
        &device.department,
        devices_count,
        &events_snapshot,
        &artifacts_snapshot,
    );

    if let Some(desc) = anomaly_description {
        if threat_score >= 0.45 && !profile.anomalies_detected.contains(&desc) {
            profile.anomalies_detected.insert(0, desc);
        }
    }

    temp_stored.current_risk_score = profile.current_risk_score;
    temp_stored.risk_level = profile.risk_level.clone();

    state
        .db
        .insert_telemetry_event(&temp_stored, &dedup_fingerprint);
    state
        .profiles
        .insert(device.employee_id.clone(), profile.clone());

    if let Ok(broadcast_msg) = serde_json::to_string(&json!({
        "type": "UEBA_EVENT_UPDATE",
        "device_id": device.device_id,
        "event": &temp_stored,
        "profile": &profile
    })) {
        let _ = state.ws_broadcaster.send(broadcast_msg);
    }

    (temp_stored, profile)
}
