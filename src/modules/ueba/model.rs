use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaFeatureVector {
    pub department_id: u8,
    pub hour_of_day: u8,
    pub powershell_spawned: u8,
    pub homograph_attempts: u32,
    pub sandbox_threat_score: f32,
    pub apk_high_risk_perms: u32,
    pub external_ip_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralBreakdown {
    pub web_phishing_incidents: u32,
    pub android_malicious_apks: u32,
    pub spoofed_documents_or_images: u32,
    pub clean_files_inspected: u32,
    pub active_devices_count: usize,
    pub primary_attack_vector: String,
    pub behavior_deviation_percent: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmployeeRiskProfile {
    pub employee_id: String,
    pub department: String,
    pub baseline_risk: f32,
    pub current_risk_score: f32,
    pub isolation_forest_score: f32,
    pub risk_level: String,
    pub anomalies_detected: Vec<String>,
    pub recommended_action: String,
    pub total_events: u32,
    pub features: UebaFeatureVector,
    pub behavioral_breakdown: BehavioralBreakdown,
    pub llm_behavioral_summary: String,
    pub updated_at: DateTime<Utc>,
}
