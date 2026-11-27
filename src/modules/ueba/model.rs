use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmployeeRiskProfile {
    pub employee_id: String,
    pub department: String,
    pub baseline_risk: f32,
    pub current_risk_score: f32,
    pub risk_level: String,
    pub anomalies_detected: Vec<String>,
    pub recommended_action: String,
    pub total_events: u32,
    pub updated_at: DateTime<Utc>,
}
