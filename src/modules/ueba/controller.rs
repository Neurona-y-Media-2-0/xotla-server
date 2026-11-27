use axum::{
    extract::{Path, State},
    Json,
};
use chrono::Utc;
use crate::{
    modules::ueba::model::EmployeeRiskProfile,
    state::AppState,
};

pub async fn get_profile_handler(
    State(state): State<AppState>,
    Path(employee_id): Path<String>,
) -> Json<EmployeeRiskProfile> {
    if let Some(existing) = state.profiles.get(&employee_id) {
        return Json(existing.clone());
    }

    Json(EmployeeRiskProfile {
        employee_id,
        department: "Contabilidad".to_string(),
        baseline_risk: 0.12,
        current_risk_score: 0.12,
        risk_level: "LOW".to_string(),
        anomalies_detected: Vec::new(),
        recommended_action: "MONITOR".to_string(),
        total_events: 0,
        updated_at: Utc::now(),
    })
}
