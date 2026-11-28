use axum::{
    extract::{Path, State},
    Json,
};
use crate::{
    modules::ueba::{
        engine::build_profile_from_stored_data,
        model::EmployeeRiskProfile,
    },
    state::AppState,
};

pub async fn get_profile_handler(
    State(state): State<AppState>,
    Path(employee_id): Path<String>,
) -> Json<EmployeeRiskProfile> {
    let events_snapshot = state.events.read().await.clone();
    let artifacts_snapshot = state.db.load_scanned_artifacts();
    let devices_count = state.devices_by_hw.len();

    let profile = build_profile_from_stored_data(
        &employee_id,
        "Contabilidad",
        devices_count,
        &events_snapshot,
        &artifacts_snapshot,
    );

    state.profiles.insert(employee_id, profile.clone());
    Json(profile)
}
