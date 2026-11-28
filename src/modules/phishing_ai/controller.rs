use axum::{extract::State, Json};
use crate::{
    modules::phishing_ai::{
        dto::{PhishingAnalysisResult, PhishingAnalyzeRequest},
        service::analyze_phishing_text,
    },
    state::AppState,
};

pub async fn analyze_phishing_handler(
    State(state): State<AppState>,
    Json(req): Json<PhishingAnalyzeRequest>,
) -> Json<PhishingAnalysisResult> {
    let res = analyze_phishing_text(&state, req).await;
    Json(res)
}
