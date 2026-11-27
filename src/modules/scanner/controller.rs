use axum::{
    extract::State,
    response::Html,
    Json,
};
use crate::{
    modules::scanner::{
        dto::{FileScanRequest, ScannedArtifactRecord},
        service::inspect_and_purge_ephemeral,
    },
    state::AppState,
};

pub async fn db_viewer_page_handler() -> Html<&'static str> {
    Html(include_str!("db_viewer.html"))
}

pub async fn scan_file_handler(
    State(state): State<AppState>,
    Json(req): Json<FileScanRequest>,
) -> Json<ScannedArtifactRecord> {
    let record = inspect_and_purge_ephemeral(&state, req);
    Json(record)
}

pub async fn list_scanned_artifacts_handler(
    State(state): State<AppState>,
) -> Json<Vec<ScannedArtifactRecord>> {
    Json(state.db.load_scanned_artifacts())
}
