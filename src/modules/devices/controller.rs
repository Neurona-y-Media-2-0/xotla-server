use axum::{extract::State, Json};
use crate::{
    modules::devices::{
        dto::{HandshakeRequest, HandshakeResponse, RegisteredDevice},
        service::register_or_recognize_device,
    },
    state::AppState,
};

pub async fn handshake_handler(
    State(state): State<AppState>,
    Json(req): Json<HandshakeRequest>,
) -> Json<HandshakeResponse> {
    let response = register_or_recognize_device(&state, req);

    if let Ok(msg) = serde_json::to_string(&serde_json::json!({
        "type": "DEVICE_HANDSHAKE",
        "data": &response
    })) {
        let _ = state.ws_broadcaster.send(msg);
    }

    Json(response)
}

pub async fn list_devices_handler(
    State(state): State<AppState>,
) -> Json<Vec<RegisteredDevice>> {
    let list = state.db.load_all_devices();
    Json(list)
}
