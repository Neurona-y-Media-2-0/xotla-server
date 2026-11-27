mod config;
mod modules;
mod state;

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use tower_http::cors::{Any, CorsLayer};
use crate::{
    config::AppConfig,
    modules::{
        devices::controller::{handshake_handler, list_devices_handler},
        telemetry::controller::{
            android_sandbox_handler, browser_telemetry_handler, list_events_handler,
            windows_sandbox_handler,
        },
        ueba::controller::get_profile_handler,
        ws::handler::ws_handler,
    },
    state::AppState,
};

async fn health_handler(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "status": "OK",
        "service": "xotla-server (AegisQRO Core)",
        "registered_devices": state.devices_by_hw.len(),
        "endpoints": {
            "handshake": "POST /v1/devices/handshake",
            "devices": "GET /v1/devices",
            "ws": "WS /v1/ws?token=<session_token>",
            "browser_telemetry": "POST /v1/telemetry/browser",
            "windows_sandbox": "POST /v1/sandbox/windows",
            "android_sandbox": "POST /v1/sandbox/android",
            "ueba_profile": "GET /v1/ueba/profile/{employee_id}",
            "events": "GET /v1/events"
        }
    }))
}

#[tokio::main]
async fn main() {
    let config = AppConfig::from_env();
    let bind_addr = format!("{}:{}", config.host, config.port);
    let state = AppState::new(config);

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/", get(health_handler))
        .route("/health", get(health_handler))
        .route("/v1/devices/handshake", post(handshake_handler))
        .route("/v1/devices", get(list_devices_handler))
        .route("/v1/ws", get(ws_handler))
        .route("/v1/telemetry/browser", post(browser_telemetry_handler))
        .route("/telemetry/browser", post(browser_telemetry_handler))
        .route("/v1/sandbox/windows", post(windows_sandbox_handler))
        .route("/sandbox/windows", post(windows_sandbox_handler))
        .route("/v1/sandbox/android", post(android_sandbox_handler))
        .route("/sandbox/android", post(android_sandbox_handler))
        .route("/v1/ueba/profile/:employee_id", get(get_profile_handler))
        .route("/ueba/profile/:employee_id", get(get_profile_handler))
        .route("/v1/events", get(list_events_handler))
        .route("/events", get(list_events_handler))
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("Failed to bind TCP listener");

    println!("[INFO] xotla-server listening on http://{}", bind_addr);
    axum::serve(listener, app).await.expect("Server crashed");
}
