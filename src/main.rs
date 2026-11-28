// src/main.rs
mod config;
mod db;
mod modules;
mod state;

use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{get, head, post, put},
    Json, Router,
};
use serde_json::{json, Value};
use tower_http::cors::{Any, CorsLayer};
use crate::{
    config::AppConfig,
    modules::{
        devices::controller::{handshake_handler, list_devices_handler},
        enterprise::controller::{
            get_enterprise_overview_handler, issue_enterprise_token_handler,
            revoke_enterprise_token_handler, update_enterprise_quota_handler,
        },
        phishing_ai::controller::analyze_phishing_handler,
        policy::controller::{
            admin_login_handler, admin_logout_handler, demo_malicious_exe_handler,
            demo_phishing_page_handler, get_admin_policy_handler, get_public_policy_handler,
            put_admin_policy_handler,
        },
        scanner::controller::{
            db_viewer_page_handler, list_scanned_artifacts_handler, scan_file_handler,
        },
        security::{
            controller::{antivirus_scan_handler, security_status_handler},
            inspector::MAX_BODY_BYTES,
            middleware::security_shield_middleware,
        },
        telemetry::controller::{
            android_sandbox_handler, browser_telemetry_handler, list_events_handler,
            telemetry_batch_handler, windows_sandbox_handler,
        },
        ueba::controller::get_profile_handler,
        ws::handler::ws_handler,
    },
    state::AppState,
};

async fn root_info_handler(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "status": "OK",
        "service": "xotla-server (AegisQRO Core)",
        "security_shield": "ACTIVE_ENFORCING",
        "registered_devices": state.devices_by_hw.len(),
        "endpoints": {
            "health": "HEAD/GET /v1/health",
            "security_status": "GET /v1/security/status",
            "antivirus_scan": "POST /v1/security/scan",
            "handshake": "POST /v1/devices/handshake (alias: /v1/devices/register)",
            "devices": "GET /v1/devices",
            "ws": "WS /v1/ws?token=<session_token>",
            "browser_telemetry": "POST /v1/telemetry/browser",
            "windows_sandbox": "POST /v1/sandbox/windows",
            "android_sandbox": "POST /v1/sandbox/android",
            "telemetry_batch": "POST /v1/telemetry/batch",
            "policy": "GET /v1/policy",
            "admin_login": "POST /admin/login",
            "admin_logout": "POST /admin/logout",
            "admin_policy": "GET/PUT /admin/policy",
            "demo_phishing": "GET /demo-phishing",
            "enterprise_overview": "GET /v1/enterprise",
            "enterprise_quota": "PUT /v1/enterprise/quota",
            "enterprise_issue_token": "POST /v1/enterprise/tokens/issue",
            "enterprise_revoke_token": "POST /v1/enterprise/tokens/revoke",
            "phishing_ai_analyze": "POST /v1/phishing/analyze",
            "scanner_inspect": "POST /v1/scanner/inspect",
            "scanned_artifacts": "GET /v1/scanner/artifacts",
            "ueba_profile": "GET /v1/ueba/profile/{employee_id}",
            "events": "GET /v1/events"
        }
    }))
}

async fn v1_health_handler() -> impl IntoResponse {
    (StatusCode::OK, "OK")
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
        .route("/", get(root_info_handler))
        .route("/health", head(v1_health_handler).get(v1_health_handler))
        .route("/v1/health", head(v1_health_handler).get(v1_health_handler))
        .route("/v1/security/status", get(security_status_handler))
        .route("/security/status", get(security_status_handler))
        .route("/v1/security/scan", post(antivirus_scan_handler))
        .route("/security/scan", post(antivirus_scan_handler))
        .route("/v1/devices/handshake", post(handshake_handler))
        .route("/v1/devices/register", post(handshake_handler))
        .route("/v1/devices", get(list_devices_handler))
        .route("/v1/enterprise", get(get_enterprise_overview_handler))
        .route("/v1/enterprise/quota", put(update_enterprise_quota_handler))
        .route("/v1/enterprise/tokens/issue", post(issue_enterprise_token_handler))
        .route("/v1/enterprise/tokens/revoke", post(revoke_enterprise_token_handler))
        .route("/v1/ws", get(ws_handler))
        .route("/v1/telemetry/browser", post(browser_telemetry_handler))
        .route("/telemetry/browser", post(browser_telemetry_handler))
        .route("/v1/sandbox/windows", post(windows_sandbox_handler))
        .route("/sandbox/windows", post(windows_sandbox_handler))
        .route("/v1/sandbox/android", post(android_sandbox_handler))
        .route("/sandbox/android", post(android_sandbox_handler))
        .route("/v1/telemetry/batch", post(telemetry_batch_handler))
        .route("/telemetry/batch", post(telemetry_batch_handler))
        .route("/v1/policy", get(get_public_policy_handler))
        .route("/policy", get(get_public_policy_handler))
        .route("/admin/login", post(admin_login_handler))
        .route("/admin/logout", post(admin_logout_handler))
        .route(
            "/admin/policy",
            get(get_admin_policy_handler).put(put_admin_policy_handler),
        )
        .route("/demo-phishing", get(demo_phishing_page_handler))
        .route("/dashboard", get(db_viewer_page_handler))
        .route("/soc", get(db_viewer_page_handler))
        .route("/db", get(db_viewer_page_handler))
        .route("/v1/db", get(db_viewer_page_handler))
        .route("/factura_noviembre.exe", get(demo_malicious_exe_handler))
        .route("/v1/phishing/analyze", post(analyze_phishing_handler))
        .route("/phishing/analyze", post(analyze_phishing_handler))
        .route("/v1/scanner/inspect", post(scan_file_handler))
        .route("/v1/scanner/artifacts", get(list_scanned_artifacts_handler))
        .route("/v1/ueba/profile/:employee_id", get(get_profile_handler))
        .route("/ueba/profile/:employee_id", get(get_profile_handler))
        .route("/v1/events", get(list_events_handler))
        .route("/events", get(list_events_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_shield_middleware,
        ))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("Failed to bind TCP listener");

    println!("[INFO] xotla-server listening on http://{}", bind_addr);
    axum::serve(listener, app).await.expect("Server crashed");
}
