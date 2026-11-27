// src/modules/ws/handler.rs
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use crate::{
    modules::{
        devices::{
            dto::{AgentKind, HandshakeRequest},
            service::{register_or_recognize_device, resolve_device_by_token},
        },
        security::{
            inspector::{
                inspect_json_value, inspect_raw_text, sanitize_json_value, sanitize_string,
                MAX_WS_BYTES,
            },
            rate_limit::record_blocked_threat,
        },
        ueba::engine::evaluate_and_record_event,
        ws::session::{mark_device_connection, WsIncomingMessage, WsQueryParams},
    },
    state::AppState,
};

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<WsQueryParams>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.max_message_size(MAX_WS_BYTES)
        .on_upgrade(move |socket| handle_socket(socket, params, state))
}

async fn handle_socket(socket: WebSocket, params: WsQueryParams, state: AppState) {
    let device = if let Some(tok) = &params.token {
        resolve_device_by_token(&state, tok)
    } else {
        None
    }
    .unwrap_or_else(|| {
        let hw = params
            .hardware_id
            .as_deref()
            .map(|s| sanitize_string(s, 128))
            .unwrap_or_else(|| "ws_auto_hw".to_string());
        let emp = params
            .employee_id
            .as_deref()
            .map(|s| sanitize_string(s, 64))
            .unwrap_or_else(|| "emp_042".to_string());
        let hs = register_or_recognize_device(
            &state,
            HandshakeRequest {
                hardware_id: hw,
                employee_id: Some(emp),
                department: Some("Contabilidad".to_string()),
                agent_kind: Some(AgentKind::WindowsOs),
                platform: None,
                os_version: None,
                device_model: None,
                agent_version: None,
                hostname: Some("ws-connected-node".to_string()),
            },
        );
        resolve_device_by_token(&state, &hs.session_token).expect("Registered device")
    });

    mark_device_connection(&state, &device, true);

    let (mut sender, mut receiver) = socket.split();
    let mut rx_broadcast = state.ws_broadcaster.subscribe();

    let welcome = json!({
        "type": "WS_SESSION_READY",
        "device_id": device.device_id,
        "employee_id": device.employee_id,
        "session_token": device.session_token,
        "role": params.role.as_deref().map(|r| sanitize_string(r, 32)).unwrap_or_else(|| "AGENT".to_string())
    });
    let _ = sender.send(Message::Text(welcome.to_string())).await;

    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = rx_broadcast.recv().await {
            if sender.send(Message::Text(msg)).await.is_err() {
                break;
            }
        }
    });

    let state_clone = state.clone();
    let device_clone = device.clone();
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(Message::Text(text))) = receiver.next().await {
            if text.len() > MAX_WS_BYTES || inspect_raw_text(&text, false).is_err() {
                record_blocked_threat(
                    &state_clone,
                    &device_clone.device_id,
                    "/v1/ws",
                    "WS_MALICIOUS_PACKET",
                    "Blocked malicious WebSocket message",
                )
                .await;
                continue;
            }

            if let Ok(mut incoming) = serde_json::from_str::<WsIncomingMessage>(&text) {
                if inspect_json_value(&incoming.payload, 0, true).is_err() {
                    record_blocked_threat(
                        &state_clone,
                        &device_clone.device_id,
                        "/v1/ws",
                        "WS_MALICIOUS_JSON",
                        "Blocked malicious JSON payload in WebSocket",
                    )
                    .await;
                    continue;
                }
                sanitize_json_value(&mut incoming.payload);

                let source = incoming
                    .source
                    .as_deref()
                    .map(|s| sanitize_string(s, 64))
                    .unwrap_or_else(|| "WS_STREAM".to_string());
                let event_type = incoming
                    .event_type
                    .as_deref()
                    .map(|s| sanitize_string(s, 64))
                    .unwrap_or_else(|| "REALTIME_TELEMETRY".to_string());
                let score = incoming.threat_score.unwrap_or(0.35).clamp(0.0, 1.0);
                let anomaly = incoming.anomaly.as_deref().map(|a| sanitize_string(a, 512));

                evaluate_and_record_event(
                    &state_clone,
                    &device_clone,
                    &source,
                    &event_type,
                    score,
                    anomaly,
                    incoming.payload,
                )
                .await;
            } else if let Ok(mut raw_val) = serde_json::from_str::<Value>(&text) {
                if inspect_json_value(&raw_val, 0, true).is_err() {
                    record_blocked_threat(
                        &state_clone,
                        &device_clone.device_id,
                        "/v1/ws",
                        "WS_MALICIOUS_JSON",
                        "Blocked malicious raw JSON in WebSocket",
                    )
                    .await;
                    continue;
                }
                sanitize_json_value(&mut raw_val);

                evaluate_and_record_event(
                    &state_clone,
                    &device_clone,
                    "WS_RAW_AGENT",
                    "AGENT_PACKET",
                    0.25,
                    None,
                    raw_val,
                )
                .await;
            }
        }
    });

    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    }

    mark_device_connection(&state, &device, false);
}
