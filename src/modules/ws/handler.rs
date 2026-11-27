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
    ws.on_upgrade(move |socket| handle_socket(socket, params, state))
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
            .unwrap_or_else(|| "ws_auto_hw".to_string());
        let emp = params
            .employee_id
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
        "role": params.role.unwrap_or_else(|| "AGENT".to_string())
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
            if let Ok(incoming) = serde_json::from_str::<WsIncomingMessage>(&text) {
                let source = incoming.source.unwrap_or_else(|| "WS_STREAM".to_string());
                let event_type = incoming
                    .event_type
                    .unwrap_or_else(|| "REALTIME_TELEMETRY".to_string());
                let score = incoming.threat_score.unwrap_or(0.35);

                evaluate_and_record_event(
                    &state_clone,
                    &device_clone,
                    &source,
                    &event_type,
                    score,
                    incoming.anomaly,
                    incoming.payload,
                )
                .await;
            } else if let Ok(raw_val) = serde_json::from_str::<Value>(&text) {
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
