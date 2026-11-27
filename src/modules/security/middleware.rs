// src/modules/security/middleware.rs
use std::sync::atomic::Ordering;
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use crate::{
    modules::security::{
        antivirus::{check_content_type, check_raw_binary_bytes},
        crypto::{decrypt_envelope_to_json, EncryptedEnvelope, DEFAULT_SHARED_KEY},
        inspector::{
            inspect_json_value, inspect_raw_text, sanitize_json_value, MAX_BODY_BYTES,
        },
        rate_limit::{check_rate_limit, extract_client_key, record_blocked_threat},
    },
    state::AppState,
};

fn build_block_response(status: StatusCode, category: &str, reason: &str) -> Response {
    let mut resp = (
        status,
        Json(json!({
            "status": "BLOCKED",
            "shield": "XOTLA_ANTIVIRUS_WAF_CRYPTO",
            "category": category,
            "error": reason
        })),
    )
        .into_response();
    attach_security_headers(resp.headers_mut());
    resp
}

fn attach_security_headers(headers: &mut HeaderMap) {
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::X_XSS_PROTECTION,
        HeaderValue::from_static("1; mode=block"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        "x-xotla-shield",
        HeaderValue::from_static("ANTIVIRUS_WAF_E2E_CRYPTO_ACTIVE"),
    );
}

fn inspect_headers(headers: &HeaderMap) -> Result<(), (&'static str, &'static str)> {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());
    check_content_type(ct)?;

    for (name, val) in headers.iter() {
        let key = name.as_str();
        if key == "cookie" || key == "accept" || key == "accept-encoding" {
            continue;
        }
        if let Ok(raw) = val.to_str() {
            if raw.len() > 4096 {
                return Err(("HEADER_TOO_LARGE", "HTTP header exceeds maximum length"));
            }
            inspect_raw_text(raw, true)?;
        }
    }
    Ok(())
}

fn resolve_shared_key(headers: &HeaderMap) -> String {
    headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_SHARED_KEY.to_string())
}

pub async fn security_shield_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let method = req.method().clone();
    let client_key = extract_client_key(req.headers());
    let shared_key = resolve_shared_key(req.headers());

    if !check_rate_limit(&state, &client_key, &path) {
        record_blocked_threat(
            &state,
            &client_key,
            &path,
            "RATE_LIMIT_EXCEEDED",
            "Too many requests from client",
        )
        .await;
        return build_block_response(
            StatusCode::TOO_MANY_REQUESTS,
            "RATE_LIMIT_EXCEEDED",
            "Demasiadas peticiones; bloqueado temporalmente por proteccion Xotla",
        );
    }

    if let Err((cat, reason)) = inspect_raw_text(&path, true).and_then(|_| inspect_raw_text(&query, true)) {
        record_blocked_threat(&state, &client_key, &path, cat, reason).await;
        return build_block_response(StatusCode::BAD_REQUEST, cat, reason);
    }

    if let Err((cat, reason)) = inspect_headers(req.headers()) {
        record_blocked_threat(&state, &client_key, &path, cat, reason).await;
        return build_block_response(StatusCode::BAD_REQUEST, cat, reason);
    }

    if method == Method::POST || method == Method::PUT || method == Method::PATCH {
        let (parts, body) = req.into_parts();
        let bytes = match to_bytes(body, MAX_BODY_BYTES).await {
            Ok(b) => b,
            Err(_) => {
                record_blocked_threat(
                    &state,
                    &client_key,
                    &path,
                    "PAYLOAD_TOO_LARGE",
                    "Body exceeds 256KB limit",
                )
                .await;
                return build_block_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "PAYLOAD_TOO_LARGE",
                    "Payload excede el limite maximo permitido (256 KB)",
                );
            }
        };

        if !bytes.is_empty() {
            if let Err((cat, reason)) = check_raw_binary_bytes(&bytes) {
                record_blocked_threat(&state, &client_key, &path, cat, reason).await;
                return build_block_response(StatusCode::FORBIDDEN, cat, reason);
            }

            let is_dedicated_scan = path.ends_with("/security/scan");
            if !is_dedicated_scan {
                let is_sandbox = path.contains("sandbox") || path.contains("telemetry");
                if let Ok(mut json_val) = serde_json::from_slice::<Value>(&bytes) {
                    if json_val.get("aegis_enc").and_then(|v| v.as_str()) == Some("v1") {
                        match serde_json::from_value::<EncryptedEnvelope>(json_val) {
                            Ok(env) => match decrypt_envelope_to_json(&env, &shared_key) {
                                Ok(decrypted) => {
                                    state
                                        .decrypted_payloads_count
                                        .fetch_add(1, Ordering::Relaxed);
                                    json_val = decrypted;
                                }
                                Err((cat, reason)) => {
                                    record_blocked_threat(&state, &client_key, &path, cat, reason)
                                        .await;
                                    return build_block_response(StatusCode::FORBIDDEN, cat, reason);
                                }
                            },
                            Err(_) => {
                                record_blocked_threat(
                                    &state,
                                    &client_key,
                                    &path,
                                    "MALFORMED_ENCRYPTED_ENVELOPE",
                                    "Invalid encrypted envelope format",
                                )
                                .await;
                                return build_block_response(
                                    StatusCode::BAD_REQUEST,
                                    "MALFORMED_ENCRYPTED_ENVELOPE",
                                    "Sobre cifrado invalido",
                                );
                            }
                        }
                    }

                    if let Err((cat, reason)) = inspect_json_value(&json_val, 0, is_sandbox) {
                        record_blocked_threat(&state, &client_key, &path, cat, reason).await;
                        return build_block_response(StatusCode::FORBIDDEN, cat, reason);
                    }
                    if sanitize_json_value(&mut json_val) {
                        state
                            .sanitized_payloads_count
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    let clean_bytes = serde_json::to_vec(&json_val).unwrap_or_else(|_| bytes.to_vec());
                    let rebuilt = Request::from_parts(parts, Body::from(clean_bytes));
                    let mut resp = next.run(rebuilt).await;
                    attach_security_headers(resp.headers_mut());
                    return resp;
                } else if let Ok(raw_str) = std::str::from_utf8(&bytes) {
                    if let Err((cat, reason)) = inspect_raw_text(raw_str, !is_sandbox) {
                        record_blocked_threat(&state, &client_key, &path, cat, reason).await;
                        return build_block_response(StatusCode::FORBIDDEN, cat, reason);
                    }
                }
            }
        }

        let rebuilt = Request::from_parts(parts, Body::from(bytes));
        let mut resp = next.run(rebuilt).await;
        attach_security_headers(resp.headers_mut());
        return resp;
    }

    let mut resp = next.run(req).await;
    attach_security_headers(resp.headers_mut());
    resp
}
