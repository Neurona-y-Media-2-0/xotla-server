use axum::{
    extract::State,
    http::StatusCode,
    response::Html,
    Json,
};
use serde_json::{json, Value};
use crate::{
    modules::enterprise::{
        dto::{
            AllocateCompanyRequest, GenerateTempPasswordRequest, IssueClientTokenRequest,
            RevokeTokenRequest,
        },
        service::{
            generate_temp_password, get_enterprise_account, issue_or_activate_client_token,
            update_company_quota, DEFAULT_COMPANY_ID,
        },
    },
    state::AppState,
};

pub async fn enterprise_admin_page_handler() -> Html<&'static str> {
    Html(include_str!("admin_tokens.html"))
}

pub async fn get_enterprise_overview_handler(
    State(state): State<AppState>,
) -> Json<Value> {
    let account = get_enterprise_account(&state, DEFAULT_COMPANY_ID);
    let tokens = state.db.load_enterprise_tokens(DEFAULT_COMPANY_ID);

    Json(json!({
        "enterprise_account": account,
        "client_tokens": tokens
    }))
}

pub async fn update_enterprise_quota_handler(
    State(state): State<AppState>,
    Json(req): Json<AllocateCompanyRequest>,
) -> Json<Value> {
    let updated = update_company_quota(&state, req);
    let tokens = state.db.load_enterprise_tokens(&updated.company_id);
    Json(json!({
        "status": "QUOTA_UPDATED",
        "enterprise_account": updated,
        "client_tokens": tokens
    }))
}

pub async fn issue_enterprise_token_handler(
    State(state): State<AppState>,
    Json(req): Json<IssueClientTokenRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match issue_or_activate_client_token(&state, req) {
        Ok((tok, acc)) => Ok(Json(json!({
            "status": "TOKEN_ISSUED_AND_ACTIVE",
            "token": tok,
            "enterprise_account": acc
        }))),
        Err(msg) => Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "status": "TOKEN_QUOTA_EXCEEDED",
                "error": msg
            })),
        )),
    }
}

pub async fn generate_temp_password_handler(
    State(state): State<AppState>,
    Json(req): Json<GenerateTempPasswordRequest>,
) -> Json<Value> {
    let (plain_password, password_sha256, expires_at, account) =
        generate_temp_password(&state, req);
    Json(json!({
        "status": "TEMP_PASSWORD_CREATED",
        "temp_password": plain_password,
        "password_sha256": password_sha256,
        "expires_at": expires_at,
        "enterprise_account": account
    }))
}

pub async fn revoke_enterprise_token_handler(
    State(state): State<AppState>,
    Json(req): Json<RevokeTokenRequest>,
) -> Json<Value> {
    state.db.revoke_enterprise_token(&req.token_id);
    let account = get_enterprise_account(&state, DEFAULT_COMPANY_ID);
    let tokens = state.db.load_enterprise_tokens(DEFAULT_COMPANY_ID);
    Json(json!({
        "status": "TOKEN_REVOKED",
        "revoked_token_id": req.token_id,
        "enterprise_account": account,
        "client_tokens": tokens
    }))
}
