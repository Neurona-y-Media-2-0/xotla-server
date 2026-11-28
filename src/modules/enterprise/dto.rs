use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseAccount {
    pub company_id: String,
    pub company_name: String,
    pub master_account_email: String,
    pub plan_tier: String,
    pub total_allocated_tokens: u32,
    pub active_tokens_used: u32,
    pub available_tokens: u32,
    pub account_status: String,
    pub has_temp_password: bool,
    pub temp_password_expires_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseClientToken {
    pub token_id: String,
    pub company_id: String,
    pub token_sha256: String,
    pub assigned_device_id: Option<String>,
    pub assigned_employee_id: Option<String>,
    pub client_label: String,
    pub platform: String,
    pub status: String,
    pub activated_at: String,
    pub last_used_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AllocateCompanyRequest {
    pub company_id: Option<String>,
    pub company_name: String,
    pub master_account_email: String,
    pub total_allocated_tokens: u32,
    pub temp_password: Option<String>,
    pub expires_in_hours: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GenerateTempPasswordRequest {
    pub company_id: Option<String>,
    pub custom_password: Option<String>,
    pub expires_in_hours: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IssueClientTokenRequest {
    pub company_id: Option<String>,
    pub employee_id: String,
    pub device_id: Option<String>,
    pub client_label: String,
    pub platform: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RevokeTokenRequest {
    pub token_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToggleAccountStatusRequest {
    pub status: Option<String>,
}
