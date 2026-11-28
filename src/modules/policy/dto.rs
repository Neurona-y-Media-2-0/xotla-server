use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionPolicy {
    pub version: u64,
    pub trusted_download_hosts: Vec<String>,
    pub protected_domains: Vec<String>,
    pub dangerous_extensions: Vec<String>,
}

impl Default for ExtensionPolicy {
    fn default() -> Self {
        Self {
            version: 1,
            trusted_download_hosts: vec![
                "tools.empresa.mx".to_string(),
                "aegisqro.internal".to_string(),
            ],
            protected_domains: vec![
                "apple-support.com".to_string(),
                "sat.gob.mx".to_string(),
                "bbva.mx".to_string(),
                "banorte.com".to_string(),
                "aegisqro.internal".to_string(),
            ],
            dangerous_extensions: vec![
                ".exe", ".com", ".msi", ".msp", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
                ".wsf", ".wsh", ".js", ".jse", ".hta", ".scr", ".pif", ".cpl", ".reg",
                ".iso", ".img", ".vhd", ".vhdx", ".lnk", ".jar", ".apk", ".dll", ".sys",
                ".zip", ".rar", ".7z", ".tar", ".gz", ".cab", ".dmg", ".pkg", ".sh",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdatePolicyRequest {
    pub trusted_download_hosts: Option<Vec<String>>,
    pub protected_domains: Option<Vec<String>>,
    pub dangerous_extensions: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminLoginRequest {
    #[serde(alias = "username")]
    pub usuario: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyAuditEntry {
    pub version: u64,
    pub actor: String,
    pub updated_at: DateTime<Utc>,
    pub summary: String,
}
