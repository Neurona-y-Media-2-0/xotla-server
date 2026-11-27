use std::env;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub host: String,
    pub port: u16,
    pub public_ws_base: String,
    pub admin_user: String,
    pub admin_password: String,
    pub db_path: String,
}

impl AppConfig {
    pub fn from_env() -> Self {
        let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8080);
        let public_ws_base = env::var("PUBLIC_WS_BASE")
            .unwrap_or_else(|_| format!("ws://54.146.211.248:{}", port));
        let admin_user = env::var("AEGIS_ADMIN_USER").unwrap_or_else(|_| "admin".to_string());
        let admin_password =
            env::var("AEGIS_ADMIN_PASSWORD").unwrap_or_else(|_| "aegisqro2026".to_string());
        let db_path = env::var("AEGIS_DB_PATH")
            .unwrap_or_else(|_| "aegisqro_devices.sqlite".to_string());

        Self {
            host,
            port,
            public_ws_base,
            admin_user,
            admin_password,
            db_path,
        }
    }
}
