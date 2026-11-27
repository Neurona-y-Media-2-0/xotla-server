use std::env;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub host: String,
    pub port: u16,
    pub public_ws_base: String,
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

        Self {
            host,
            port,
            public_ws_base,
        }
    }
}
