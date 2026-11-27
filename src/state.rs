use std::sync::Arc;
use dashmap::DashMap;
use tokio::sync::{broadcast, RwLock};
use crate::{
    config::AppConfig,
    modules::{
        devices::dto::RegisteredDevice,
        telemetry::dto::StoredTelemetryEvent,
        ueba::model::EmployeeRiskProfile,
    },
};

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub devices_by_hw: Arc<DashMap<String, RegisteredDevice>>,
    pub devices_by_id: Arc<DashMap<String, String>>,
    pub token_to_hw: Arc<DashMap<String, String>>,
    pub active_ws_sessions: Arc<DashMap<String, usize>>,
    pub profiles: Arc<DashMap<String, EmployeeRiskProfile>>,
    pub events: Arc<RwLock<Vec<StoredTelemetryEvent>>>,
    pub ws_broadcaster: broadcast::Sender<String>,
}

impl AppState {
    pub fn new(config: AppConfig) -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self {
            config,
            devices_by_hw: Arc::new(DashMap::new()),
            devices_by_id: Arc::new(DashMap::new()),
            token_to_hw: Arc::new(DashMap::new()),
            active_ws_sessions: Arc::new(DashMap::new()),
            profiles: Arc::new(DashMap::new()),
            events: Arc::new(RwLock::new(Vec::new())),
            ws_broadcaster: tx,
        }
    }
}
