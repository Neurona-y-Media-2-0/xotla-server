use std::sync::Arc;
use dashmap::DashMap;
use tokio::sync::{broadcast, RwLock};
use crate::{
    config::AppConfig,
    db::Database,
    modules::{
        devices::dto::RegisteredDevice,
        policy::dto::{ExtensionPolicy, PolicyAuditEntry},
        telemetry::dto::StoredTelemetryEvent,
        ueba::model::EmployeeRiskProfile,
    },
};

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub db: Arc<Database>,
    pub devices_by_hw: Arc<DashMap<String, RegisteredDevice>>,
    pub devices_by_id: Arc<DashMap<String, String>>,
    pub token_to_hw: Arc<DashMap<String, String>>,
    pub active_ws_sessions: Arc<DashMap<String, usize>>,
    pub profiles: Arc<DashMap<String, EmployeeRiskProfile>>,
    pub events: Arc<RwLock<Vec<StoredTelemetryEvent>>>,
    pub policy: Arc<RwLock<ExtensionPolicy>>,
    pub policy_audit_log: Arc<RwLock<Vec<PolicyAuditEntry>>>,
    pub admin_sessions: Arc<DashMap<String, (String, String)>>,
    pub ws_broadcaster: broadcast::Sender<String>,
}

impl AppState {
    pub fn new(config: AppConfig) -> Self {
        let (tx, _) = broadcast::channel(1024);
        let db = Arc::new(Database::new(&config.db_path));
        let devices_by_hw = Arc::new(DashMap::new());
        let devices_by_id = Arc::new(DashMap::new());
        let token_to_hw = Arc::new(DashMap::new());

        for dev in db.load_all_devices() {
            devices_by_id.insert(dev.device_id.clone(), dev.hardware_id.clone());
            token_to_hw.insert(dev.session_token.clone(), dev.hardware_id.clone());
            devices_by_hw.insert(dev.hardware_id.clone(), dev);
        }

        Self {
            config,
            db,
            devices_by_hw,
            devices_by_id,
            token_to_hw,
            active_ws_sessions: Arc::new(DashMap::new()),
            profiles: Arc::new(DashMap::new()),
            events: Arc::new(RwLock::new(Vec::new())),
            policy: Arc::new(RwLock::new(ExtensionPolicy::default())),
            policy_audit_log: Arc::new(RwLock::new(Vec::new())),
            admin_sessions: Arc::new(DashMap::new()),
            ws_broadcaster: tx,
        }
    }
}
