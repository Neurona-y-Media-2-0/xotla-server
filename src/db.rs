use std::path::Path;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use crate::modules::devices::dto::{AgentKind, RegisteredDevice};

pub struct Database {
    db_path: String,
}

impl Database {
    pub fn new(db_path: &str) -> Self {
        let db = Self {
            db_path: db_path.to_string(),
        };
        db.init_schema();
        db
    }

    fn connect(&self) -> Connection {
        Connection::open(&self.db_path).expect("Failed to open SQLite database")
    }

    fn init_schema(&self) {
        let conn = self.connect();
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                hardware_id TEXT NOT NULL UNIQUE,
                hardware_sha256 TEXT NOT NULL UNIQUE,
                employee_id TEXT NOT NULL,
                department TEXT NOT NULL,
                agent_kind TEXT NOT NULL,
                platform TEXT NOT NULL,
                os_version TEXT NOT NULL,
                device_model TEXT NOT NULL,
                agent_version TEXT NOT NULL,
                hostname TEXT NOT NULL,
                session_token TEXT NOT NULL,
                token_sha256 TEXT NOT NULL,
                approved INTEGER NOT NULL DEFAULT 1,
                registered_at TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );
            ",
        )
        .expect("Failed to initialize SQLite schema");
    }

    pub fn upsert_device(&self, dev: &RegisteredDevice) {
        let conn = self.connect();
        let hw_sha256 = sha256_hex(&dev.hardware_id);
        let tok_sha256 = sha256_hex(&dev.session_token);
        let kind_str = serde_json::to_string(&dev.agent_kind)
            .unwrap_or_else(|_| "\"WINDOWS_OS\"".to_string())
            .trim_matches('"')
            .to_string();

        let _ = conn.execute(
            "
            INSERT INTO devices (
                device_id, hardware_id, hardware_sha256, employee_id, department,
                agent_kind, platform, os_version, device_model, agent_version,
                hostname, session_token, token_sha256, approved, registered_at, last_seen
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
            ON CONFLICT(device_id) DO UPDATE SET
                last_seen = excluded.last_seen,
                hostname = excluded.hostname,
                os_version = excluded.os_version
            ",
            params![
                dev.device_id,
                dev.hardware_id,
                hw_sha256,
                dev.employee_id,
                dev.department,
                kind_str,
                dev.platform,
                dev.os_version,
                dev.device_model,
                dev.agent_version,
                dev.hostname,
                dev.session_token,
                tok_sha256,
                if dev.approved { 1 } else { 0 },
                dev.registered_at.to_rfc3339(),
                dev.last_seen.to_rfc3339(),
            ],
        );
    }

    pub fn load_all_devices(&self) -> Vec<RegisteredDevice> {
        let conn = self.connect();
        let mut stmt = match conn.prepare(
            "SELECT device_id, hardware_id, employee_id, department, agent_kind,
                    platform, os_version, device_model, agent_version, hostname,
                    session_token, approved, registered_at, last_seen
             FROM devices",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let iter = stmt.query_map([], |row| {
            let kind_raw: String = row.get(4)?;
            let agent_kind = match kind_raw.as_str() {
                "BROWSER_EXT" => AgentKind::BrowserExt,
                "ANDROID_AGENT" => AgentKind::AndroidAgent,
                _ => AgentKind::WindowsOs,
            };
            let reg_str: String = row.get(12)?;
            let seen_str: String = row.get(13)?;
            let registered_at = DateTime::parse_from_rfc3339(&reg_str)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let last_seen = DateTime::parse_from_rfc3339(&seen_str)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let approved_int: i32 = row.get(11)?;

            Ok(RegisteredDevice {
                device_id: row.get(0)?,
                hardware_id: row.get(1)?,
                employee_id: row.get(2)?,
                department: row.get(3)?,
                agent_kind,
                platform: row.get(5)?,
                os_version: row.get(6)?,
                device_model: row.get(7)?,
                agent_version: row.get(8)?,
                hostname: row.get(9)?,
                session_token: row.get(10)?,
                approved: approved_int != 0,
                online: false,
                registered_at,
                last_seen,
            })
        });

        match iter {
            Ok(rows) => rows.filter_map(Result::ok).collect(),
            Err(_) => Vec::new(),
        }
    }
}

pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn purge_ephemeral_artifact(filename: &str) -> bool {
    let tmp_dir = std::env::temp_dir().join("aegisqro_ephemeral");
    let candidate = tmp_dir.join(
        Path::new(filename)
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("artifact.tmp")),
    );
    if candidate.exists() {
        let _ = std::fs::remove_file(&candidate);
    }
    true
}
