use std::path::Path;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde_json::Value;
use sha2::{Digest, Sha256};
use crate::modules::{
    devices::dto::{AgentKind, RegisteredDevice},
    scanner::dto::ScannedArtifactRecord,
    telemetry::dto::StoredTelemetryEvent,
};

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

            CREATE TABLE IF NOT EXISTS telemetry_events (
                event_id TEXT PRIMARY KEY,
                event_sha256 TEXT NOT NULL UNIQUE,
                device_id TEXT NOT NULL,
                employee_id TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                threat_score REAL NOT NULL,
                current_risk_score REAL NOT NULL,
                risk_level TEXT NOT NULL,
                raw_payload TEXT NOT NULL,
                received_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scanned_artifacts (
                artifact_sha256 TEXT PRIMARY KEY,
                file_type TEXT NOT NULL,
                detected_magic TEXT NOT NULL,
                verdict TEXT NOT NULL,
                threat_score REAL NOT NULL,
                detection_method TEXT NOT NULL,
                detection_reasons TEXT NOT NULL,
                device_id TEXT NOT NULL,
                employee_id TEXT NOT NULL,
                ephemeral_purged INTEGER NOT NULL DEFAULT 1,
                scanned_at TEXT NOT NULL
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

    pub fn upsert_scanned_artifact(&self, rec: &ScannedArtifactRecord) {
        let conn = self.connect();
        let reasons_json =
            serde_json::to_string(&rec.detection_reasons).unwrap_or_else(|_| "[]".to_string());

        let _ = conn.execute(
            "
            INSERT INTO scanned_artifacts (
                artifact_sha256, file_type, detected_magic, verdict, threat_score,
                detection_method, detection_reasons, device_id, employee_id,
                ephemeral_purged, scanned_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            ON CONFLICT(artifact_sha256) DO UPDATE SET
                verdict = excluded.verdict,
                threat_score = excluded.threat_score,
                detection_method = excluded.detection_method,
                detection_reasons = excluded.detection_reasons,
                scanned_at = excluded.scanned_at
            ",
            params![
                rec.artifact_sha256,
                rec.file_type,
                rec.detected_magic,
                rec.verdict,
                rec.threat_score,
                rec.detection_method,
                reasons_json,
                rec.device_id,
                rec.employee_id,
                if rec.ephemeral_purged { 1 } else { 0 },
                rec.scanned_at.to_rfc3339(),
            ],
        );
    }

    pub fn load_scanned_artifacts(&self) -> Vec<ScannedArtifactRecord> {
        let conn = self.connect();
        let mut stmt = match conn.prepare(
            "SELECT artifact_sha256, file_type, detected_magic, verdict, threat_score,
                    detection_method, detection_reasons, device_id, employee_id,
                    ephemeral_purged, scanned_at
             FROM scanned_artifacts
             ORDER BY scanned_at DESC
             LIMIT 500",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let iter = stmt.query_map([], |row| {
            let reasons_str: String = row.get(6)?;
            let scanned_str: String = row.get(10)?;
            let reasons: Vec<String> = serde_json::from_str(&reasons_str).unwrap_or_default();
            let scanned_at = DateTime::parse_from_rfc3339(&scanned_str)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let purged_int: i32 = row.get(9)?;

            Ok(ScannedArtifactRecord {
                artifact_sha256: row.get(0)?,
                file_type: row.get(1)?,
                detected_magic: row.get(2)?,
                verdict: row.get(3)?,
                threat_score: row.get(4)?,
                detection_method: row.get(5)?,
                detection_reasons: reasons,
                device_id: row.get(7)?,
                employee_id: row.get(8)?,
                ephemeral_purged: purged_int != 0,
                scanned_at,
            })
        });

        match iter {
            Ok(rows) => rows.filter_map(Result::ok).collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn insert_telemetry_event(&self, evt: &StoredTelemetryEvent, dedup_fingerprint: &str) -> bool {
        let conn = self.connect();
        let event_sha256 = sha256_hex(dedup_fingerprint);
        let payload_str = serde_json::to_string(&evt.raw_payload).unwrap_or_else(|_| "{}".to_string());

        let res = conn.execute(
            "
            INSERT INTO telemetry_events (
                event_id, event_sha256, device_id, employee_id, source,
                event_type, threat_score, current_risk_score, risk_level,
                raw_payload, received_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            ON CONFLICT(event_sha256) DO UPDATE SET
                received_at = excluded.received_at,
                current_risk_score = excluded.current_risk_score,
                risk_level = excluded.risk_level
            ",
            params![
                evt.event_id,
                event_sha256,
                evt.device_id,
                evt.employee_id,
                evt.source,
                evt.event_type,
                evt.threat_score,
                evt.current_risk_score,
                evt.risk_level,
                payload_str,
                evt.received_at.to_rfc3339(),
            ],
        );

        res.is_ok()
    }

    pub fn load_all_events(&self) -> Vec<StoredTelemetryEvent> {
        let conn = self.connect();
        let mut stmt = match conn.prepare(
            "SELECT event_id, device_id, employee_id, source, event_type,
                    threat_score, current_risk_score, risk_level, raw_payload, received_at
             FROM telemetry_events
             ORDER BY received_at ASC
             LIMIT 500",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let iter = stmt.query_map([], |row| {
            let raw_str: String = row.get(8)?;
            let received_str: String = row.get(9)?;
            let raw_payload: Value = serde_json::from_str(&raw_str).unwrap_or(Value::Null);
            let received_at = DateTime::parse_from_rfc3339(&received_str)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            Ok(StoredTelemetryEvent {
                event_id: row.get(0)?,
                device_id: row.get(1)?,
                employee_id: row.get(2)?,
                source: row.get(3)?,
                event_type: row.get(4)?,
                threat_score: row.get(5)?,
                current_risk_score: row.get(6)?,
                risk_level: row.get(7)?,
                raw_payload,
                received_at,
            })
        });

        match iter {
            Ok(rows) => rows.filter_map(Result::ok).collect(),
            Err(_) => Vec::new(),
        }
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
