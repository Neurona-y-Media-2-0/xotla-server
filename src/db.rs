use std::path::Path;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde_json::Value;
use sha2::{Digest, Sha256};
use crate::modules::{
    devices::dto::{AgentKind, RegisteredDevice},
    enterprise::dto::{CompanySitePolicy, EnterpriseAccount, EnterpriseClientToken},
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

            CREATE TABLE IF NOT EXISTS enterprise_accounts (
                company_id TEXT PRIMARY KEY,
                company_name TEXT NOT NULL,
                master_account_email TEXT NOT NULL,
                plan_tier TEXT NOT NULL,
                total_allocated_tokens INTEGER NOT NULL,
                account_status TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS enterprise_client_tokens (
                token_id TEXT PRIMARY KEY,
                company_id TEXT NOT NULL,
                token_sha256 TEXT NOT NULL UNIQUE,
                assigned_device_id TEXT UNIQUE,
                assigned_employee_id TEXT,
                client_label TEXT NOT NULL,
                platform TEXT NOT NULL,
                status TEXT NOT NULL,
                activated_at TEXT NOT NULL,
                last_used_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS enterprise_site_policies (
                company_id TEXT PRIMARY KEY,
                version INTEGER NOT NULL DEFAULT 1,
                allowed_sites_json TEXT NOT NULL,
                blacklisted_sites_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            ",
        )
        .expect("Failed to initialize SQLite schema");

        let _ = conn.execute(
            "ALTER TABLE enterprise_accounts ADD COLUMN temp_password_sha256 TEXT",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE enterprise_accounts ADD COLUMN temp_password_expires_at TEXT",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE enterprise_client_tokens ADD COLUMN secondary_device_id TEXT",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE enterprise_client_tokens ADD COLUMN max_devices INTEGER NOT NULL DEFAULT 2",
            [],
        );

        let _ = conn.execute(
            "INSERT OR IGNORE INTO enterprise_accounts (
                company_id, company_name, master_account_email, plan_tier,
                total_allocated_tokens, account_status, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "comp_aegis_qro_01",
                "Corporativo Industrial Queretaro S.A. de C.V.",
                "seguridad@corporativo-qro.mx",
                "ENTERPRISE_ZERO_TRUST",
                10,
                "ACTIVE",
                Utc::now().to_rfc3339()
            ],
        );
    }

    pub fn authenticate_company_login(&self, email: &str, password_sha256: &str) -> Option<EnterpriseAccount> {
        let conn = self.connect();
        let cid: Option<String> = conn
            .query_row(
                "SELECT company_id FROM enterprise_accounts
                 WHERE LOWER(master_account_email) = LOWER(?1)
                   AND temp_password_sha256 = ?2
                   AND account_status = 'ACTIVE'",
                params![email.trim(), password_sha256],
                |r| r.get(0),
            )
            .ok();

        cid.map(|id| self.load_enterprise_account(&id))
    }

    pub fn count_company_non_revoked_tokens(&self, company_id: &str) -> u32 {
        let conn = self.connect();
        conn.query_row(
            "SELECT COUNT(*) FROM enterprise_client_tokens WHERE company_id = ?1",
            params![company_id],
            |r| r.get(0),
        )
        .unwrap_or(0)
    }

    pub fn delete_company_token(&self, company_id: &str, token_id: &str) -> bool {
        let conn = self.connect();
        conn.execute(
            "DELETE FROM enterprise_client_tokens WHERE company_id = ?1 AND token_id = ?2",
            params![company_id, token_id],
        )
        .map(|rows| rows > 0)
        .unwrap_or(false)
    }

    pub fn load_company_site_policy(&self, company_id: &str) -> CompanySitePolicy {
        let conn = self.connect();
        conn.query_row(
            "SELECT version, allowed_sites_json, blacklisted_sites_json
             FROM enterprise_site_policies WHERE company_id = ?1",
            params![company_id],
            |row| {
                let ver: u64 = row.get(0)?;
                let allow_str: String = row.get(1)?;
                let black_str: String = row.get(2)?;
                let allowed_sites: Vec<String> =
                    serde_json::from_str(&allow_str).unwrap_or_default();
                let blacklisted_sites: Vec<String> =
                    serde_json::from_str(&black_str).unwrap_or_default();
                Ok(CompanySitePolicy {
                    company_id: company_id.to_string(),
                    version: ver,
                    allowed_sites,
                    blacklisted_sites,
                })
            },
        )
        .unwrap_or_else(|_| CompanySitePolicy {
            company_id: company_id.to_string(),
            version: 1,
            allowed_sites: vec![
                "tools.empresa.mx".to_string(),
                "aegisqro.internal".to_string(),
                "sat.gob.mx".to_string(),
            ],
            blacklisted_sites: vec![
                "xn--sat-gob-mx-99a.com".to_string(),
                "recolector-externo.evil.org".to_string(),
            ],
        })
    }

    pub fn save_company_site_policy(
        &self,
        company_id: &str,
        allowed_sites: &[String],
        blacklisted_sites: &[String],
    ) -> CompanySitePolicy {
        let current = self.load_company_site_policy(company_id);
        let next_ver = current.version + 1;
        let allow_json = serde_json::to_string(allowed_sites).unwrap_or_else(|_| "[]".to_string());
        let black_json =
            serde_json::to_string(blacklisted_sites).unwrap_or_else(|_| "[]".to_string());
        let conn = self.connect();
        let _ = conn.execute(
            "INSERT INTO enterprise_site_policies (
                company_id, version, allowed_sites_json, blacklisted_sites_json, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(company_id) DO UPDATE SET
                version = excluded.version,
                allowed_sites_json = excluded.allowed_sites_json,
                blacklisted_sites_json = excluded.blacklisted_sites_json,
                updated_at = excluded.updated_at",
            params![
                company_id,
                next_ver,
                allow_json,
                black_json,
                Utc::now().to_rfc3339()
            ],
        );
        CompanySitePolicy {
            company_id: company_id.to_string(),
            version: next_ver,
            allowed_sites: allowed_sites.to_vec(),
            blacklisted_sites: blacklisted_sites.to_vec(),
        }
    }

    pub fn load_all_enterprise_accounts(&self) -> Vec<EnterpriseAccount> {
        let conn = self.connect();
        let mut stmt = match conn.prepare(
            "SELECT company_id FROM enterprise_accounts ORDER BY created_at DESC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let ids: Vec<String> = match stmt.query_map([], |r| r.get(0)) {
            Ok(rows) => rows.filter_map(Result::ok).collect(),
            Err(_) => return Vec::new(),
        };
        ids.into_iter()
            .map(|id| self.load_enterprise_account(&id))
            .collect()
    }

    pub fn load_enterprise_account(&self, company_id: &str) -> EnterpriseAccount {
        let conn = self.connect();
        let active_used: u32 = conn
            .query_row(
                "SELECT COUNT(*) FROM enterprise_client_tokens WHERE company_id = ?1 AND status = 'ACTIVE'",
                params![company_id],
                |r| r.get(0),
            )
            .unwrap_or(0);

        conn.query_row(
            "SELECT company_id, company_name, master_account_email, plan_tier,
                    total_allocated_tokens, account_status, created_at,
                    temp_password_sha256, temp_password_expires_at
             FROM enterprise_accounts WHERE company_id = ?1",
            params![company_id],
            |row| {
                let total: u32 = row.get(4)?;
                let avail = total.saturating_sub(active_used);
                let pw_hash: Option<String> = row.get(7).ok().flatten();
                let pw_exp: Option<String> = row.get(8).ok().flatten();
                Ok(EnterpriseAccount {
                    company_id: row.get(0)?,
                    company_name: row.get(1)?,
                    master_account_email: row.get(2)?,
                    plan_tier: row.get(3)?,
                    total_allocated_tokens: total,
                    active_tokens_used: active_used,
                    available_tokens: avail,
                    account_status: row.get(5)?,
                    has_temp_password: pw_hash.as_deref().map(|s| !s.is_empty()).unwrap_or(false),
                    temp_password_expires_at: pw_exp,
                    created_at: row.get(6)?,
                })
            },
        )
        .unwrap_or_else(|_| EnterpriseAccount {
            company_id: company_id.to_string(),
            company_name: "Corporativo Industrial Queretaro S.A. de C.V.".to_string(),
            master_account_email: "seguridad@corporativo-qro.mx".to_string(),
            plan_tier: "ENTERPRISE_ZERO_TRUST".to_string(),
            total_allocated_tokens: 10,
            active_tokens_used: active_used,
            available_tokens: 10u32.saturating_sub(active_used),
            account_status: "ACTIVE".to_string(),
            has_temp_password: false,
            temp_password_expires_at: None,
            created_at: Utc::now().to_rfc3339(),
        })
    }

    pub fn set_enterprise_account_status(&self, company_id: &str, status: &str) {
        let conn = self.connect();
        let _ = conn.execute(
            "UPDATE enterprise_accounts SET account_status = ?1 WHERE company_id = ?2",
            params![status, company_id],
        );
        if status == "DISABLED" {
            let _ = conn.execute(
                "UPDATE enterprise_client_tokens SET status = 'SUSPENDED' WHERE company_id = ?1 AND status != 'REVOKED'",
                params![company_id],
            );
        } else if status == "ACTIVE" {
            let _ = conn.execute(
                "UPDATE enterprise_client_tokens SET status = CASE WHEN assigned_device_id IS NOT NULL THEN 'ACTIVE' ELSE 'AVAILABLE' END WHERE company_id = ?1 AND status = 'SUSPENDED'",
                params![company_id],
            );
        }
    }

    pub fn delete_enterprise_account(&self, company_id: &str) {
        let conn = self.connect();
        let _ = conn.execute(
            "DELETE FROM enterprise_client_tokens WHERE company_id = ?1",
            params![company_id],
        );
        let _ = conn.execute(
            "DELETE FROM enterprise_accounts WHERE company_id = ?1",
            params![company_id],
        );
    }

    pub fn set_enterprise_temp_password(
        &self,
        company_id: &str,
        password_sha256: &str,
        expires_at: &str,
    ) {
        let conn = self.connect();
        let _ = conn.execute(
            "UPDATE enterprise_accounts
             SET temp_password_sha256 = ?1, temp_password_expires_at = ?2
             WHERE company_id = ?3",
            params![password_sha256, expires_at, company_id],
        );
    }

    pub fn verify_enterprise_credentials(
        &self,
        email_or_name: &str,
        plain_password: &str,
    ) -> Option<EnterpriseAccount> {
        let conn = self.connect();
        let expected_sha = sha256_hex(plain_password.trim());
        let company_id: String = conn
            .query_row(
                "SELECT company_id FROM enterprise_accounts
                 WHERE (LOWER(master_account_email) = LOWER(?1)
                        OR LOWER(company_name) = LOWER(?1)
                        OR company_id = ?1)
                   AND temp_password_sha256 = ?2
                   AND account_status = 'ACTIVE'
                 LIMIT 1",
                params![email_or_name.trim(), expected_sha],
                |r| r.get(0),
            )
            .ok()?;

        Some(self.load_enterprise_account(&company_id))
    }

    pub fn find_enterprise_token_by_id(&self, token_id: &str) -> Option<EnterpriseClientToken> {
        let conn = self.connect();
        conn.query_row(
            "SELECT token_id, company_id, token_sha256, assigned_device_id,
                    assigned_employee_id, client_label, platform, status,
                    activated_at, last_used_at, secondary_device_id, max_devices
             FROM enterprise_client_tokens
             WHERE token_id = ?1",
            params![token_id.trim()],
            |row| {
                let d1: Option<String> = row.get(3)?;
                let d2: Option<String> = row.get(10).ok().flatten();
                let max_dev: u32 = row.get(11).unwrap_or(2);
                let used = u32::from(d1.is_some()) + u32::from(d2.is_some());
                Ok(EnterpriseClientToken {
                    token_id: row.get(0)?,
                    company_id: row.get(1)?,
                    token_sha256: row.get(2)?,
                    assigned_device_id: d1,
                    secondary_device_id: d2,
                    assigned_employee_id: row.get(4)?,
                    max_devices: max_dev,
                    used_devices_count: used,
                    client_label: row.get(5)?,
                    platform: row.get(6)?,
                    status: row.get(7)?,
                    activated_at: row.get(8)?,
                    last_used_at: row.get(9)?,
                })
            },
        )
        .ok()
    }

    pub fn bind_device_to_specific_token(
        &self,
        token_id: &str,
        device_id: &str,
        employee_id: Option<&str>,
        client_label: Option<&str>,
        platform: &str,
    ) -> Result<EnterpriseClientToken, String> {
        let Some(tok) = self.find_enterprise_token_by_id(token_id) else {
            return Err("Token no encontrado en el servidor".to_string());
        };
        if tok.status == "REVOKED" || tok.status == "SUSPENDED" {
            return Err("Este token fue revocado o suspendido".to_string());
        }

        let conn = self.connect();
        let now = Utc::now().to_rfc3339();
        let clean_emp = employee_id
            .map(str::trim)
            .filter(|s| !s.is_empty() && *s != "General");
        let next_emp = match tok.assigned_employee_id.as_deref() {
            Some(existing) if !existing.is_empty() && existing != "General" => Some(existing.to_string()),
            _ => clean_emp.map(str::to_string).or(tok.assigned_employee_id.clone()),
        };

        if tok.assigned_device_id.as_deref() == Some(device_id)
            || tok.secondary_device_id.as_deref() == Some(device_id)
        {
            let _ = conn.execute(
                "UPDATE enterprise_client_tokens
                 SET status = 'ACTIVE', last_used_at = ?1,
                     assigned_employee_id = COALESCE(?2, assigned_employee_id)
                 WHERE token_id = ?3",
                params![now, next_emp, tok.token_id],
            );
            return Ok(self.find_enterprise_token_by_id(&tok.token_id).unwrap_or(tok));
        }

        if tok.assigned_device_id.is_none() {
            let next_plat = if tok.platform == "UNASSIGNED" || tok.platform.is_empty() {
                platform.to_string()
            } else if tok.platform == platform {
                tok.platform.clone()
            } else {
                format!("{} + {}", tok.platform, platform)
            };
            let next_label = client_label
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(&tok.client_label);
            let _ = conn.execute(
                "UPDATE enterprise_client_tokens
                 SET assigned_device_id = ?1,
                     assigned_employee_id = ?2,
                     client_label = ?3,
                     platform = ?4,
                     status = 'ACTIVE',
                     last_used_at = ?5
                 WHERE token_id = ?6",
                params![device_id, next_emp, next_label, next_plat, now, tok.token_id],
            );
            return Ok(self.find_enterprise_token_by_id(&tok.token_id).unwrap_or(tok));
        }

        if tok.secondary_device_id.is_none() {
            let next_plat = if tok.platform == "UNASSIGNED" || tok.platform.is_empty() {
                platform.to_string()
            } else if tok.platform == platform || tok.platform.contains(platform) {
                tok.platform.clone()
            } else {
                format!("{} + {}", tok.platform, platform)
            };
            let _ = conn.execute(
                "UPDATE enterprise_client_tokens
                 SET secondary_device_id = ?1,
                     assigned_employee_id = COALESCE(?2, assigned_employee_id),
                     platform = ?3,
                     status = 'ACTIVE',
                     last_used_at = ?4
                 WHERE token_id = ?5",
                params![device_id, next_emp, next_plat, now, tok.token_id],
            );
            return Ok(self.find_enterprise_token_by_id(&tok.token_id).unwrap_or(tok));
        }

        Err(format!(
            "Este token ya tiene sus {} dispositivos ocupados ({} y {})",
            tok.max_devices,
            tok.assigned_device_id.as_deref().unwrap_or("-"),
            tok.secondary_device_id.as_deref().unwrap_or("-")
        ))
    }

    pub fn activate_available_company_token(
        &self,
        company_id: &str,
        employee_id: &str,
        client_label: &str,
        platform: &str,
        device_id: Option<&str>,
    ) -> Option<EnterpriseClientToken> {
        if let Some(dev_id) = device_id {
            if let Some(existing) = self.find_token_by_device(company_id, dev_id) {
                self.touch_device_token(company_id, dev_id);
                return Some(existing);
            }
        }

        let conn = self.connect();
        let candidate_id: Option<String> = conn
            .query_row(
                "SELECT token_id FROM enterprise_client_tokens
                 WHERE company_id = ?1
                   AND status IN ('AVAILABLE', 'ACTIVE')
                   AND (assigned_device_id IS NULL OR secondary_device_id IS NULL)
                 ORDER BY CASE WHEN status = 'AVAILABLE' THEN 0 ELSE 1 END, activated_at ASC
                 LIMIT 1",
                params![company_id],
                |r| r.get(0),
            )
            .ok();

        if let Some(tid) = candidate_id {
            if let Some(dev_id) = device_id {
                if let Ok(bound) = self.bind_device_to_specific_token(
                    &tid,
                    dev_id,
                    Some(employee_id),
                    Some(client_label),
                    platform,
                ) {
                    return Some(bound);
                }
            } else {
                let now = Utc::now().to_rfc3339();
                let _ = conn.execute(
                    "UPDATE enterprise_client_tokens
                     SET status = 'ACTIVE',
                         assigned_employee_id = COALESCE(assigned_employee_id, ?1),
                         client_label = ?2,
                         platform = ?3,
                         last_used_at = ?4
                     WHERE token_id = ?5",
                    params![employee_id, client_label, platform, now, tid],
                );
                return self.find_enterprise_token_by_id(&tid);
            }
        }

        self.load_enterprise_tokens(company_id)
            .into_iter()
            .find(|t| t.status == "ACTIVE")
    }

    pub fn upsert_enterprise_account(
        &self,
        company_id: &str,
        company_name: &str,
        master_email: &str,
        total_tokens: u32,
    ) {
        let conn = self.connect();
        let _ = conn.execute(
            "INSERT INTO enterprise_accounts (
                company_id, company_name, master_account_email, plan_tier,
                total_allocated_tokens, account_status, created_at
            ) VALUES (?1, ?2, ?3, 'ENTERPRISE_ZERO_TRUST', ?4, 'ACTIVE', ?5)
            ON CONFLICT(company_id) DO UPDATE SET
                company_name = excluded.company_name,
                master_account_email = excluded.master_account_email,
                total_allocated_tokens = excluded.total_allocated_tokens",
            params![
                company_id,
                company_name,
                master_email,
                total_tokens,
                Utc::now().to_rfc3339()
            ],
        );
    }

    pub fn find_token_by_device(
        &self,
        company_id: &str,
        device_id: &str,
    ) -> Option<EnterpriseClientToken> {
        let conn = self.connect();
        conn.query_row(
            "SELECT token_id, company_id, token_sha256, assigned_device_id,
                    assigned_employee_id, client_label, platform, status,
                    activated_at, last_used_at, secondary_device_id, max_devices
             FROM enterprise_client_tokens
             WHERE company_id = ?1
               AND (assigned_device_id = ?2 OR secondary_device_id = ?2)
               AND status = 'ACTIVE'",
            params![company_id, device_id],
            |row| {
                let d1: Option<String> = row.get(3)?;
                let d2: Option<String> = row.get(10).ok().flatten();
                let max_dev: u32 = row.get(11).unwrap_or(2);
                let used = u32::from(d1.is_some()) + u32::from(d2.is_some());
                Ok(EnterpriseClientToken {
                    token_id: row.get(0)?,
                    company_id: row.get(1)?,
                    token_sha256: row.get(2)?,
                    assigned_device_id: d1,
                    secondary_device_id: d2,
                    assigned_employee_id: row.get(4)?,
                    max_devices: max_dev,
                    used_devices_count: used,
                    client_label: row.get(5)?,
                    platform: row.get(6)?,
                    status: row.get(7)?,
                    activated_at: row.get(8)?,
                    last_used_at: row.get(9)?,
                })
            },
        )
        .ok()
    }

    pub fn bind_device_to_existing_user_token(
        &self,
        company_id: &str,
        employee_id: &str,
        device_id: &str,
        platform: &str,
    ) -> bool {
        let conn = self.connect();
        let candidate: Option<(String, Option<String>, Option<String>, String)> = conn
            .query_row(
                "SELECT token_id, assigned_device_id, secondary_device_id, platform
                 FROM enterprise_client_tokens
                 WHERE company_id = ?1
                   AND (assigned_employee_id = ?2 OR assigned_employee_id IS NULL)
                   AND status IN ('ACTIVE', 'AVAILABLE')
                   AND (assigned_device_id IS NULL OR secondary_device_id IS NULL)
                 ORDER BY CASE WHEN assigned_employee_id = ?2 THEN 0 ELSE 1 END, activated_at ASC
                 LIMIT 1",
                params![company_id, employee_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .ok();

        let Some((tok_id, d1, d2, old_plat)) = candidate else {
            return false;
        };

        let now = Utc::now().to_rfc3339();
        if d1.is_none() {
            let _ = conn.execute(
                "UPDATE enterprise_client_tokens
                 SET assigned_device_id = ?1, assigned_employee_id = ?2,
                     platform = ?3, status = 'ACTIVE', last_used_at = ?4
                 WHERE token_id = ?5",
                params![device_id, employee_id, platform, now, tok_id],
            );
            return true;
        }

        if d1.as_deref() != Some(device_id) && d2.is_none() {
            let combined_plat = if old_plat == "UNASSIGNED" || old_plat == platform {
                platform.to_string()
            } else {
                format!("{} + {}", old_plat, platform)
            };
            let _ = conn.execute(
                "UPDATE enterprise_client_tokens
                 SET secondary_device_id = ?1, assigned_employee_id = ?2,
                     platform = ?3, status = 'ACTIVE', last_used_at = ?4
                 WHERE token_id = ?5",
                params![device_id, employee_id, combined_plat, now, tok_id],
            );
            return true;
        }

        false
    }

    pub fn touch_device_token(&self, company_id: &str, device_id: &str) {
        let conn = self.connect();
        let _ = conn.execute(
            "UPDATE enterprise_client_tokens
             SET last_used_at = ?1
             WHERE company_id = ?2 AND (assigned_device_id = ?3 OR secondary_device_id = ?3)",
            params![Utc::now().to_rfc3339(), company_id, device_id],
        );
    }

    pub fn insert_enterprise_token(&self, tok: &EnterpriseClientToken) {
        let conn = self.connect();
        let _ = conn.execute(
            "INSERT INTO enterprise_client_tokens (
                token_id, company_id, token_sha256, assigned_device_id,
                assigned_employee_id, client_label, platform, status,
                activated_at, last_used_at, secondary_device_id, max_devices
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            ON CONFLICT(token_id) DO UPDATE SET
                last_used_at = excluded.last_used_at,
                status = excluded.status,
                assigned_employee_id = COALESCE(excluded.assigned_employee_id, enterprise_client_tokens.assigned_employee_id)",
            params![
                tok.token_id,
                tok.company_id,
                tok.token_sha256,
                tok.assigned_device_id,
                tok.assigned_employee_id,
                tok.client_label,
                tok.platform,
                tok.status,
                tok.activated_at,
                tok.last_used_at,
                tok.secondary_device_id,
                tok.max_devices,
            ],
        );
    }

    pub fn revoke_enterprise_token(&self, token_id: &str) {
        let conn = self.connect();
        let _ = conn.execute(
            "UPDATE enterprise_client_tokens SET status = 'REVOKED' WHERE token_id = ?1",
            params![token_id],
        );
    }

    pub fn load_enterprise_tokens(&self, company_id: &str) -> Vec<EnterpriseClientToken> {
        let conn = self.connect();
        let mut stmt = match conn.prepare(
            "SELECT token_id, company_id, token_sha256, assigned_device_id,
                    assigned_employee_id, client_label, platform, status,
                    activated_at, last_used_at, secondary_device_id, max_devices
             FROM enterprise_client_tokens
             WHERE company_id = ?1
             ORDER BY activated_at DESC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let iter = stmt.query_map(params![company_id], |row| {
            let d1: Option<String> = row.get(3)?;
            let d2: Option<String> = row.get(10).ok().flatten();
            let max_dev: u32 = row.get(11).unwrap_or(2);
            let used = u32::from(d1.is_some()) + u32::from(d2.is_some());
            Ok(EnterpriseClientToken {
                token_id: row.get(0)?,
                company_id: row.get(1)?,
                token_sha256: row.get(2)?,
                assigned_device_id: d1,
                secondary_device_id: d2,
                assigned_employee_id: row.get(4)?,
                max_devices: max_dev,
                used_devices_count: used,
                client_label: row.get(5)?,
                platform: row.get(6)?,
                status: row.get(7)?,
                activated_at: row.get(8)?,
                last_used_at: row.get(9)?,
            })
        });

        match iter {
            Ok(rows) => rows.filter_map(Result::ok).collect(),
            Err(_) => Vec::new(),
        }
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
