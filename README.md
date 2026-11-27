# xotla-server — AegisQRO Core Backend (Rust)

Servidor central Zero-Trust, administrador de políticas de TI y motor de perfilado de comportamiento (UEBA) en tiempo real para **AegisQRO** (Hackathon Ciberseguridad BLOQUE Querétaro). Construido 100% en **Rust** con `Axum`, `Tokio`, `WebSockets` y `DashMap`.

---

## Servidor en Vivo (AWS EC2 Production)

- **Base URL REST:** `http://54.146.211.248:8080`
- **Base URL v1:** `http://54.146.211.248:8080/v1`
- **WebSocket Stream:** `ws://54.146.211.248:8080/v1/ws`
- **Laboratorio Interactivo de Phishing (Demo):** `http://54.146.211.248:8080/demo-phishing`
- **Servicio Systemd en AWS:** `xotla-server.service` (auto-restart activo en puerto `8080`)

### Enlaces Rápidos en Vivo
| Recurso | URL Pública Activa |
| :--- | :--- |
| **Índice de Endpoints** | `http://54.146.211.248:8080/` |
| **Health Check (`HEAD`/`GET`)** | `http://54.146.211.248:8080/v1/health` |
| **Política TI (Extensión Chrome)** | `http://54.146.211.248:8080/v1/policy` |
| **Laboratorio de 5 Ataques (Demo)** | `http://54.146.211.248:8080/demo-phishing` |
| **Handshake Zero-Touch (`POST`)** | `http://54.146.211.248:8080/v1/devices/handshake` |
| **Fallback Registro (`POST`)** | `http://54.146.211.248:8080/v1/devices/register` |
| **Dispositivos Registrados (`GET`)** | `http://54.146.211.248:8080/v1/devices` |
| **Lote Offline SQLite (`POST`)** | `http://54.146.211.248:8080/v1/telemetry/batch` |
| **Telemetría Extensión Web (`POST`)** | `http://54.146.211.248:8080/v1/telemetry/browser` |
| **Reporte Windows Sandbox (`POST`)** | `http://54.146.211.248:8080/v1/sandbox/windows` |
| **Reporte Android Sandbox (`POST`)** | `http://54.146.211.248:8080/v1/sandbox/android` |
| **Feed de Eventos (`GET`)** | `http://54.146.211.248:8080/v1/events` |
| **Perfil de Riesgo UEBA (`GET`)** | `http://54.146.211.248:8080/v1/ueba/profile/emp_042` |
| **WebSocket Tiempo Real (`WS`)** | `ws://54.146.211.248:8080/v1/ws` |

---

## Arquitectura Modular del Proyecto

```text
xotla-server/
├── Cargo.toml
├── docs/
│   ├── ADMIN_POLICY_CONTRACT.md     # Contrato de política TI y panel Admin (Berny)
│   └── API_CONTRACT_XOTLA.md        # Contrato de sincronización offline-first (Agente / Rafa)
└── src/
    ├── main.rs                      # Router HTTP REST + WebSockets en 0.0.0.0:8080
    ├── config.rs                    # Variables de entorno (HOST, PORT, PUBLIC_WS_BASE, credenciales Admin)
    ├── state.rs                     # Estado concurrente en memoria y canal broadcast WS
    └── modules/
        ├── devices/                 # Registro e identificación física Zero-Touch (Handshake)
        ├── policy/                  # Política dinámica de TI, login Admin, CSRF, auditoría y /demo-phishing
        ├── telemetry/               # Recepción REST individual y por lotes (Browser, Windows, Android, Batch)
        ├── ws/                      # Sesiones en tiempo real para Agentes y Dashboard SOC
        └── ueba/                    # Motor de cálculo de riesgo y anomalías por empleado
```

---

## 1. Handshake y Auto-Registro de Dispositivos (Zero-Touch)

Soporta tanto el esquema de los agentes de escritorio/extensión (`hardware_id`) como el agente móvil offline-first (`hardware_uid`).

### `POST /v1/devices/handshake` *(Alias: `POST /v1/devices/register`)*

**Request (Formato Agente Móvil / Endpoint):**
```json
{
  "hardware_uid": "0e280d928b8a68e275ca4c270497214a15c0d529b92b868e96c1c156ecf243d6",
  "platform": "android",
  "os_version": "Android 14 (API 34)",
  "device_model": "Pixel 7 / Corporativo",
  "agent_version": "0.1.0-hackathon"
}
```

**Request (Formato Agente Desktop / Extensión):**
```json
{
  "hardware_id": "MAC-AA-BB-CC-11-22",
  "employee_id": "emp_042",
  "department": "Contabilidad",
  "agent_kind": "WINDOWS_OS",
  "hostname": "win-qro-01"
}
```

**Response (`200 OK`):**
```json
{
  "status": "ENROLLED_NEW",
  "is_new_device": true,
  "device_id": "dev_qro_0e280d92",
  "internal_device_id": "dev_qro_0e280d92",
  "employee_id": "emp_042",
  "assigned_profile": "standard_employee",
  "current_risk_score": 0.1,
  "sync_interval_sec": 30,
  "session_token": "xotla_tok_a4075590cff9489bbb8fa81771085a9c",
  "approved": true,
  "ws_url": "ws://54.146.211.248:8080/v1/ws?token=xotla_tok_a4075590cff9489bbb8fa81771085a9c"
}
```
> Si el dispositivo ya fue registrado previamente, devuelve `"status": "ENROLLED_EXISTING"` y conserva su `device_id` y `session_token`.

---

## 2. Política Administrada por TI (Extensión de Navegador & Panel Admin)

### `GET /v1/policy` *(Alias: `GET /policy`)*
Consumido por la extensión de Chrome al arrancar y cada 15 minutos (`Header: X-API-Key: aegis-qro-team-token-2026`).
```json
{
  "version": 1,
  "trusted_download_hosts": ["tools.empresa.mx", "aegisqro.internal"],
  "protected_domains": ["apple-support.com", "sat.gob.mx", "bbva.mx", "banorte.com", "aegisqro.internal"],
  "dangerous_extensions": [".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".wsf", ".js", ".jse", ".hta", ".scr", ".pif", ".reg", ".iso", ".img", ".vhd", ".lnk", ".jar", ".zip"]
}
```

### Administración de Política (`/admin/*`)
- **`POST /admin/login`**: Recibe `{"usuario": "admin", "password": "..."}` y emite cookie `aegis_admin_session` (`HttpOnly; SameSite=Strict`) + `csrf_token`.
- **`POST /admin/logout`**: Invalida la sesión activa.
- **`GET /admin/policy`**: Devuelve la política actual y la bitácora de auditoría (`audit_log`).
- **`PUT /admin/policy`**: Actualiza `trusted_download_hosts`, `protected_domains` y/o `dangerous_extensions`, valida formatos e incrementa automáticamente `version`.

---

## 3. Ingestión de Telemetría (Tiempo Real y Lotes Offline)

### A. Sincronización por Lotes SQLite (`POST /v1/telemetry/batch`)
```json
{
  "hardware_uid": "0e280d928b8a68e275ca4c270497214a15c0d529b92b868e96c1c156ecf243d6",
  "internal_device_id": "dev_qro_0e280d92",
  "batch_timestamp": "2026-11-27T18:15:00Z",
  "events": [
    {
      "event_id": "evt_test_001",
      "occurred_at": "2026-11-27T18:00:00Z",
      "was_offline": true,
      "category": "APK_INSPECTION",
      "artifact_sha256": "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
      "local_verdict": "BLOCKED",
      "local_risk_score": 0.89,
      "details": { "package_name": "com.sat.actualizacion.fiscal" }
    }
  ]
}
```
**Response:**
```json
{
  "status": "PROCESSED",
  "processed_count": 1
}
```

### B. Evento de Extensión Web (`POST /v1/telemetry/browser`)
```json
{
  "employee_id": "emp_042",
  "device_id": "win_qro_01",
  "timestamp": "2026-11-27T14:32:00Z",
  "event_type": "HOMOGRAPH_BLOCKED",
  "details": {
    "original_url": "https://аpple-support.com/login",
    "punycode_url": "https://xn--pple-support-97a.com/login",
    "detected_script": "Cyrillic",
    "similarity_score": 0.94,
    "action_taken": "BLOCKED"
  }
}
```

### C. Reporte Windows Sandbox (`POST /v1/sandbox/windows`)
```json
{
  "employee_id": "emp_042",
  "device_id": "win_qro_01",
  "timestamp": "2026-11-27T14:35:10Z",
  "file_info": {
    "filename": "factura_noviembre.exe",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "size_bytes": 245760
  },
  "sandbox_telemetry": {
    "execution_time_ms": 15000,
    "spawned_processes": ["cmd.exe", "powershell.exe -enc ..."],
    "modified_registry_keys": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
    "network_attempts": ["185.220.101.4:443"],
    "files_created": ["C:\\Users\\WDAGUtilityAccount\\AppData\\Local\\Temp\\payload.dll"]
  },
  "verdict": "MALICIOUS",
  "threat_score": 0.91
}
```

### D. Reporte Android Sandbox (`POST /v1/sandbox/android`)
```json
{
  "employee_id": "emp_042",
  "device_id": "and_qro_01",
  "timestamp": "2026-11-27T14:40:00Z",
  "apk_info": {
    "package_name": "com.sat.actualizacion.fiscal",
    "sha256": "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
    "requested_permissions": [
      "android.permission.READ_SMS",
      "android.permission.BIND_ACCESSIBILITY_SERVICE",
      "android.permission.SYSTEM_ALERT_WINDOW"
    ],
    "suspicious_urls_in_dex": ["http://192.99.45.12/gate.php"]
  },
  "verdict": "HIGH_RISK",
  "threat_score": 0.87
}
```

---

## 4. Dashboard SOC y WebSockets en Tiempo Real

- **`GET /v1/ueba/profile/{employee_id}`**: Devuelve el score de riesgo consolidado (`baseline_risk`, `current_risk_score`, `risk_level`, `anomalies_detected`, `recommended_action`).
- **`GET /v1/events`**: Historial completo de eventos recibidos.
- **`GET /v1/devices`**: Lista de dispositivos registrados y estado `online`.
- **`WS /v1/ws?role=DASHBOARD`**: Canal en vivo que recibe `DEVICE_HANDSHAKE` y `UEBA_EVENT_UPDATE` automáticamente cada vez que entra telemetría.

---

## Administración del Servicio en AWS (`hackbloque`)

```bash
# Ver estado y logs en vivo en AWS
ssh hackbloque "sudo systemctl status xotla-server"
ssh hackbloque "sudo journalctl -u xotla-server -f"

# Reiniciar el servicio
ssh hackbloque "sudo systemctl restart xotla-server"
```
