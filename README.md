# xotla-server — AegisQRO Core Backend (Rust)

Servidor central Zero-Trust y motor de perfilado de comportamiento (UEBA) en tiempo real para **AegisQRO** (Hackathon Ciberseguridad BLOQUE Querétaro). Construido en **Rust** con `Axum`, `Tokio`, `WebSockets` y `DashMap`.

---

## Arquitectura del Proyecto

```text
xotla-server/
├── Cargo.toml
└── src/
    ├── main.rs                      # Punto de entrada HTTP REST + WebSockets (0.0.0.0:8080)
    ├── config.rs                    # Variables de entorno (HOST, PORT, PUBLIC_WS_BASE)
    ├── state.rs                     # Estado concurrente en memoria y canal broadcast WS
    └── modules/
        ├── devices/                 # Registro e identificación física de dispositivos (Handshake)
        ├── telemetry/               # Recepción REST de telemetría (Browser, Windows, Android)
        ├── ws/                      # Sesiones en tiempo real para Agentes y Dashboard SOC
        └── ueba/                    # Motor de cálculo de riesgo y anomalías por empleado
```

---

## URL Base en AWS

- **REST API:** `http://54.146.211.248:8080`
- **WebSocket:** `ws://54.146.211.248:8080/v1/ws`

---

## Flujo de Conexión de Dispositivos y Agentes

1. **Handshake Inicial (`POST /v1/devices/handshake`)**:
   - Cuando un dispositivo (Extensión Web, Agente Windows o Agente Android) enciende o inicia, envía su identificador físico (`hardware_id`).
   - Si el dispositivo es **desconocido**, el servidor lo registra, genera un `device_id` único (`dev_...`) y le asigna un `session_token` (`xotla_tok_...`).
   - Si el dispositivo ya es **conocido**, el servidor lo reconoce y devuelve su `device_id` y `session_token` existentes.
2. **Autenticación en Peticiones Posteriores**:
   - Los agentes envían el header `X-Session-Token: <session_token>` (o `X-API-Key`) en sus peticiones REST, o se conectan por WebSocket a `ws://54.146.211.248:8080/v1/ws?token=<session_token>`.
3. **Perfilado UEBA en Tiempo Real**:
   - Cada evento recibido actualiza el perfil de riesgo del empleado (`current_risk_score`, `risk_level`, `anomalies_detected`, `recommended_action`) y emite un evento en vivo por WebSocket hacia el Dashboard Web SOC.

---

## Documentación de Endpoints (API REST & WebSockets)

### 1. Handshake y Registro de Dispositivos

#### `POST /v1/devices/handshake`

**Request:**
```json
{
  "hardware_id": "MAC-AA-BB-CC-11-22",
  "employee_id": "emp_042",
  "department": "Contabilidad",
  "agent_kind": "WINDOWS_OS",
  "hostname": "win-qro-01"
}
```
> Valores válidos para `agent_kind`: `"BROWSER_EXT"`, `"WINDOWS_OS"`, `"ANDROID_AGENT"`.

**Response:**
```json
{
  "status": "NEW_DEVICE_REGISTERED",
  "is_new_device": true,
  "device_id": "dev_8f91a2c4b012",
  "employee_id": "emp_042",
  "session_token": "xotla_tok_4c9f8e1a2b3c4d5e6f7a8b9c0d1e2f3a",
  "approved": true,
  "ws_url": "ws://54.146.211.248:8080/v1/ws?token=xotla_tok_4c9f8e1a2b3c4d5e6f7a8b9c0d1e2f3a"
}
```

#### `GET /v1/devices`
Lista todos los dispositivos registrados, su estado `online` (`true`/`false`), `device_id`, `employee_id` y `last_seen`.

---

### 2. Telemetría de Agentes (Berny & Rafa)

> Header recomendado en todas las peticiones: `X-Session-Token: <session_token>`

#### A. Extensión de Navegador (`POST /v1/telemetry/browser`)
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

#### B. Agente Windows Sandbox (`POST /v1/sandbox/windows`)
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

#### C. Analizador Android Sandbox (`POST /v1/sandbox/android`)
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

### 3. Endpoints para la Aplicación Web / Dashboard SOC (Pap)

#### `GET /v1/ueba/profile/{employee_id}`
Obtiene el perfil de riesgo calculado en tiempo real para un empleado (ej. `/v1/ueba/profile/emp_042`):
```json
{
  "employee_id": "emp_042",
  "department": "Contabilidad",
  "baseline_risk": 0.12,
  "current_risk_score": 0.88,
  "risk_level": "CRITICAL",
  "anomalies_detected": [
    "Intento de acceso a dominio con caracteres Cyrillic (https://аpple-support.com/login)",
    "Ejecucion de PowerShell por factura_noviembre.exe fuera del perfil del departamento de Contabilidad",
    "Descarga de APK (com.sat.actualizacion.fiscal) con permisos de alto riesgo: android.permission.READ_SMS, android.permission.BIND_ACCESSIBILITY_SERVICE, android.permission.SYSTEM_ALERT_WINDOW"
  ],
  "recommended_action": "ISOLATE_HOST_AND_REVOKE_SESSION",
  "total_events": 3,
  "updated_at": "2026-11-27T14:40:01Z"
}
```

#### `GET /v1/events`
Devuelve la lista cronológica de todos los eventos recibidos y su impacto en el score de riesgo.

#### `WS /v1/ws` (Canal WebSocket en Tiempo Real)
- **Para el Dashboard Web:** Conectar a `ws://54.146.211.248:8080/v1/ws?role=DASHBOARD` para recibir automáticamente eventos `DEVICE_HANDSHAKE` y `UEBA_EVENT_UPDATE` en vivo.
- **Para Agentes:** Conectar a `ws://54.146.211.248:8080/v1/ws?token=<session_token>` para mantener estado `online: true` y enviar telemetría en tiempo real:
```json
{
  "source": "WINDOWS_OS",
  "event_type": "PROCESS_ANOMALY",
  "threat_score": 0.75,
  "anomaly": "Proceso sospechoso detectado en memoria",
  "payload": { "pid": 4120, "cmd": "powershell.exe -nop -w hidden" }
}
```

---

## Ejecución Local y en Servidor

```bash
cargo run --release
```

Variables de entorno opcionales:
- `HOST` (default: `0.0.0.0`)
- `PORT` (default: `8080`)
- `PUBLIC_WS_BASE` (default: `ws://54.146.211.248:8080`)
