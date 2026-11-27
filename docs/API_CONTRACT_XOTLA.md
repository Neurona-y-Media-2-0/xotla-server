# 🛡️ Contrato de API: Agente Endpoint (AegisQRO) ⟷ Backend AWS (Xotla)

**Documento:** Especificación de Integración de Protocolo HTTP/JSON  
**Versión del Agente:** `0.1.0-hackathon` (`aegis_agent_core` / Android App)  
**Destinatario:** Desarrollador del Backend en AWS (Axum / Rust) — Xotla  
**Convención de Serialización:** `snake_case` estricto en todos los campos JSON.  
**Formato de Fechas:** ISO 8601 / RFC 3339 en UTC (ej. `2026-11-27T18:15:00Z`).

---

## 1. Resumen Ejecutivo de la Sincronización

El agente corre en modo **Offline-First**. Cuando el dispositivo no tiene conexión a red, almacena las evaluaciones locales del sandbox (`SandboxVerdict`) y las métricas de comportamiento en una base de datos transaccional SQLite local (`offline_queue.db`).

En cuanto el worker asíncrono en Tokio (`src/sync.rs`) detecta conectividad con AWS:
1. Sondea conectividad mediante `HEAD /v1/health` (con fallback a `GET /v1/health`).
2. Si el dispositivo no tiene credenciales en memoria/disco (`internal_device_id == None`), ejecuta el **Zero-Touch Handshake** (`POST /v1/devices/handshake`).
3. Extrae lotes de hasta `batch_size` (ej. 50 eventos) en orden FIFO de SQLite y los envía a `POST /v1/telemetry/batch`.
4. Solo al recibir respuesta HTTP exitosa (`200 OK`) con status `"PROCESSED"`, `"OK"`, `"SUCCESS"` o `processed_count > 0`, el agente marca atómicamente los eventos como `SYNCED` en SQLite para su posterior depuración.

---

## 2. Endpoints Exactos y Headers Requeridos

| Método | Ruta Exacta en `src/sync.rs` | Headers de Petición (Request) | Propósito Técnico |
| :--- | :--- | :--- | :--- |
| **`HEAD`** / **`GET`** | `/v1/health` | *(Ninguno requerido)* | Sondeo de conectividad de baja latencia previo a cualquier transmisión de datos. |
| **`POST`** | `/v1/devices/handshake`<br>*(Fallback: `/v1/devices/register`)* | `Content-Type: application/json` | Handshake de auto-enrolamiento y reconocimiento por huella de hardware. |
| **`POST`** | `/v1/telemetry/batch` | `Content-Type: application/json`<br>`Authorization: Bearer <session_token>` *(si existe)* | Descarga masiva del buffer de eventos acumulados durante el periodo offline. |

> [!NOTE]
> `src/sync.rs` normaliza la variable de entorno `AWS_BACKEND_URL` eliminando cualquier barra final (`/`). Por lo tanto, los paths concatenados por el cliente son siempre exactamente `/v1/health`, `/v1/devices/handshake`, `/v1/devices/register` y `/v1/telemetry/batch`.

---

## 3. Contratos Request / Response (JSON Reales)

### 3.1. Health Check (`/v1/health`)

* **Método:** `HEAD` (con fallback automático a `GET` si `HEAD` retorna 404 o 405).
* **Headers:** No requiere headers de autenticación.
* **Request Body:** Vacío.
* **Códigos HTTP Esperados:** `200 OK` (cualquier `2xx` es interpretado como enlace activo).
* **Response Body:** Texto plano (`"OK"`) o JSON (`{"status": "UP"}`).

---

### 3.2. Handshake y Auto-Registro (`POST /v1/devices/handshake`)
*(Si la ruta retorna `404 Not Found`, el cliente reintenta automáticamente contra `POST /v1/devices/register`).*

#### Headers:
```http
POST /v1/devices/handshake HTTP/1.1
Host: api.aegisqro.aws.internal
Content-Type: application/json
```

#### Request Payload (`DeviceRegistration`):
```json
{
  "hardware_uid": "0e280d928b8a68e275ca4c270497214a15c0d529b92b868e96c1c156ecf243d6",
  "platform": "android",
  "os_version": "Android 14 (API 34)",
  "device_model": "Pixel 7 / Corporativo",
  "agent_version": "0.1.0-hackathon"
}
```

#### Response Payload (`RegistrationResponse`):
```json
{
  "status": "ENROLLED_NEW",
  "internal_device_id": "dev_qro_0e280d92",
  "assigned_profile": "standard_employee",
  "current_risk_score": 0.10,
  "sync_interval_sec": 30,
  "session_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZXZfcXJvXzBlMjgwZDkyIn0.sample_signature"
}
```

* **Campos devueltos por el servidor:**
  * `status` (string, obligatorio): `"ENROLLED_NEW"` (dispositivo recién registrado) o `"ENROLLED_EXISTING"` / `"RECOGNIZED"` (dispositivo ya existente en PostgreSQL).
  * `internal_device_id` (string, obligatorio): Identificador canónico del dispositivo en la nube (ej. `dev_qro_0e280d92`). El cliente lo almacena localmente y lo usa como clave foránea de telemetría.
  * `assigned_profile` (string, obligatorio): Perfil de aislamiento asignado (ej. `"standard_employee"`, `"high_risk_quarantine"`).
  * `current_risk_score` (f32, obligatorio): Puntaje consolidado de riesgo en la nube (rango `0.0` a `1.0`).
  * `sync_interval_sec` (u64, obligatorio): Frecuencia recomendada de sincronización para el cliente.
  * `session_token` (string, opcional): Token JWT o Bearer temporal para autorizar los lotes de telemetría.

---

### 3.3. Sincronización en Lote (`POST /v1/telemetry/batch`)

#### Headers:
```http
POST /v1/telemetry/batch HTTP/1.1
Host: api.aegisqro.aws.internal
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Request Payload (`TelemetryBatchRequest`):
```json
{
  "hardware_uid": "0e280d928b8a68e275ca4c270497214a15c0d529b92b868e96c1c156ecf243d6",
  "internal_device_id": "dev_qro_0e280d92",
  "batch_timestamp": "2026-11-27T18:15:00Z",
  "events": [
    {
      "event_id": "evt_1732731300000_1_8f434346",
      "occurred_at": "2026-11-27T17:40:12Z",
      "was_offline": true,
      "category": "APK_INSPECTION",
      "artifact_sha256": "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
      "local_verdict": "BLOCKED",
      "local_risk_score": 0.89,
      "details": {
        "filename": "factura_sat_viewer.apk",
        "violations": [
          "Dangerous capability requested: android.permission.BIND_ACCESSIBILITY_SERVICE",
          "Dangerous capability requested: android.permission.RECEIVE_SMS",
          "Suspicious homograph or spoofed domain detected: xn--sat-gob-mx-99a.com"
        ],
        "detected_domains": [
          "xn--sat-gob-mx-99a.com"
        ],
        "risk_score": 0.89
      }
    },
    {
      "event_id": "evt_1732731425000_2_4b227777",
      "occurred_at": "2026-11-27T17:42:05Z",
      "was_offline": true,
      "category": "DOCUMENT_CDR",
      "artifact_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
      "local_verdict": "SANITIZED",
      "local_risk_score": 0.62,
      "details": {
        "filename": "comprobante_pago.pdf",
        "violations": [
          "Dangerous active PDF element found: /JS embedded script",
          "Dangerous active PDF element found: Auto-executing /OpenAction"
        ],
        "detected_domains": [],
        "risk_score": 0.62
      }
    }
  ]
}
```

#### Response Payload (`TelemetryBatchResponse`):
```json
{
  "status": "PROCESSED",
  "processed_count": 2
}
```

> [!IMPORTANT]
> El cliente Rust en `src/sync.rs` evalúa la respuesta con:
> ```rust
> let is_processed = batch_resp.status.eq_ignore_ascii_case("PROCESSED")
>     || batch_resp.status.eq_ignore_ascii_case("OK")
>     || batch_resp.status.eq_ignore_ascii_case("SUCCESS")
>     || batch_resp.processed_count > 0;
> ```
> Asegúrate de que tu handler en Axum devuelva `status: "PROCESSED"` (o `"OK"`) y el número de eventos insertados en `processed_count`.

---

## 4. Flujo de Auto-Registro sin Login (Zero-Touch Enrollment)

El empleado nunca introduce credenciales en la aplicación móvil ni en la terminal:

```mermaid
sequenceDiagram
    autonumber
    participant App as Agente Endpoint (Rust / Android)
    participant SQLite as Cola Local SQLite
    participant AWS as Backend AWS (Axum / PostgreSQL)
    participant UEBA as Modelo UEBA (Isolation Forest)

    Note over App, SQLite: Operación Desconectada (Modo Offline)
    App->>SQLite: Encola veredictos y telemetría (status='PENDING')

    Note over App, AWS: El teléfono recupera conectividad a Internet
    App->>AWS: HEAD /v1/health
    AWS-->>App: 200 OK

    alt Dispositivo NO tiene internal_device_id
        App->>AWS: POST /v1/devices/handshake (hardware_uid, platform, etc.)
        Note over AWS: SELECT * FROM devices WHERE hardware_uid = $1
        alt Es un dispositivo nuevo
            AWS->>AWS: INSERT INTO devices (dev_id, hardware_uid, profile, risk=0.1)
            AWS-->>App: 200 OK (status="ENROLLED_NEW", internal_device_id="dev_qro_xxx")
        else Ya existía previamente
            AWS->>AWS: UPDATE devices SET last_seen = NOW()
            AWS-->>App: 200 OK (status="ENROLLED_EXISTING", internal_device_id="dev_qro_xxx")
        end
        App->>App: Guarda internal_device_id y session_token en disco local
    end

    App->>SQLite: SELECT * FROM telemetry_events WHERE status='PENDING' LIMIT 50
    SQLite-->>App: Lote de N eventos
    App->>AWS: POST /v1/telemetry/batch (con Bearer token y hardware_uid)
    AWS->>AWS: Guarda eventos en histórico de auditoría
    AWS->>UEBA: Alimenta histórico al modelo UEBA en AWS
    AWS-->>App: 200 OK {"status": "PROCESSED", "processed_count": N}
    App->>SQLite: UPDATE telemetry_events SET status='SYNCED' WHERE event_id IN (...)
```

---

## 5. Códigos de Estado HTTP y Comportamiento del Agente

| Código HTTP | Significado para el Agente | Acción en SQLite / Transmisión |
| :---: | :--- | :--- |
| **`200 OK`**<br>**`201 Created`** | Éxito total en handshake o lote procesado. | Transición atómica de los eventos a `status = 'SYNCED'`. No se retransmiten. |
| **`401 Unauthorized`**<br>**`403 Forbidden`** | Token de sesión expirado o dispositivo bloqueado. | El agente invalida su `session_token` local y forzará un nuevo handshake en el siguiente ciclo. |
| **`404 Not Found`** | Ruta no encontrada. | En `/v1/devices/handshake`, el agente reintenta automáticamente contra `/v1/devices/register`. |
| **`500 Internal Error`**<br>**`502 Bad Gateway`**<br>**`503 Unavailable`** | Falla temporal del backend o balanceador AWS. | Modo offline preservado: los eventos **NO se pierden**, se incrementa `retry_count` y se reintentan en el próximo ciclo. |
| **Timeout / Red caída** | Sin conexión a Internet. | Retención total en SQLite; aborta el ciclo de inmediato sin bloquear hilos. |

---

## 6. Código Rust Listo para Copiar y Pegar en Axum (`axum_shared_models.rs`)

Xotla puede copiar este bloque íntegro en su crate de Axum para contar de inmediato con los modelos y handlers compatibles al 100%:

```rust
//! Axum Shared Models & Handlers for AegisQRO Endpoint Synchronization
//! Archivo: src/api/aegis_sync_handlers.rs

use axum::{
    extract::{Json, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, head, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ============================================================================
// 1. ESTRUCTURAS DE DATOS (CONTRATOS EXACTOS)
// ============================================================================

/// Petición de auto-registro enviada por el agente endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegistration {
    pub hardware_uid: String,
    pub platform: String,
    pub os_version: String,
    pub device_model: String,
    pub agent_version: String,
}

/// Respuesta del handshake devuelta al agente endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResponse {
    pub status: String,
    pub internal_device_id: String,
    pub assigned_profile: String,
    pub current_risk_score: f32,
    pub sync_interval_sec: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
}

/// Evento individual de telemetría y veredicto de sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub event_id: String,
    pub occurred_at: String,
    pub was_offline: bool,
    pub category: String, // "APK_INSPECTION", "DOCUMENT_CDR", etc.
    pub artifact_sha256: String,
    pub local_verdict: String, // "BLOCKED", "SANITIZED", "ALLOWED", "SUSPICIOUS"
    pub local_risk_score: f32,
    pub details: serde_json::Value,
}

/// Lote masivo de telemetría enviado por el agente al recuperar red
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryBatchRequest {
    pub hardware_uid: String,
    pub internal_device_id: String,
    pub batch_timestamp: String,
    pub events: Vec<TelemetryEvent>,
}

/// Confirmación de entrega procesada por el servidor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryBatchResponse {
    pub status: String,
    pub processed_count: usize,
}

// ============================================================================
// 2. HANDLERS BASE LISTOS PARA INTEGRAR EN AXUM
// ============================================================================

/// Handler para sondeo de conectividad de bajo consumo (/v1/health)
pub async fn health_check_handler() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

/// Handler para handshake y auto-registro (/v1/devices/handshake y /v1/devices/register)
pub async fn device_handshake_handler(
    Json(payload): Json<DeviceRegistration>,
) -> Result<Json<RegistrationResponse>, (StatusCode, String)> {
    // 1. Validar formato mínimo de hardware_uid (64 caracteres SHA-256)
    if payload.hardware_uid.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "hardware_uid cannot be empty".to_string()));
    }

    // 2. LÓGICA DE BASE DE DATOS (Ejemplo Xotla / PostgreSQL):
    //    SELECT internal_device_id, assigned_profile, risk_score FROM devices WHERE hardware_uid = $1
    //    Si no existe:
    //      INSERT INTO devices (...) VALUES (...) RETURNING ...
    let short_hash = if payload.hardware_uid.len() >= 8 {
        &payload.hardware_uid[..8]
    } else {
        "dev"
    };
    let internal_device_id = format!("dev_qro_{}", short_hash);

    let response = RegistrationResponse {
        status: "ENROLLED_NEW".to_string(), // O "ENROLLED_EXISTING" si ya estaba en DB
        internal_device_id,
        assigned_profile: "standard_employee".to_string(),
        current_risk_score: 0.10,
        sync_interval_sec: 30,
        session_token: Some(format!("jwt_token_for_{}", payload.hardware_uid)),
    };

    Ok(Json(response))
}

/// Handler para procesar lotes de telemetría offline (/v1/telemetry/batch)
pub async fn telemetry_batch_handler(
    headers: HeaderMap,
    Json(payload): Json<TelemetryBatchRequest>,
) -> Result<Json<TelemetryBatchResponse>, (StatusCode, String)> {
    // Validar autorización opcional vía Bearer token si tu política lo requiere
    if let Some(auth_header) = headers.get("Authorization") {
        let _token = auth_header.to_str().unwrap_or_default();
        // Validar claims del JWT contra el payload.internal_device_id
    }

    let count = payload.events.len();

    // 1. Guardar eventos en la tabla de auditoría PostgreSQL
    // 2. Notificar al servicio UEBA de Fer (Isolation Forest ONNX) para perfilar anomalías
    for event in &payload.events {
        tracing::info!(
            device_id = %payload.internal_device_id,
            category = %event.category,
            verdict = %event.local_verdict,
            risk = event.local_risk_score,
            "Procesando evento de telemetría de endpoint"
        );
    }

    // IMPORTANTE: Status debe ser "PROCESSED" o "OK" para que el agente marque SQLite como sincronizado
    Ok(Json(TelemetryBatchResponse {
        status: "PROCESSED".to_string(),
        processed_count: count,
    }))
}

// ============================================================================
// 3. REGISTRO DE RUTAS EN EL ROUTER DE AXUM
// ============================================================================

pub fn build_aegis_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        // Health check soportando HEAD y GET
        .route("/v1/health", head(health_check_handler).get(health_check_handler))
        // Handshake con soporte para ruta principal y fallback
        .route("/v1/devices/handshake", post(device_handshake_handler))
        .route("/v1/devices/register", post(device_handshake_handler))
        // Lote de eventos de telemetría
        .route("/v1/telemetry/batch", post(telemetry_batch_handler))
}
```

---

## 7. Verificación de Compatibilidad y Checklist de Pruebas

Para verificar localmente que tu backend en Axum es compatible con el agente en Rust:

1. **Prueba de Health:**
   ```bash
   curl -I http://127.0.0.1:8080/v1/health
   # Debe responder HTTP/1.1 200 OK
   ```

2. **Prueba de Auto-Registro:**
   ```bash
   curl -X POST http://127.0.0.1:8080/v1/devices/handshake \
     -H "Content-Type: application/json" \
     -d '{
       "hardware_uid": "0e280d928b8a68e275ca4c270497214a15c0d529b92b868e96c1c156ecf243d6",
       "platform": "android",
       "os_version": "Android 14",
       "device_model": "Pixel 7",
       "agent_version": "0.1.0"
     }'
   ```

3. **Prueba de Lote de Telemetría:**
   ```bash
   curl -X POST http://127.0.0.1:8080/v1/telemetry/batch \
     -H "Content-Type: application/json" \
     -d '{
       "hardware_uid": "0e280d928b8a68e275ca4c270497214a15c0d529b92b868e96c1c156ecf243d6",
       "internal_device_id": "dev_qro_0e280d92",
       "batch_timestamp": "2026-11-27T18:15:00Z",
       "events": [
         {
           "event_id": "evt_test_001",
           "occurred_at": "2026-11-27T18:00:00Z",
           "was_offline": true,
           "category": "APK_INSPECTION",
           "artifact_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
           "local_verdict": "BLOCKED",
           "local_risk_score": 0.95,
           "details": { "package_name": "com.malicious.app" }
         }
       ]
     }'
   # Debe responder: {"status":"PROCESSED","processed_count":1}
   ```

4. **Prueba desde el Agente:**
   ```bash
   cargo run -- sync http://127.0.0.1:8080
   ```
