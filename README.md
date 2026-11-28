# xotla-server — AegisQRO Core Backend (Rust)

Servidor central Zero-Trust, gestor de políticas de seguridad corporativa, motor de perfilado de comportamiento (UEBA) y plataforma de gestión empresarial multi-tenant para **AegisQRO / Apolo** (Hackathon Ciberseguridad BLOQUE Querétaro). Construido 100% en **Rust** con `Axum`, `Tokio`, `WebSockets`, `SQLite` y `DashMap`.

---

## Servidor en Produccion (AWS EC2)

- **Base URL:** `http://54.146.211.248:8080`
- **Portal Empresarial:** `http://54.146.211.248:8080/portal`
- **Consola Global SOC / Zero-Trust:** `http://54.146.211.248:8080/dashboard`
- **API v1:** `http://54.146.211.248:8080/v1`
- **WebSocket Stream:** `ws://54.146.211.248:8080/v1/ws`
- **Simulador de Amenazas y Phishing:** `http://54.146.211.248:8080/demo-phishing`
- **Servicio Systemd:** `xotla-server.service` (reinicio automatico en puerto 8080)
- **Base de Datos Persistente:** SQLite en `/home/ubuntu/aegisqro_devices.sqlite`

### Tabla de Endpoints Principales

| Recurso / Vista | Metodo / Ruta | Descripcion |
| :--- | :--- | :--- |
| **Portal Empresarial** | `GET /portal` | Panel de administracion por empresa: tokens, politicas, inventario y reportes PDF. |
| **Consola Global SOC** | `GET /dashboard` | Panel de monitoreo de telemetria, cuentas de empresas y estado de red. |
| **Login Empresarial** | `POST /v1/portal/login` | Autenticacion corporativa por correo y clave SHA-256. |
| **Politicas del Portal** | `GET, PUT /v1/portal/sites` | Consulta y guardado de listas blancas y negras corporativas. |
| **Gestion de Tokens** | `POST, DELETE /v1/portal/tokens` | Emision y revocacion de tokens corporativos (limite de 10 por plan). |
| **Politica Dinamica** | `GET /v1/policy` | Entrega de dominios permitidos, bloqueados y extensiones peligrosas. |
| **Registro Zero-Touch** | `POST /v1/devices/handshake` | Auto-enrolamiento de equipos con control de cupos (maximo 2 por token). |
| **Telemetria Cifrada** | `POST /v1/telemetry/browser` | Ingesta de eventos de extension web con sobre AEGIS-SHA256-CTR-HMAC. |
| **Telemetria Agentes** | `POST /v1/sandbox/windows`, `/android` | Ingesta de eventos desde agente Windows y sandbox Android. |
| **WebSocket SOC** | `WS /v1/ws` | Transmision bidireccional en tiempo real de eventos de riesgo. |

---

## Arquitectura Modular del Backend

```text
xotla-server/
├── Cargo.toml
├── aegisqro_devices.sqlite          # Base de datos persistente SQLite (WAL mode)
├── docs/
│   ├── ADMIN_POLICY_CONTRACT.md     # Especificacion de politicas de seguridad
│   └── API_CONTRACT_XOTLA.md        # Contrato de datos y telemetria offline-first
└── src/
    ├── main.rs                      # Enrutamiento Axum HTTP + WebSockets en 0.0.0.0:8080
    ├── config.rs                    # Configuracion de entorno (HOST, PORT, PUBLIC_WS_BASE)
    ├── db.rs                        # Capa de acceso a datos SQLite (cuentas, tokens, politicas, eventos)
    ├── state.rs                     # Estado en memoria compartido y canales broadcast
    └── modules/
        ├── enterprise/              # Portal de empresas, gestion de licencias y reportes PDF
        ├── dashboard/               # Dashboard SOC Zero-Trust y creacion de cuentas corporativas
        ├── policy/                  # Control de listas blancas, listas negras y extensiones
        ├── security/                # Cifrado simetrico de sobre, firmas HMAC y middleware WAF
        ├── devices/                 # Control de concurrencia y vinculacion de 2 dispositivos por token
        ├── telemetry/               # Ingesta, deduplicacion SHA-256 y clasificacion de incidentes
        ├── ws/                      # Gestor de conexiones WebSockets concurrentes
        └── ueba/                    # Calculo de perfiles de riesgo y anomalias
```

---

## Modulos y Funcionalidades Destacadas

### 1. Portal de Administracion Empresarial (`/portal`)
- **Acceso seguro**: Credenciales corporativas con contrasenas hasheadas en SHA-256.
- **Pool de Tokens**: Maximo 10 tokens por cuenta empresarial (plan base).
- **Asignacion de 2 Dispositivos por Token**: Visualizacion de Slot 1 y Slot 2 con identificacion de plataforma (Windows, Android, Extension Web) y fecha de vinculacion.
- **Politica de Navegacion en Vivo**:
  - **Lista Blanca (Sitios Permitidos)**: Dominios corporativos confiables para acceso y descargas.
  - **Lista Negra (Sitios Bloqueados)**: Dominios restringidos propagados en tiempo real hacia las extensiones conectadas.
- **Reportes Ejecutivos en PDF**: Generacion desde el navegador con jsPDF filtrando por dispositivo especifico (Slot 1 o Slot 2) o reporte general consolidado.

### 2. Consola Global Zero-Trust (`/dashboard`)
- Autenticacion para administradores de plataforma (`admin@bloque.com`).
- Creacion y suspension de cuentas de empresa.
- Emision de pools iniciales de tokens.
- Monitoreo en vivo de telemetria proveniente de todos los endpoints.

### 3. Cifrado de Aplicacion en Transito
- Telemetria protegida mediante el sobre criptografico `AEGIS-SHA256-CTR-HMAC-V1`.
- Generacion de `nonce` unico por paquete de red.
- Validacion de integridad mediante HMAC-SHA256 en tiempo constante antes del desempaquetado.

---

## Ejecucion y Pruebas Locales

```bash
# Compilar en modo desarrollo
cargo check

# Ejecutar el servidor localmente
cargo run

# Compilar para produccion
cargo build --release
```
