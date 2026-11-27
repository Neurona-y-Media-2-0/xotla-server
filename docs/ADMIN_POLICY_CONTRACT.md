# Contrato: panel de administración TI y política de la extensión

Para: Xotla (backend). La extensión ya consume la política; falta el endpoint y el panel con login.

## 1. Endpoint que consume la extensión (obligatorio)

`GET /v1/policy`  
Header: `X-API-Key: <token_equipo>`  
Respuesta `200 application/json`:

```json
{
  "version": 3,
  "trusted_download_hosts": ["tools.empresa.mx", "aegisqro.internal"],
  "protected_domains": ["apple-support.com", "sat.gob.mx", "bbva.mx", "banorte.com", "aegisqro.internal"],
  "dangerous_extensions": [".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".scr", ".iso", ".lnk", ".zip"]
}
```

La extensión la pide al arrancar y cada 15 minutos, la valida y la guarda en caché. Reglas que ella misma aplica
(lo que no cumpla se ignora y se conserva la política anterior):

- `trusted_download_hosts` y `protected_domains`: hostnames en minúsculas con al menos un punto. No se aceptan `com`, comodines ni URLs. Puede ir vacía solo `trusted_download_hosts`.
- `dangerous_extensions`: empiezan con punto, 1 a 10 caracteres alfanuméricos.
- Máximo 500 elementos por lista. Un campo ausente o inválido no cambia ese valor.

Una descarga de `trusted_download_hosts` se permite solo si es HTTPS, el host coincide exacto o es subdominio, y no redirige fuera. El valor de `version` debe subir en cada cambio.

## 2. Login y panel de administración (backend)

El login no puede vivir en la extensión (cualquiera puede editar su código), debe ser del servidor.

| Endpoint | Uso |
|---|---|
| `POST /admin/login` `{usuario, password}` | Devuelve cookie de sesión `HttpOnly; Secure; SameSite=Strict`, 8 h máximo |
| `POST /admin/logout` | Invalida la sesión |
| `GET /admin/policy` | Política actual (requiere sesión) |
| `PUT /admin/policy` | Reemplaza la política y sube `version` (requiere sesión + token CSRF) |

Requisitos mínimos de seguridad:

1. Contraseñas con argon2id o bcrypt (>= 12 rondas). Nunca en texto plano ni en el repo.
2. Límite de intentos de login (p. ej. 5 por 15 min por IP y por usuario) y mensaje de error genérico.
3. Servir el panel y `/v1/policy` por **HTTPS**. Hoy el servidor responde por HTTP: quien intercepte la red podría publicar una lista de confianza falsa. Con HTTPS el riesgo desaparece.
4. Bitácora de cambios: quién, cuándo y diff de la política.
5. Validar en el servidor las mismas reglas de la sección 1 antes de guardar.
6. `/admin/*` separado del `X-API-Key` de las extensiones: esa llave está embebida en cada instalación y no debe dar acceso al panel.

## 3. Pantallas del panel

Tres listas editables (agregar y quitar elementos): orígenes de descarga de confianza, dominios protegidos y extensiones peligrosas, con botón Guardar que muestra la nueva `version`.
