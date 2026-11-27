// src/modules/security/inspector.rs
use serde_json::Value;

pub const MAX_BODY_BYTES: usize = 256 * 1024;
pub const MAX_WS_BYTES: usize = 64 * 1024;
pub const MAX_JSON_DEPTH: usize = 16;
pub const MAX_ARRAY_LEN: usize = 200;
pub const MAX_STRING_LEN: usize = 2048;

const XSS_PATTERNS: &[&str] = &[
    "<script",
    "</script",
    "javascript:",
    "vbscript:",
    "data:text/html",
    "onerror=",
    "onload=",
    "onclick=",
    "onmouseover=",
    "<iframe",
    "<object",
    "<embed",
    "<svg",
];

const SQLI_PATTERNS: &[&str] = &[
    "union select",
    "drop table",
    "drop database",
    "insert into",
    "delete from",
    "update devices set",
    "sqlite_master",
    "' or '1'='1",
    "\" or \"1\"=\"1",
    "' or 1=1",
    "';--",
];

const TRAVERSAL_PATTERNS: &[&str] = &[
    "../",
    "..\\",
    "%2e%2e%2f",
    "%2e%2e/",
    "..%2f",
    "%2e%2e%5c",
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self",
    "c:\\windows\\system32\\config",
];

const CMD_INJECTION_PATTERNS: &[&str] = &[
    "$(",
    "`",
    "; rm -",
    "| sh",
    "| bash",
    "|/bin/sh",
    "&& curl ",
    "&& wget ",
    "; cat /etc/",
    "\0",
    "%00",
];

pub fn inspect_raw_text(input: &str, check_cmd: bool) -> Result<(), (&'static str, &'static str)> {
    if input.len() > MAX_BODY_BYTES {
        return Err(("PAYLOAD_TOO_LARGE", "Payload exceeds size limit"));
    }

    let lower = input.to_lowercase();

    for pat in TRAVERSAL_PATTERNS {
        if lower.contains(pat) {
            return Err(("PATH_TRAVERSAL", "Path traversal pattern blocked"));
        }
    }

    for pat in XSS_PATTERNS {
        if lower.contains(pat) {
            return Err(("XSS_ATTACK", "Cross-site scripting payload blocked"));
        }
    }

    for pat in SQLI_PATTERNS {
        if lower.contains(pat) {
            return Err(("SQL_INJECTION", "SQL injection pattern blocked"));
        }
    }

    if check_cmd {
        for pat in CMD_INJECTION_PATTERNS {
            if lower.contains(pat) {
                return Err(("COMMAND_INJECTION", "Command injection or null byte blocked"));
            }
        }
    } else if lower.contains('\0') || lower.contains("%00") {
        return Err(("NULL_BYTE_INJECTION", "Null byte blocked"));
    }

    Ok(())
}

pub fn inspect_json_value(
    val: &Value,
    depth: usize,
    is_sandbox_route: bool,
) -> Result<(), (&'static str, &'static str)> {
    if depth > MAX_JSON_DEPTH {
        return Err(("JSON_DEPTH_EXCEEDED", "JSON nesting depth exceeds safe limit"));
    }

    match val {
        Value::String(s) => {
            if s.len() > MAX_STRING_LEN {
                return Err(("STRING_TOO_LONG", "String field exceeds 2048 bytes"));
            }
            inspect_raw_text(s, !is_sandbox_route)
        }
        Value::Array(arr) => {
            if arr.len() > MAX_ARRAY_LEN {
                return Err(("ARRAY_TOO_LARGE", "Array exceeds 200 items limit"));
            }
            for item in arr {
                inspect_json_value(item, depth + 1, is_sandbox_route)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            if map.len() > MAX_ARRAY_LEN {
                return Err(("OBJECT_TOO_LARGE", "Object has too many keys"));
            }
            for (k, v) in map {
                inspect_raw_text(k, true)?;
                inspect_json_value(v, depth + 1, is_sandbox_route)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub fn sanitize_string(input: &str, max_len: usize) -> String {
    let mut out = String::with_capacity(input.len().min(max_len));
    for ch in input.chars() {
        if out.len() >= max_len {
            break;
        }
        if ch == '\0' || (ch.is_control() && ch != '\n' && ch != '\r' && ch != '\t') {
            continue;
        }
        match ch {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(ch),
        }
    }
    out.trim().to_string()
}

pub fn sanitize_json_value(val: &mut Value) -> bool {
    match val {
        Value::String(s) => {
            let clean = sanitize_string(s, MAX_STRING_LEN);
            let changed = clean != *s;
            *s = clean;
            changed
        }
        Value::Array(arr) => {
            arr.truncate(MAX_ARRAY_LEN);
            let mut changed = false;
            for item in arr {
                if sanitize_json_value(item) {
                    changed = true;
                }
            }
            changed
        }
        Value::Object(map) => {
            let mut changed = false;
            for (_, v) in map.iter_mut() {
                if sanitize_json_value(v) {
                    changed = true;
                }
            }
            changed
        }
        _ => false,
    }
}
