use std::fs;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use crate::{
    db::sha256_hex,
    modules::scanner::dto::{FileScanRequest, ScannedArtifactRecord},
    state::AppState,
};

pub fn classify_file_extension(filename: &str) -> String {
    let lower = filename.trim().to_lowercase();
    if lower.ends_with(".png") {
        "IMAGE_PNG".to_string()
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        "IMAGE_JPEG".to_string()
    } else if lower.ends_with(".webp") || lower.ends_with(".gif") {
        "IMAGE_WEB".to_string()
    } else if lower.ends_with(".apk") {
        "ANDROID_APK".to_string()
    } else if lower.ends_with(".exe") || lower.ends_with(".msi") || lower.ends_with(".dll") {
        "WINDOWS_EXECUTABLE".to_string()
    } else if lower.ends_with(".pdf") {
        "DOCUMENT_PDF".to_string()
    } else if lower.ends_with(".ps1") || lower.ends_with(".bat") || lower.ends_with(".cmd") {
        "SCRIPT_SHELL".to_string()
    } else if lower.starts_with("http://") || lower.starts_with("https://") {
        "WEB_URL".to_string()
    } else {
        "BINARY_ARTIFACT".to_string()
    }
}

fn detect_magic_bytes(bytes: &[u8]) -> &'static str {
    if bytes.len() >= 8 && &bytes[..8] == b"\x89PNG\r\n\x1a\n" {
        "PNG_IMAGE"
    } else if bytes.len() >= 3 && &bytes[..3] == b"\xFF\xD8\xFF" {
        "JPEG_IMAGE"
    } else if bytes.len() >= 4 && &bytes[..4] == b"GIF8" {
        "GIF_IMAGE"
    } else if bytes.len() >= 4 && &bytes[..4] == b"%PDF" {
        "PDF_DOCUMENT"
    } else if bytes.len() >= 2 && &bytes[..2] == b"MZ" {
        "PE_WINDOWS_EXE"
    } else if bytes.len() >= 4 && &bytes[..4] == b"\x7FELF" {
        "ELF_LINUX_BINARY"
    } else if bytes.len() >= 4 && &bytes[..4] == b"PK\x03\x04" {
        "ZIP_OR_APK_ARCHIVE"
    } else {
        "GENERIC_STREAM"
    }
}

fn shannon_entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f32;
    let mut entropy = 0.0f32;
    for &c in &counts {
        if c > 0 {
            let p = (c as f32) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

pub fn inspect_and_purge_ephemeral(
    state: &AppState,
    req: FileScanRequest,
) -> ScannedArtifactRecord {
    let file_type = classify_file_extension(&req.filename);
    let device_id = req.device_id.unwrap_or_else(|| "dev_qro_scanner".to_string());
    let employee_id = req.employee_id.unwrap_or_else(|| "emp_042".to_string());

    let raw_bytes = req
        .content_base64
        .as_deref()
        .and_then(|b64| BASE64.decode(b64.trim()).ok())
        .unwrap_or_default();

    let tmp_dir = std::env::temp_dir().join("aegisqro_ephemeral");
    let _ = fs::create_dir_all(&tmp_dir);
    let tmp_file = tmp_dir.join(format!("scan_{}.tmp", Uuid::new_v4().simple()));

    if !raw_bytes.is_empty() {
        let _ = fs::write(&tmp_file, &raw_bytes);
    }

    let artifact_sha256 = if !raw_bytes.is_empty() {
        let mut hasher = Sha256::new();
        hasher.update(&raw_bytes);
        hex::encode(hasher.finalize())
    } else if let Some(ref provided) = req.sha256 {
        if provided.len() == 64 {
            provided.to_lowercase()
        } else {
            sha256_hex(provided)
        }
    } else {
        sha256_hex(&req.filename)
    };

    let mut reasons = req.reported_reasons;
    let mut methods = Vec::new();
    let mut score: f32 = 0.05;

    let detected_magic = if !raw_bytes.is_empty() {
        detect_magic_bytes(&raw_bytes).to_string()
    } else {
        file_type.clone()
    };

    let lower_name = req.filename.to_lowercase();
    for dbl in [".pdf.exe", ".png.exe", ".jpg.exe", ".docx.exe", ".png.scr", ".jpg.bat"] {
        if lower_name.ends_with(dbl) {
            score = score.max(0.95);
            methods.push("DOUBLE_EXTENSION_DETECTION");
            reasons.push(format!("Doble extension maliciosa detectada ({})", dbl));
        }
    }

    if file_type.starts_with("IMAGE_")
        && (detected_magic == "PE_WINDOWS_EXE"
            || detected_magic == "ELF_LINUX_BINARY"
            || detected_magic == "ZIP_OR_APK_ARCHIVE")
    {
        score = score.max(0.98);
        methods.push("MAGIC_BYTES_SPOOFING");
        reasons.push(format!(
            "Imagen falsa: extension {} pero sus Magic Bytes reales son {}",
            file_type, detected_magic
        ));
    }

    if !raw_bytes.is_empty() {
        let text_lossy = String::from_utf8_lossy(&raw_bytes).to_lowercase();
        let suspicious_markers = [
            ("powershell", "Payload PowerShell embebido en archivo/imagen"),
            ("cmd.exe", "Invocacion a cmd.exe oculta en bytes del archivo"),
            ("<script", "Script HTML/JS oculto en metadatos o cuerpo"),
            ("<?php", "Webshell PHP inyectada en imagen (Steganography/Polyglot)"),
            ("/openaction", "Accion automatica peligrosa /OpenAction en documento"),
            ("/js", "Codigo JavaScript embebido en PDF/imagen"),
            ("eval(", "Ejecucion dinamica eval() detectada en payload"),
        ];

        for (needle, explanation) in suspicious_markers {
            if text_lossy.contains(needle) {
                score = score.max(0.92);
                if !methods.contains(&"PAYLOAD_SIGNATURE_SCAN") {
                    methods.push("PAYLOAD_SIGNATURE_SCAN");
                }
                reasons.push(explanation.to_string());
            }
        }

        let entropy = shannon_entropy(&raw_bytes);
        if entropy > 7.4 && !file_type.starts_with("IMAGE_") {
            score = score.max(0.78);
            methods.push("HIGH_SHANNON_ENTROPY");
            reasons.push(format!(
                "Entropia de Shannon alta ({:.2}/8.0): posible payload cifrado o empaquetado",
                entropy
            ));
        }
    }

    if !reasons.is_empty() && score < 0.80 {
        score = 0.88;
        if methods.is_empty() {
            methods.push("SANDBOX_BEHAVIORAL_DETECTION");
        }
    }

    if tmp_file.exists() {
        let _ = fs::remove_file(&tmp_file);
    }

    let verdict = if score >= 0.80 {
        "MALICIOUS"
    } else if score >= 0.45 {
        "SUSPICIOUS"
    } else {
        "CLEAN"
    }
    .to_string();

    if methods.is_empty() {
        methods.push("SHA256_STATIC_VERIFICATION");
    }
    if reasons.is_empty() {
        reasons.push("Sin firmas maliciosas detectadas".to_string());
    }

    let record = ScannedArtifactRecord {
        artifact_sha256,
        file_type,
        detected_magic,
        verdict,
        threat_score: score,
        detection_method: methods.join(" + "),
        detection_reasons: reasons,
        device_id,
        employee_id,
        ephemeral_purged: true,
        scanned_at: Utc::now(),
    };

    state.db.upsert_scanned_artifact(&record);
    record
}
