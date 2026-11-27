// src/modules/security/antivirus.rs
use serde::{Deserialize, Serialize};
use crate::db::sha256_hex;

const BLOCKED_CONTENT_TYPES: &[&str] = &[
    "application/octet-stream",
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-executable",
    "application/x-elf",
    "application/x-sh",
    "application/x-bat",
    "application/x-msi",
];

const BINARY_MAGIC_AND_B64_SIGNATURES: &[(&str, &str)] = &[
    ("eicar-standard-antivirus-test-file", "EICAR_TEST_VIRUS"),
    ("x5o!p%@ap[4\\pzx54(p^)7cc)7}", "EICAR_TEST_VIRUS"),
    ("tvqqaamaaaaeaaaa", "BASE64_WINDOWS_PE_EXECUTABLE"),
    ("tvpqaamaaaaeaaaa", "BASE64_WINDOWS_PE_EXECUTABLE"),
    ("f0vmrg", "BASE64_LINUX_ELF_BINARY"),
    ("\x7felf", "RAW_LINUX_ELF_BINARY"),
    ("dex\n035", "RAW_ANDROID_DEX_BINARY"),
    ("4d5a900003000000", "HEX_ENCODED_PE_EXECUTABLE"),
    ("7f454c4602010100", "HEX_ENCODED_ELF_BINARY"),
];

const MALWARE_PAYLOAD_SIGNATURES: &[(&str, &str)] = &[
    ("vssadmin delete shadows", "RANSOMWARE_SHADOW_DELETE"),
    ("wmic shadowcopy delete", "RANSOMWARE_SHADOW_DELETE"),
    ("wbadmin delete catalog", "RANSOMWARE_BACKUP_WIPE"),
    ("bcdedit /set {default} recoveryenabled no", "RANSOMWARE_RECOVERY_DISABLE"),
    ("sekurlsa::logonpasswords", "MIMIKATZ_CREDENTIAL_DUMPER"),
    ("lsadump::sam", "MIMIKATZ_SAM_DUMP"),
    ("meterpreter", "METASPLOIT_METERPRETER_PAYLOAD"),
    ("beacon.dll", "COBALT_STRIKE_BEACON"),
    ("/dev/tcp/", "LINUX_REVERSE_SHELL"),
    ("nc -e /bin/", "NETCAT_REVERSE_SHELL"),
    ("bash -i >&", "BASH_INTERACTIVE_REVERSE_SHELL"),
    ("python -c 'import socket,subprocess,os", "PYTHON_REVERSE_SHELL"),
    ("virtualalloc", "SHELLCODE_MEMORY_INJECTION"),
    ("createremotethread", "PROCESS_HOLLOWING_INJECTION"),
    ("xmrig", "CRYPTOMINER_PAYLOAD"),
    ("stratum+tcp://", "CRYPTOMINER_POOL_CONNECTION"),
];

const KNOWN_MALICIOUS_SHA256: &[(&str, &str)] = &[
    (
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "EICAR_TEST_FILE_SHA256",
    ),
    (
        "db349b97c37d22f5ea1d1841e3c89eb41545c9072716079255a5d42815c18824",
        "WANNACRY_RANSOMWARE_DROPPER",
    ),
    (
        "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        "WANNACRY_RANSOMWARE_PAYLOAD",
    ),
    (
        "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",
        "NOTPETYA_WIPER_PAYLOAD",
    ),
];

const DOUBLE_EXT_PATTERNS: &[&str] = &[
    ".pdf.exe",
    ".doc.exe",
    ".docx.exe",
    ".xls.exe",
    ".xlsx.exe",
    ".jpg.exe",
    ".png.exe",
    ".txt.exe",
    ".pdf.scr",
    ".jpg.scr",
    ".pdf.bat",
    ".pdf.cmd",
    ".pdf.ps1",
    ".pdf.vbs",
    ".zip.exe",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntivirusScanRequest {
    pub filename: Option<String>,
    pub sha256: Option<String>,
    pub content_sample: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntivirusScanResult {
    pub clean: bool,
    pub action: String,
    pub signature_matched: Option<String>,
    pub details: String,
    pub computed_sha256: String,
}

pub fn check_content_type(content_type: Option<&str>) -> Result<(), (&'static str, &'static str)> {
    let Some(ct) = content_type else {
        return Ok(());
    };
    let lower = ct.to_lowercase();
    for blocked in BLOCKED_CONTENT_TYPES {
        if lower.contains(blocked) {
            return Err((
                "BINARY_UPLOAD_BLOCKED",
                "Subida directa de binarios o ejecutables bloqueada por Antivirus Xotla",
            ));
        }
    }
    Ok(())
}

pub fn check_raw_binary_bytes(bytes: &[u8]) -> Result<(), (&'static str, &'static str)> {
    if bytes.len() >= 2 && bytes[0] == 0x4D && bytes[1] == 0x5A {
        return Err((
            "WINDOWS_PE_VIRUS_BLOCKED",
            "Ejecutable Windows MZ/PE detectado en el cuerpo de la peticion",
        ));
    }
    if bytes.len() >= 4 && bytes[0] == 0x7F && &bytes[1..4] == b"ELF" {
        return Err((
            "LINUX_ELF_BINARY_BLOCKED",
            "Binario ejecutable Linux ELF detectado y bloqueado",
        ));
    }
    if bytes.len() >= 4 && &bytes[0..4] == b"dex\n" {
        return Err((
            "ANDROID_DEX_BINARY_BLOCKED",
            "Binario ejecutable Android DEX detectado y bloqueado",
        ));
    }
    Ok(())
}

pub fn scan_text_for_viruses(
    input: &str,
    is_sandbox_report: bool,
) -> Result<(), (&'static str, &'static str)> {
    let lower = input.to_lowercase();

    for (sig, name) in BINARY_MAGIC_AND_B64_SIGNATURES {
        if lower.contains(sig) {
            return Err(("MALWARE_BINARY_SIGNATURE", name));
        }
    }

    for (hash, name) in KNOWN_MALICIOUS_SHA256 {
        if lower.contains(hash) && !is_sandbox_report {
            return Err(("KNOWN_MALWARE_HASH", name));
        }
    }

    if !is_sandbox_report {
        for ext in DOUBLE_EXT_PATTERNS {
            if lower.contains(ext) {
                return Err((
                    "TROJAN_DOUBLE_EXTENSION",
                    "Archivo con doble extension enganosa detectado (.pdf.exe / .scr)",
                ));
            }
        }

        for (sig, name) in MALWARE_PAYLOAD_SIGNATURES {
            if lower.contains(sig) {
                return Err(("VIRUS_PAYLOAD_DETECTED", name));
            }
        }
    }

    Ok(())
}

pub fn scan_payload_request(req: &AntivirusScanRequest) -> AntivirusScanResult {
    let combined = format!(
        "{} {} {}",
        req.filename.as_deref().unwrap_or(""),
        req.sha256.as_deref().unwrap_or(""),
        req.content_sample.as_deref().unwrap_or("")
    );
    let computed_sha256 = req
        .sha256
        .clone()
        .unwrap_or_else(|| sha256_hex(&combined));

    if let Err((cat, sig)) = scan_text_for_viruses(&combined, false) {
        return AntivirusScanResult {
            clean: false,
            action: "QUARANTINED_AND_DROPPED".to_string(),
            signature_matched: Some(format!("{}:{}", cat, sig)),
            details: "Amenaza/virus detectado en memoria; descartado sin tocar el disco".to_string(),
            computed_sha256,
        };
    }

    AntivirusScanResult {
        clean: true,
        action: "ALLOWED".to_string(),
        signature_matched: None,
        details: "Sin firmas de virus, binarios embebidos ni payloads destructivos".to_string(),
        computed_sha256,
    }
}
