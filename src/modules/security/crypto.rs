// src/modules/security/crypto.rs
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const DEFAULT_SHARED_KEY: &str = "aegis-qro-team-token-2026";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub aegis_enc: String,
    #[serde(default)]
    pub alg: String,
    pub nonce: String,
    pub ciphertext: String,
    pub mac: String,
}

fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn sha256_hex_str(input: &str) -> String {
    hex::encode(sha256_bytes(input.as_bytes()))
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn xor_keystream(data: &[u8], key: &str, nonce_hex: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for (block_idx, chunk) in data.chunks(32).enumerate() {
        let seed = format!("{}:enc:{}:{}", key, nonce_hex, block_idx);
        let ks = sha256_bytes(seed.as_bytes());
        for (i, &byte) in chunk.iter().enumerate() {
            out.push(byte ^ ks[i]);
        }
    }
    out
}

#[allow(dead_code)]
pub fn encrypt_json_payload(payload: &Value, key: &str, nonce_hex: &str) -> EncryptedEnvelope {
    let plain_bytes = serde_json::to_vec(payload).unwrap_or_default();
    let cipher_bytes = xor_keystream(&plain_bytes, key, nonce_hex);
    let ciphertext = hex::encode(cipher_bytes);
    let mac_input = format!("{}:mac:{}:{}", key, nonce_hex, ciphertext);
    let mac = sha256_hex_str(&mac_input);

    EncryptedEnvelope {
        aegis_enc: "v1".to_string(),
        alg: "AEGIS-SHA256-CTR-HMAC".to_string(),
        nonce: nonce_hex.to_string(),
        ciphertext,
        mac,
    }
}

pub fn decrypt_envelope_to_json(
    env: &EncryptedEnvelope,
    key: &str,
) -> Result<Value, (&'static str, &'static str)> {
    if env.aegis_enc != "v1" {
        return Err(("UNSUPPORTED_CIPHER_VERSION", "Unsupported aegis_enc version"));
    }
    if env.nonce.len() < 16 || env.nonce.len() > 64 {
        return Err(("INVALID_NONCE", "Invalid encryption nonce length"));
    }

    let expected_mac = sha256_hex_str(&format!("{}:mac:{}:{}", key, env.nonce, env.ciphertext));
    if !constant_time_eq(&expected_mac, &env.mac.to_lowercase()) {
        return Err((
            "INVALID_ENCRYPTION_MAC",
            "Firma HMAC de cifrado invalida o paquete alterado en red",
        ));
    }

    let cipher_bytes = hex::decode(&env.ciphertext)
        .map_err(|_| ("INVALID_CIPHERTEXT_HEX", "Ciphertext is not valid hex"))?;
    let plain_bytes = xor_keystream(&cipher_bytes, key, &env.nonce);

    serde_json::from_slice::<Value>(&plain_bytes)
        .map_err(|_| ("DECRYPTED_JSON_INVALID", "Decrypted payload is not valid JSON"))
}
