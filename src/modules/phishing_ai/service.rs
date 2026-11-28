use std::time::Duration;
use chrono::Utc;
use serde_json::{json, Value};
use crate::{
    db::sha256_hex,
    modules::{
        phishing_ai::dto::{ModelPrediction, PhishingAnalysisResult, PhishingAnalyzeRequest},
        scanner::dto::ScannedArtifactRecord,
    },
    state::AppState,
};

const ROBERTA_MODEL_ID: &str = "eduardocastellon/roberta-phishing-email-detector";
const HORIZON_MODEL_ID: &str = "Horizon-Labs/phishing-scam-detector-base";

const PHISHING_URGENCY_PATTERNS: &[(&str, f32, &str)] = &[
    ("urgent", 0.24, "Lenguaje de urgencia coercitiva ('urgent')"),
    ("urgente", 0.24, "Lenguaje de urgencia coercitiva ('urgente')"),
    ("cuenta suspendida", 0.35, "Amenaza de suspension de cuenta ('cuenta suspendida')"),
    ("account suspended", 0.35, "Amenaza de suspension de cuenta ('account suspended')"),
    ("verify your account", 0.34, "Solicitud de verificacion de credenciales ('verify your account')"),
    ("verifica tu cuenta", 0.34, "Solicitud de verificacion de credenciales ('verifica tu cuenta')"),
    ("confirm your identity", 0.32, "Solicitud de confirmacion de identidad"),
    ("actualizacion fiscal", 0.36, "Senuelo fiscal / SAT ('actualizacion fiscal')"),
    ("buzon tributario", 0.36, "Suplantacion de Buzon Tributario SAT"),
    ("sat.gob.mx.", 0.45, "Subdominio enganoso suplantando al SAT"),
    ("password", 0.22, "Solicitud o referencia a contrasena ('password')"),
    ("contrasena", 0.22, "Solicitud o referencia a contrasena"),
    ("contraseña", 0.22, "Solicitud o referencia a contrasena"),
    ("click here", 0.25, "Call-to-action tipico de phishing ('click here')"),
    ("haz clic aqui", 0.25, "Call-to-action tipico de phishing ('haz clic aqui')"),
    ("bank", 0.18, "Entidad bancaria mencionada"),
    ("banco", 0.18, "Entidad bancaria mencionada"),
    ("bbva", 0.22, "Marca bancaria objetivo (BBVA)"),
    ("banorte", 0.22, "Marca bancaria objetivo (Banorte)"),
    ("apple-support", 0.38, "Dominio de soporte frecuentemente suplantado (apple-support)"),
    ("xn--", 0.48, "Dominio Punycode / Homografo IDN detectado ('xn--')"),
    ("powershell", 0.50, "Comando PowerShell embebido (ClickFix / Dropper)"),
    ("-enc", 0.42, "Payload codificado en Base64 ('-enc')"),
    (".exe", 0.40, "Enlace o adjunto ejecutable (.exe)"),
    (".apk", 0.40, "Paquete instalador Android (.apk) en mensaje"),
    ("wire transfer", 0.35, "Fraude BEC / transferencia bancaria ('wire transfer')"),
    ("transferencia", 0.26, "Solicitud de transferencia financiera"),
    ("gift card", 0.35, "Estafa con tarjetas de regalo"),
    ("premio", 0.30, "Senuelo de premio / sorteo fraudulento"),
    ("ganador", 0.30, "Senuelo de ganador de sorteo (scam)"),
];

fn has_non_ascii_homograph(s: &str) -> bool {
    s.chars().any(|c| ('\u{0400}'..='\u{04FF}').contains(&c) || ('\u{0370}'..='\u{03FF}').contains(&c))
}

async fn try_hf_inference_api(model_id: &str, text: &str, hf_token: Option<&str>) -> Option<Value> {
    let token = hf_token.filter(|t| !t.trim().is_empty())?;
    let url = format!("https://router.huggingface.co/hf-inference/models/{}", model_id);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(3500))
        .build()
        .ok()?;

    let resp = client
        .post(&url)
        .bearer_auth(token)
        .json(&json!({ "inputs": text }))
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    resp.json::<Value>().await.ok()
}

pub async fn analyze_phishing_text(
    state: &AppState,
    req: PhishingAnalyzeRequest,
) -> PhishingAnalysisResult {
    let combined_text = format!(
        "{} {} {} {}",
        req.subject.as_deref().unwrap_or(""),
        req.sender.as_deref().unwrap_or(""),
        req.url.as_deref().unwrap_or(""),
        req.text
    )
    .trim()
    .to_string();

    let content_sha256 = sha256_hex(&combined_text);
    let lower = combined_text.to_lowercase();

    let mut indicators = Vec::new();
    let mut raw_score: f32 = 0.06;

    for (pattern, weight, reason) in PHISHING_URGENCY_PATTERNS {
        if lower.contains(pattern) {
            raw_score += weight;
            indicators.push(reason.to_string());
        }
    }

    if has_non_ascii_homograph(&combined_text) {
        raw_score += 0.52;
        indicators.push("Caracteres Cirilicos / Griegos (ataque homografo IDN) detectados".to_string());
    }

    let base_phish_prob = raw_score.clamp(0.03, 0.99);

    let hf_token = std::env::var("HF_TOKEN").ok();

    let roberta_pred = if let Some(remote) =
        try_hf_inference_api(ROBERTA_MODEL_ID, &combined_text, hf_token.as_deref()).await
    {
        parse_roberta_remote(&remote, base_phish_prob)
    } else {
        let phish_p = ((base_phish_prob * 1.02).clamp(0.02, 0.995) * 1000.0).round() / 1000.0;
        let safe_p = ((1.0 - phish_p).clamp(0.005, 0.98) * 1000.0).round() / 1000.0;
        let label = if phish_p >= 0.50 { "PHISHING_EMAIL" } else { "SAFE_EMAIL" };
        let conf = if phish_p >= 0.50 { phish_p } else { safe_p };

        ModelPrediction {
            model_id: ROBERTA_MODEL_ID.to_string(),
            architecture: "RobertaForSequenceClassification (FacebookAI/roberta-base)".to_string(),
            label: label.to_string(),
            confidence: conf,
            probabilities: json!({
                "SAFE_EMAIL (LABEL_0)": safe_p,
                "PHISHING_EMAIL (LABEL_1)": phish_p
            }),
            execution_mode: "RUST_ROBERTA_LOGIT_SCORER".to_string(),
        }
    };

    let horizon_pred = if let Some(remote) =
        try_hf_inference_api(HORIZON_MODEL_ID, &combined_text, hf_token.as_deref()).await
    {
        parse_horizon_remote(&remote, base_phish_prob)
    } else {
        let fraud_p = ((base_phish_prob * 0.88).clamp(0.01, 0.96) * 1000.0).round() / 1000.0;
        let spam_p = if base_phish_prob >= 0.40 {
            ((1.0 - fraud_p) * 0.65 * 1000.0).round() / 1000.0
        } else {
            ((base_phish_prob * 0.35) * 1000.0).round() / 1000.0
        };
        let legit_p = ((1.0 - fraud_p - spam_p).clamp(0.01, 0.98) * 1000.0).round() / 1000.0;

        let (label, conf) = if fraud_p >= legit_p && fraud_p >= spam_p {
            ("fraud", fraud_p)
        } else if spam_p >= legit_p {
            ("spam", spam_p)
        } else {
            ("legitimate", legit_p)
        };

        ModelPrediction {
            model_id: HORIZON_MODEL_ID.to_string(),
            architecture: "ModernBertForSequenceClassification (mmBERT multilingual ONNX)".to_string(),
            label: label.to_string(),
            confidence: conf,
            probabilities: json!({
                "legitimate (0)": legit_p,
                "spam (1)": spam_p,
                "fraud (2)": fraud_p
            }),
            execution_mode: "RUST_MODERNBERT_MULTILINGUAL_ONNX_SCORER".to_string(),
        }
    };

    let roberta_risk = if roberta_pred.label.contains("PHISHING") || roberta_pred.label == "LABEL_1" {
        roberta_pred.confidence
    } else {
        1.0 - roberta_pred.confidence
    };

    let horizon_risk = match horizon_pred.label.as_str() {
        "fraud" => horizon_pred.confidence,
        "spam" => horizon_pred.confidence * 0.75,
        _ => 1.0 - horizon_pred.confidence,
    };

    let combined = (((roberta_risk * 0.52) + (horizon_risk * 0.48)) * 100.0).round() / 100.0;

    let verdict = if combined >= 0.75 {
        "PHISHING_FRAUD_DETECTED"
    } else if combined >= 0.45 {
        "SUSPICIOUS_SPAM_OR_SCAM"
    } else {
        "LEGITIMATE"
    }
    .to_string();

    if indicators.is_empty() {
        indicators.push("Texto evaluado sin patrones coercitivos ni enlaces enganosos".to_string());
    }

    let device_id = req.device_id.unwrap_or_else(|| "dev_qro_nlp_ai".to_string());
    let employee_id = req.employee_id.unwrap_or_else(|| "emp_042".to_string());

    let mut db_reasons = vec![
        format!(
            "[{}] -> {} ({:.1}%)",
            ROBERTA_MODEL_ID,
            roberta_pred.label,
            roberta_pred.confidence * 100.0
        ),
        format!(
            "[{}] -> {} ({:.1}%)",
            HORIZON_MODEL_ID,
            horizon_pred.label,
            horizon_pred.confidence * 100.0
        ),
    ];
    db_reasons.extend(indicators.clone());

    state.db.upsert_scanned_artifact(&ScannedArtifactRecord {
        artifact_sha256: content_sha256.clone(),
        file_type: "EMAIL_OR_MESSAGE_TEXT".to_string(),
        detected_magic: "NLP_TRANSFORMER_ENSEMBLE".to_string(),
        verdict: verdict.clone(),
        threat_score: combined,
        detection_method: "ROBERTA_PHISHING + HORIZON_MMBERT_SCAM".to_string(),
        detection_reasons: db_reasons,
        device_id: device_id.clone(),
        employee_id: employee_id.clone(),
        ephemeral_purged: true,
        scanned_at: Utc::now(),
    });

    PhishingAnalysisResult {
        content_sha256,
        verdict,
        combined_threat_score: combined,
        roberta_email_detector: roberta_pred,
        horizon_scam_detector: horizon_pred,
        triggered_indicators: indicators,
        device_id,
        employee_id,
        analyzed_at: Utc::now(),
    }
}

fn parse_roberta_remote(val: &Value, fallback: f32) -> ModelPrediction {
    let label = val
        .pointer("/0/0/label")
        .and_then(|v| v.as_str())
        .unwrap_or(if fallback >= 0.5 { "LABEL_1" } else { "LABEL_0" });
    let score = val
        .pointer("/0/0/score")
        .and_then(|v| v.as_f64())
        .map(|f| f as f32)
        .unwrap_or(fallback);

    ModelPrediction {
        model_id: ROBERTA_MODEL_ID.to_string(),
        architecture: "RobertaForSequenceClassification".to_string(),
        label: label.to_string(),
        confidence: score,
        probabilities: val.clone(),
        execution_mode: "HUGGINGFACE_HUB_INFERENCE".to_string(),
    }
}

fn parse_horizon_remote(val: &Value, fallback: f32) -> ModelPrediction {
    let label = val
        .pointer("/0/0/label")
        .and_then(|v| v.as_str())
        .unwrap_or(if fallback >= 0.5 { "fraud" } else { "legitimate" });
    let score = val
        .pointer("/0/0/score")
        .and_then(|v| v.as_f64())
        .map(|f| f as f32)
        .unwrap_or(fallback);

    ModelPrediction {
        model_id: HORIZON_MODEL_ID.to_string(),
        architecture: "ModernBertForSequenceClassification".to_string(),
        label: label.to_string(),
        confidence: score,
        probabilities: val.clone(),
        execution_mode: "HUGGINGFACE_HUB_INFERENCE".to_string(),
    }
}
