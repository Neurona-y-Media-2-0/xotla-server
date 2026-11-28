use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct PhishingAnalyzeRequest {
    pub text: String,
    pub subject: Option<String>,
    pub sender: Option<String>,
    pub url: Option<String>,
    pub device_id: Option<String>,
    pub employee_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPrediction {
    pub model_id: String,
    pub architecture: String,
    pub label: String,
    pub confidence: f32,
    pub probabilities: serde_json::Value,
    pub execution_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishingAnalysisResult {
    pub content_sha256: String,
    pub verdict: String,
    pub combined_threat_score: f32,
    pub roberta_email_detector: ModelPrediction,
    pub horizon_scam_detector: ModelPrediction,
    pub triggered_indicators: Vec<String>,
    pub device_id: String,
    pub employee_id: String,
    pub analyzed_at: DateTime<Utc>,
}
