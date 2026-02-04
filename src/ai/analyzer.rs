//! AI-powered vulnerability analysis using Ollama
//!
//! Stub for future integration with Ollama for intelligent analysis.
//! When implemented, it will analyze findings, identify attack chains,
//! and prioritize remediation.

use crate::error::Result;
use crate::models::Finding;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::info;

/// AI-generated insight about scan findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiInsight {
    /// Natural language summary of the risk
    pub summary: String,
    /// Risk score from 1-10
    pub risk_score: u8,
    /// Description of potential attack chains
    pub attack_chain: String,
    /// Suggested remediation priority order
    pub remediation_priority: Vec<String>,
}

/// Trait for AI analysis backends
#[async_trait]
pub trait AiAnalyzer: Send + Sync {
    /// Analyzes findings and returns AI-generated insights
    async fn analyze_findings(&self, findings: &[Finding]) -> Result<Vec<AiInsight>>;

    /// Returns whether the analyzer is available and configured
    fn is_available(&self) -> bool;
}

/// Ollama-based AI analyzer for local LLM analysis
pub struct OllamaAnalyzer {
    endpoint: String,
    model: String,
    enabled: bool,
}

impl OllamaAnalyzer {
    /// Creates a new OllamaAnalyzer
    pub fn new(endpoint: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            model: model.into(),
            enabled: false,
        }
    }

    /// Creates a disabled analyzer (default)
    pub fn disabled() -> Self {
        Self {
            endpoint: "http://localhost:11434".to_string(),
            model: "llama3".to_string(),
            enabled: false,
        }
    }
}

#[async_trait]
impl AiAnalyzer for OllamaAnalyzer {
    async fn analyze_findings(&self, findings: &[Finding]) -> Result<Vec<AiInsight>> {
        if !self.enabled {
            info!(
                "AI module not configured. Enable in config.toml with Ollama at {}",
                self.endpoint
            );
            return Ok(vec![AiInsight {
                summary: "AI module not configured. Enable Ollama integration in config.toml."
                    .to_string(),
                risk_score: 0,
                attack_chain: "N/A - AI module disabled".to_string(),
                remediation_priority: vec!["Configure AI module for automated analysis".to_string()],
            }]);
        }

        // TODO: POST to {endpoint}/api/generate with model and prompt
        // containing findings summary, parse structured response
        info!(
            "AI analysis would use model '{}' at '{}' for {} findings",
            self.model,
            self.endpoint,
            findings.len()
        );

        Ok(Vec::new())
    }

    fn is_available(&self) -> bool {
        self.enabled
    }
}
