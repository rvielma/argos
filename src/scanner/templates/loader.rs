//! YAML template loader for CVE detection

use crate::error::{ArgosError, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use tracing::{info, warn};

/// A CVE detection template
#[derive(Debug, Clone, Deserialize)]
pub struct CveTemplate {
    pub id: String,
    pub name: String,
    pub severity: String,
    /// Confidence level: "confirmed", "tentative", "informational"
    #[serde(default = "default_confidence")]
    pub confidence: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub reference: Option<String>,
    pub requests: Vec<TemplateRequest>,
    /// Classification tags for the template
    #[serde(default)]
    pub tags: Vec<String>,
    /// Initial variables for interpolation
    #[serde(default)]
    pub variables: HashMap<String, String>,
}

fn default_confidence() -> String {
    "tentative".to_string()
}

/// A request within a CVE template
#[derive(Debug, Clone, Deserialize)]
pub struct TemplateRequest {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    pub matchers: Vec<TemplateMatcher>,
    /// How to combine matchers: "and" (all must match) or "or" (any must match)
    #[serde(default = "default_condition")]
    pub condition: String,
    /// Extractors to capture values from the response
    #[serde(default)]
    pub extractors: Vec<TemplateExtractor>,
    /// If true, generate a finding and stop after this request matches
    #[serde(default)]
    pub stop_at_first_match: bool,
}

/// A matcher that evaluates the response
#[derive(Debug, Clone, Deserialize)]
pub struct TemplateMatcher {
    #[serde(rename = "type")]
    pub matcher_type: String,
    #[serde(default)]
    pub status: Option<Vec<u16>>,
    #[serde(default)]
    pub words: Option<Vec<String>>,
    #[serde(default)]
    pub regex: Option<Vec<String>>,
    #[serde(default)]
    pub header: Option<String>,
    /// For response time matchers (in seconds)
    #[serde(default)]
    pub duration: Option<f64>,
    /// Variable name for version comparison
    #[serde(default)]
    pub variable: Option<String>,
    /// Version range for comparison (e.g., "< 2.4.51", ">= 8.0 < 8.5.78")
    #[serde(default)]
    pub version_range: Option<String>,
}

/// Extractor to capture values from HTTP responses
#[derive(Debug, Clone, Deserialize)]
pub struct TemplateExtractor {
    /// Extractor type: "regex", "header", "json"
    #[serde(rename = "type")]
    pub extractor_type: String,
    /// Variable name to store the extracted value
    pub name: String,
    /// Regex pattern (for regex type)
    #[serde(default)]
    pub regex: Option<String>,
    /// Capture group index (for regex type, default 0)
    #[serde(default)]
    pub group: Option<usize>,
    /// Header name to extract from (for header type)
    #[serde(default)]
    pub header: Option<String>,
    /// JSON path expression (for json type, simple dot notation)
    #[serde(default)]
    pub json_path: Option<String>,
}

fn default_condition() -> String {
    "and".to_string()
}

/// Validates a template for correctness
pub fn validate_template(template: &CveTemplate) -> std::result::Result<(), String> {
    if template.id.is_empty() {
        return Err("Template id is empty".to_string());
    }
    if template.name.is_empty() {
        return Err("Template name is empty".to_string());
    }
    if template.requests.is_empty() {
        return Err("Template has no requests".to_string());
    }

    let valid_severities = ["critical", "high", "medium", "low", "info"];
    if !valid_severities.contains(&template.severity.to_lowercase().as_str()) {
        return Err(format!("Invalid severity: {}", template.severity));
    }

    for (i, request) in template.requests.iter().enumerate() {
        let valid_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
        if !valid_methods.contains(&request.method.to_uppercase().as_str()) {
            return Err(format!(
                "Request {} has invalid method: {}",
                i, request.method
            ));
        }

        for extractor in &request.extractors {
            match extractor.extractor_type.as_str() {
                "regex" => {
                    if extractor.regex.is_none() {
                        return Err(format!(
                            "Regex extractor '{}' in request {} missing regex field",
                            extractor.name, i
                        ));
                    }
                }
                "header" => {
                    if extractor.header.is_none() {
                        return Err(format!(
                            "Header extractor '{}' in request {} missing header field",
                            extractor.name, i
                        ));
                    }
                }
                "json" => {
                    if extractor.json_path.is_none() {
                        return Err(format!(
                            "JSON extractor '{}' in request {} missing json_path field",
                            extractor.name, i
                        ));
                    }
                }
                other => {
                    return Err(format!(
                        "Unknown extractor type '{}' for '{}' in request {}",
                        other, extractor.name, i
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Loads all CVE templates from a directory
pub fn load_templates(dir: &Path) -> Result<Vec<CveTemplate>> {
    let mut templates = Vec::new();

    if !dir.exists() {
        warn!("Templates directory does not exist: {}", dir.display());
        return Ok(templates);
    }

    let entries = std::fs::read_dir(dir).map_err(ArgosError::IoError)?;

    for entry in entries {
        let entry = entry.map_err(ArgosError::IoError)?;
        let path = entry.path();

        if path.extension().and_then(|e| e.to_str()) == Some("yaml")
            || path.extension().and_then(|e| e.to_str()) == Some("yml")
        {
            match load_template(&path) {
                Ok(template) => {
                    info!("Loaded template: {} ({})", template.id, template.name);
                    templates.push(template);
                }
                Err(e) => {
                    warn!("Failed to load template {}: {}", path.display(), e);
                }
            }
        }
    }

    info!("Loaded {} CVE templates", templates.len());
    Ok(templates)
}

/// Loads a single template from a YAML file
fn load_template(path: &Path) -> Result<CveTemplate> {
    let content = std::fs::read_to_string(path).map_err(ArgosError::IoError)?;
    let template: CveTemplate = serde_yaml::from_str(&content)?;

    // Validate the template
    if let Err(msg) = validate_template(&template) {
        return Err(ArgosError::TemplateValidationError(
            path.display().to_string(),
            msg,
        ));
    }

    Ok(template)
}
