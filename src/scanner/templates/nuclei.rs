//! Nuclei template compatibility parser
//!
//! Converts basic Nuclei-format YAML templates into Argos CveTemplate format.
//! Supports: id, info, http protocol with word/status/regex matchers.
//! Does NOT support: extractors, workflows, code/dns/tcp protocols, variables.

use super::loader::{CveTemplate, TemplateMatcher, TemplateRequest};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use tracing::{info, warn};

/// Top-level Nuclei template structure
#[derive(Debug, Deserialize)]
struct NucleiTemplate {
    id: String,
    info: NucleiInfo,
    #[serde(default)]
    http: Option<Vec<NucleiHttpRequest>>,
    /// Nuclei v3 uses 'requests' instead of 'http' sometimes
    #[serde(default)]
    requests: Option<Vec<NucleiHttpRequest>>,
}

/// Nuclei info block
#[derive(Debug, Deserialize)]
struct NucleiInfo {
    name: String,
    #[serde(default = "default_severity")]
    severity: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    reference: Option<NucleiReference>,
    #[serde(default)]
    tags: Option<String>,
}

fn default_severity() -> String {
    "info".to_string()
}

/// Nuclei reference can be a string or list
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum NucleiReference {
    Single(String),
    List(Vec<String>),
}

impl NucleiReference {
    fn first(&self) -> Option<&str> {
        match self {
            NucleiReference::Single(s) => Some(s.as_str()),
            NucleiReference::List(v) => v.first().map(|s| s.as_str()),
        }
    }
}

/// Nuclei HTTP request block
#[derive(Debug, Deserialize)]
struct NucleiHttpRequest {
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    path: Option<Vec<String>>,
    #[serde(default)]
    headers: Option<HashMap<String, String>>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    matchers: Option<Vec<NucleiMatcher>>,
    #[serde(default = "default_condition")]
    #[serde(rename = "matchers-condition")]
    matchers_condition: String,
}

fn default_condition() -> String {
    "or".to_string()
}

/// Nuclei matcher
#[derive(Debug, Deserialize)]
struct NucleiMatcher {
    #[serde(rename = "type")]
    matcher_type: String,
    #[serde(default)]
    words: Option<Vec<String>>,
    #[serde(default)]
    status: Option<Vec<u16>>,
    #[serde(default)]
    regex: Option<Vec<String>>,
    #[serde(default)]
    part: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    condition: Option<String>,
}

/// Loads Nuclei-format templates from a directory and converts to CveTemplate
pub fn load_nuclei_templates(dir: &Path) -> Vec<CveTemplate> {
    let mut templates = Vec::new();

    if !dir.exists() {
        warn!("Nuclei templates directory does not exist: {}", dir.display());
        return templates;
    }

    load_nuclei_dir(dir, &mut templates);
    info!("Loaded {} Nuclei-compatible templates", templates.len());
    templates
}

fn load_nuclei_dir(dir: &Path, templates: &mut Vec<CveTemplate>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            warn!("Failed to read Nuclei templates dir {}: {}", dir.display(), e);
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            load_nuclei_dir(&path, templates);
        } else if path.extension().and_then(|e| e.to_str()) == Some("yaml")
            || path.extension().and_then(|e| e.to_str()) == Some("yml")
        {
            match load_nuclei_template(&path) {
                Ok(tmpl) => templates.push(tmpl),
                Err(e) => {
                    tracing::debug!("Skipping Nuclei template {}: {}", path.display(), e);
                }
            }
        }
    }
}

/// Converts a single Nuclei YAML file to CveTemplate
fn load_nuclei_template(path: &Path) -> std::result::Result<CveTemplate, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("IO error: {e}"))?;

    let nuclei: NucleiTemplate = serde_yaml::from_str(&content)
        .map_err(|e| format!("YAML parse error: {e}"))?;

    // Get HTTP requests (Nuclei uses either 'http' or 'requests')
    let http_requests = nuclei.http
        .or(nuclei.requests)
        .ok_or("No HTTP requests defined (dns/tcp/code protocols not supported)")?;

    if http_requests.is_empty() {
        return Err("Empty HTTP requests".to_string());
    }

    let mut requests = Vec::new();

    for nuclei_req in &http_requests {
        let method = nuclei_req.method.clone().unwrap_or_else(|| "GET".to_string());
        let paths = nuclei_req.path.clone().unwrap_or_else(|| vec!["/".to_string()]);

        // Convert Nuclei matchers
        let mut matchers = Vec::new();
        if let Some(ref nuclei_matchers) = nuclei_req.matchers {
            for nm in nuclei_matchers {
                let matcher = convert_matcher(nm)?;
                matchers.push(matcher);
            }
        }

        if matchers.is_empty() {
            return Err("No matchers defined".to_string());
        }

        // Create a request for each path
        for req_path in &paths {
            // Nuclei uses {{BaseURL}} placeholder — we strip it
            let clean_path = req_path
                .replace("{{BaseURL}}", "")
                .replace("{{RootURL}}", "");
            let clean_path = if clean_path.is_empty() { "/".to_string() } else { clean_path };

            requests.push(TemplateRequest {
                method: method.to_uppercase(),
                path: clean_path,
                headers: nuclei_req.headers.clone().unwrap_or_default(),
                body: nuclei_req.body.clone(),
                matchers: matchers.clone(),
                condition: nuclei_req.matchers_condition.clone(),
                extractors: Vec::new(),
                stop_at_first_match: false,
            });
        }
    }

    if requests.is_empty() {
        return Err("No valid requests generated".to_string());
    }

    // Map Nuclei severity to Argos severity
    let severity = match nuclei.info.severity.to_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        _ => "info",
    };

    // Parse tags
    let tags: Vec<String> = nuclei.info.tags
        .unwrap_or_default()
        .split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();

    let reference = nuclei.info.reference
        .as_ref()
        .and_then(|r| r.first())
        .map(|s| s.to_string());

    Ok(CveTemplate {
        id: nuclei.id,
        name: nuclei.info.name,
        severity: severity.to_string(),
        confidence: "tentative".to_string(),
        description: nuclei.info.description,
        reference,
        requests,
        tags,
        variables: HashMap::new(),
        category: "Nuclei".to_string(),
    })
}

/// Converts a Nuclei matcher to an Argos TemplateMatcher
fn convert_matcher(nm: &NucleiMatcher) -> std::result::Result<TemplateMatcher, String> {
    match nm.matcher_type.as_str() {
        "word" => {
            let words = nm.words.clone()
                .ok_or("Word matcher missing 'words' field")?;
            let part = nm.part.clone().unwrap_or_else(|| "body".to_string());
            let header = if part == "header" { Some("".to_string()) } else { None };

            Ok(TemplateMatcher {
                matcher_type: "word".to_string(),
                status: None,
                words: Some(words),
                regex: None,
                header,
                duration: None,
                variable: None,
                version_range: None,
            })
        }
        "status" => {
            let status = nm.status.clone()
                .ok_or("Status matcher missing 'status' field")?;

            Ok(TemplateMatcher {
                matcher_type: "status".to_string(),
                status: Some(status),
                words: None,
                regex: None,
                header: None,
                duration: None,
                variable: None,
                version_range: None,
            })
        }
        "regex" => {
            let regex = nm.regex.clone()
                .ok_or("Regex matcher missing 'regex' field")?;

            Ok(TemplateMatcher {
                matcher_type: "regex".to_string(),
                status: None,
                words: None,
                regex: Some(regex),
                header: None,
                duration: None,
                variable: None,
                version_range: None,
            })
        }
        other => Err(format!("Unsupported matcher type: {other}")),
    }
}
