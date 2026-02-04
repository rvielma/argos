//! Template execution engine

use crate::http::HttpClient;
use crate::models::{Confidence, Finding, Severity};
use regex::Regex;
use std::collections::HashMap;
use std::time::Instant;
use tracing::debug;

use super::loader::{CveTemplate, TemplateExtractor};
use super::matcher;

/// Executes a CVE template against a target URL.
/// Supports multi-step requests with variable interpolation and extractors.
/// ALL requests in a template must match for a finding to be generated.
pub async fn execute_template(
    client: &HttpClient,
    base_url: &str,
    template: &CveTemplate,
) -> Vec<Finding> {
    let base = base_url.trim_end_matches('/');

    // Initialize variables from template defaults
    let mut variables: HashMap<String, String> = template.variables.clone();

    let mut all_matched = true;
    let mut combined_evidence = Vec::new();
    let mut last_url = String::new();
    let mut last_method = String::new();

    for request in &template.requests {
        let path = interpolate_variables(&request.path, &variables);
        let url = format!("{}/{}", base, path.trim_start_matches('/'));

        let start = Instant::now();

        // Interpolate headers
        let mut req_headers: HashMap<String, String> = HashMap::new();
        for (k, v) in &request.headers {
            req_headers.insert(k.clone(), interpolate_variables(v, &variables));
        }

        // Interpolate body
        let body = request
            .body
            .as_ref()
            .map(|b| interpolate_variables(b, &variables));

        let response =
            execute_request(client, &request.method, &url, &req_headers, body.as_deref()).await;

        let elapsed = start.elapsed().as_secs_f64();

        match response {
            Ok((status_code, resp_headers, resp_body)) => {
                // Run extractors to capture values
                for extractor in &request.extractors {
                    if let Some(value) = run_extractor(extractor, &resp_body, &resp_headers) {
                        debug!(
                            "Template {}: extracted {} = {}",
                            template.id, extractor.name, value
                        );
                        variables.insert(extractor.name.clone(), value);
                    }
                }

                // Evaluate matchers (standard + version)
                let mut result = matcher::evaluate_matchers(
                    &request.matchers,
                    &request.condition,
                    status_code,
                    &resp_body,
                    &resp_headers,
                    elapsed,
                );

                // Evaluate version matchers separately (they need access to variables)
                for m in &request.matchers {
                    if m.matcher_type == "version" {
                        let ver_result =
                            matcher::evaluate_version_matcher(m, &variables);
                        if !ver_result.matched {
                            result.matched = false;
                        }
                        if !ver_result.evidence.is_empty() {
                            result.evidence =
                                format!("{}; {}", result.evidence, ver_result.evidence);
                        }
                    }
                }

                if result.matched {
                    combined_evidence.push(result.evidence);
                    last_url = url;
                    last_method = request.method.to_uppercase();

                    // stop_at_first_match: generate finding immediately on first match
                    if request.stop_at_first_match {
                        let severity = parse_severity(&template.severity);
                        let confidence = parse_confidence(&template.confidence);
                        let finding = Finding::new(
                            format!("{}: {}", template.id, template.name),
                            template.description.as_deref().unwrap_or(&template.name),
                            severity,
                            "CVE Templates",
                            &last_url,
                        )
                        .with_confidence(confidence)
                        .with_evidence(combined_evidence.join("; "))
                        .with_request(format!("{} {}", last_method, last_url))
                        .with_recommendation(format!(
                            "Investigate {} and apply vendor patches.",
                            template.id
                        ))
                        .with_cwe(template.reference.as_deref().unwrap_or("CWE-0"))
                        .with_owasp("A06:2021 Vulnerable and Outdated Components");
                        return vec![finding];
                    }
                } else {
                    // Any request that doesn't match means the template fails
                    all_matched = false;
                    break;
                }
            }
            Err(e) => {
                debug!("Template {} request to {} failed: {}", template.id, url, e);
                all_matched = false;
                break;
            }
        }
    }

    // Only generate finding if ALL requests matched
    if all_matched && !combined_evidence.is_empty() {
        let severity = parse_severity(&template.severity);
        let confidence = parse_confidence(&template.confidence);
        let finding = Finding::new(
            format!("{}: {}", template.id, template.name),
            template.description.as_deref().unwrap_or(&template.name),
            severity,
            "CVE Templates",
            &last_url,
        )
        .with_confidence(confidence)
        .with_evidence(combined_evidence.join("; "))
        .with_request(format!("{} {}", last_method, last_url))
        .with_recommendation(format!(
            "Investigate {} and apply vendor patches.",
            template.id
        ))
        .with_cwe(template.reference.as_deref().unwrap_or("CWE-0"))
        .with_owasp("A06:2021 Vulnerable and Outdated Components");

        return vec![finding];
    }

    Vec::new()
}

/// Execute an HTTP request and return (status, headers, body)
async fn execute_request(
    client: &HttpClient,
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: Option<&str>,
) -> std::result::Result<(u16, Vec<(String, String)>, String), crate::error::ArgosError> {
    let reqwest_method = match method.to_uppercase().as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "PATCH" => reqwest::Method::PATCH,
        "HEAD" => reqwest::Method::HEAD,
        "OPTIONS" => reqwest::Method::OPTIONS,
        other => {
            debug!("Unsupported method '{}', skipping", other);
            return Err(crate::error::ArgosError::ScanError(format!(
                "Unsupported HTTP method: {}",
                other
            )));
        }
    };

    let header_vec: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let response = client
        .request(reqwest_method, url, &header_vec, body)
        .await?;

    let status_code = response.status().as_u16();
    let resp_headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let resp_body = response.text().await.unwrap_or_default();

    Ok((status_code, resp_headers, resp_body))
}

/// Interpolate {{variable}} placeholders in a string
fn interpolate_variables(input: &str, variables: &HashMap<String, String>) -> String {
    let mut result = input.to_string();
    for (name, value) in variables {
        let placeholder = format!("{{{{{}}}}}", name);
        result = result.replace(&placeholder, value);
    }
    result
}

/// Run an extractor against a response, returning the captured value
fn run_extractor(
    extractor: &TemplateExtractor,
    body: &str,
    headers: &[(String, String)],
) -> Option<String> {
    match extractor.extractor_type.as_str() {
        "regex" => run_regex_extractor(extractor, body),
        "header" => run_header_extractor(extractor, headers),
        "json" => run_json_extractor(extractor, body),
        _ => {
            debug!("Unknown extractor type: {}", extractor.extractor_type);
            None
        }
    }
}

/// Extract a value using regex capture group
fn run_regex_extractor(extractor: &TemplateExtractor, body: &str) -> Option<String> {
    let pattern = extractor.regex.as_ref()?;
    let re = Regex::new(pattern).ok()?;
    let captures = re.captures(body)?;
    let group = extractor.group.unwrap_or(0);
    captures.get(group).map(|m| m.as_str().to_string())
}

/// Extract a value from a response header
fn run_header_extractor(
    extractor: &TemplateExtractor,
    headers: &[(String, String)],
) -> Option<String> {
    let header_name = extractor.header.as_ref()?;
    for (name, value) in headers {
        if name.to_lowercase() == header_name.to_lowercase() {
            return Some(value.clone());
        }
    }
    None
}

/// Extract a value using a simple JSON path (dot notation)
fn run_json_extractor(extractor: &TemplateExtractor, body: &str) -> Option<String> {
    let json_path = extractor.json_path.as_ref()?;
    let value: serde_json::Value = serde_json::from_str(body).ok()?;

    let mut current = &value;
    for key in json_path.split('.') {
        // Handle array indices like "items[0]"
        if let Some(bracket_pos) = key.find('[') {
            let field = &key[..bracket_pos];
            let idx_str = &key[bracket_pos + 1..key.len() - 1];

            if !field.is_empty() {
                current = current.get(field)?;
            }
            let idx: usize = idx_str.parse().ok()?;
            current = current.get(idx)?;
        } else {
            current = current.get(key)?;
        }
    }

    match current {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Null => None,
        other => Some(other.to_string()),
    }
}

/// Evaluates a single-request template against a pre-fetched response.
/// Used by template clustering to avoid redundant HTTP requests.
pub fn evaluate_template_against_response(
    template: &super::loader::CveTemplate,
    status_code: u16,
    headers: &[(String, String)],
    body: &str,
    url: &str,
) -> Vec<Finding> {
    if template.requests.len() != 1 {
        return Vec::new();
    }

    let request = &template.requests[0];
    let result = matcher::evaluate_matchers(
        &request.matchers,
        &request.condition,
        status_code,
        body,
        headers,
        0.0,
    );

    if result.matched {
        let severity = parse_severity(&template.severity);
        let confidence = parse_confidence(&template.confidence);
        let finding = Finding::new(
            format!("{}: {}", template.id, template.name),
            template.description.as_deref().unwrap_or(&template.name),
            severity,
            "CVE Templates",
            url,
        )
        .with_confidence(confidence)
        .with_evidence(result.evidence)
        .with_request(format!("{} {}", request.method.to_uppercase(), url))
        .with_recommendation(format!(
            "Investigate {} and apply vendor patches.",
            template.id
        ))
        .with_cwe(template.reference.as_deref().unwrap_or("CWE-0"))
        .with_owasp("A06:2021 Vulnerable and Outdated Components");
        return vec![finding];
    }

    Vec::new()
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

fn parse_confidence(s: &str) -> Confidence {
    match s.to_lowercase().as_str() {
        "confirmed" => Confidence::Confirmed,
        "informational" => Confidence::Informational,
        _ => Confidence::Tentative,
    }
}
