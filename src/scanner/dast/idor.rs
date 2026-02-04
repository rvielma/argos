//! IDOR (Insecure Direct Object Reference) detection
//!
//! Detects IDOR by identifying numeric ID parameters and testing adjacent values.

use crate::http::HttpClient;
use crate::models::{Confidence, Finding, Severity};
use regex::Regex;
use tracing::debug;
use url::Url;

/// Parameter names commonly associated with IDOR
const IDOR_PARAM_PATTERNS: &[&str] = &[
    r"^id$",
    r"^user_?id$",
    r"^account_?id$",
    r"^order_?id$",
    r"^doc_?id$",
    r"^file_?id$",
    r"^record_?id$",
    r"^patient_?id$",
    r"^report_?id$",
    r"^invoice_?id$",
];

/// Checks a URL for IDOR vulnerabilities
pub async fn check_idor(client: &HttpClient, url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let parsed = match Url::parse(url) {
        Ok(u) => u,
        Err(_) => return findings,
    };

    let idor_regexes: Vec<Regex> = IDOR_PARAM_PATTERNS
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect();

    // Find numeric parameters that match IDOR patterns
    let mut idor_params: Vec<(String, i64)> = Vec::new();
    for (key, value) in parsed.query_pairs() {
        let lower_key = key.to_lowercase();
        let is_idor = idor_regexes.iter().any(|re| re.is_match(&lower_key));
        if !is_idor {
            continue;
        }

        if let Ok(num) = value.parse::<i64>() {
            idor_params.push((key.to_string(), num));
        }
    }

    if idor_params.is_empty() {
        return findings;
    }

    // Get baseline response with original ID
    let baseline = match client.get(url).await {
        Ok(response) => {
            let status = response.status().as_u16();
            if status != 200 {
                return findings;
            }
            response.text().await.unwrap_or_default()
        }
        Err(_) => return findings,
    };

    if baseline.len() < 100 {
        return findings;
    }

    // Try adjacent IDs
    for (param, original_id) in &idor_params {
        let test_ids: Vec<i64> = vec![
            original_id + 1,
            original_id - 1,
            original_id + 2,
            original_id - 2,
        ];

        for test_id in test_ids {
            if test_id < 0 {
                continue;
            }

            let test_url = build_url_with_param(url, param, &test_id.to_string());
            let test_url = match test_url {
                Some(u) => u,
                None => continue,
            };

            match client.get(&test_url).await {
                Ok(response) => {
                    let status = response.status().as_u16();
                    if status != 200 {
                        continue;
                    }

                    let body = response.text().await.unwrap_or_default();

                    // Body must be different from baseline and substantial
                    if body.len() < 100 {
                        continue;
                    }

                    let similarity = calculate_similarity(&baseline, &body);

                    // Different content (not identical, but the request succeeded)
                    // Very similar means probably same template, different data = IDOR
                    if similarity < 0.95 && similarity > 0.3 {
                        debug!(
                            "IDOR detected: {}={} returned different content (similarity: {:.2})",
                            param, test_id, similarity
                        );

                        let finding = Finding::new(
                            "Insecure Direct Object Reference (IDOR)",
                            format!(
                                "Changing parameter {}={} to {} returned different content, \
                                 suggesting unauthorized access to another user's data.",
                                param, original_id, test_id
                            ),
                            Severity::High,
                            "IDOR",
                            url,
                        )
                        .with_confidence(Confidence::Tentative)
                        .with_evidence(format!(
                            "Original ({}={}): {} bytes, Test ({}={}): {} bytes, Similarity: {:.2}",
                            param,
                            original_id,
                            baseline.len(),
                            param,
                            test_id,
                            body.len(),
                            similarity
                        ))
                        .with_recommendation(
                            "Implement proper authorization checks. Verify that the \
                             authenticated user has permission to access the requested resource.",
                        )
                        .with_cwe("CWE-639")
                        .with_owasp("A01:2021 Broken Access Control");

                        findings.push(finding);
                        return findings; // One IDOR finding per URL is enough
                    }
                }
                Err(e) => {
                    debug!("IDOR check request failed: {}", e);
                }
            }
        }
    }

    findings
}

/// Builds a URL replacing a specific query parameter value
fn build_url_with_param(url: &str, param: &str, new_value: &str) -> Option<String> {
    let mut parsed = Url::parse(url).ok()?;
    let pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .map(|(k, v)| {
            if k == param {
                (k.to_string(), new_value.to_string())
            } else {
                (k.to_string(), v.to_string())
            }
        })
        .collect();

    parsed.set_query(None);
    let query: Vec<String> = pairs.iter().map(|(k, v)| format!("{k}={v}")).collect();
    if !query.is_empty() {
        parsed.set_query(Some(&query.join("&")));
    }
    Some(parsed.to_string())
}

/// Simple similarity ratio between two strings (Jaccard-like on words)
fn calculate_similarity(a: &str, b: &str) -> f64 {
    let words_a: std::collections::HashSet<&str> = a.split_whitespace().collect();
    let words_b: std::collections::HashSet<&str> = b.split_whitespace().collect();

    if words_a.is_empty() && words_b.is_empty() {
        return 1.0;
    }

    let intersection = words_a.intersection(&words_b).count();
    let union = words_a.union(&words_b).count();

    if union == 0 {
        return 0.0;
    }

    intersection as f64 / union as f64
}
