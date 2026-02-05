//! Open Redirect detection

use crate::http::HttpClient;
use crate::models::{Finding, Severity};
use std::collections::HashMap;

use super::BaselineResponse;
use super::InjectionPoint;
use super::InjectionScanner;

/// Payloads that attempt to redirect to an external domain
const REDIRECT_PAYLOADS: &[&str] = &[
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com%00",
    "//evil.com/%2f..",
    "https:///evil.com",
    "//%2Fevil.com",
];

/// Scans for open redirect vulnerabilities
pub async fn scan(
    client: &HttpClient,
    points: &[InjectionPoint],
    _baselines: &HashMap<(String, String), BaselineResponse>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for point in points.iter().take(10) {
        for param in &point.params {
            // Only test params that look like redirect/url targets
            let param_lower = param.to_lowercase();
            let is_redirect_param = param_lower.contains("url")
                || param_lower.contains("redirect")
                || param_lower.contains("next")
                || param_lower.contains("return")
                || param_lower.contains("goto")
                || param_lower.contains("dest")
                || param_lower.contains("target")
                || param_lower.contains("rurl")
                || param_lower.contains("continue")
                || param_lower.contains("link");

            if !is_redirect_param {
                continue;
            }

            'redirect: for payload in REDIRECT_PAYLOADS {
                if let Some(test_url) =
                    InjectionScanner::build_test_url(&point.url, param, payload)
                {
                    // Use a client that doesn't follow redirects for this check
                    if let Ok(resp) = client
                        .request(
                            reqwest::Method::GET,
                            &test_url,
                            &[],
                            None,
                        )
                        .await
                    {
                        let status = resp.status().as_u16();
                        let location = resp
                            .headers()
                            .get("location")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        let body = resp.text().await.unwrap_or_default();

                        // Check 3xx redirect to evil.com
                        let is_redirect = (300..400).contains(&status)
                            && location.contains("evil.com");

                        // Check meta refresh redirect
                        let meta_redirect = body.contains("http-equiv=\"refresh\"")
                            && body.contains("evil.com");

                        // Check JS redirect patterns
                        let js_redirect = (body.contains("window.location")
                            || body.contains("document.location")
                            || body.contains("location.href"))
                            && body.contains("evil.com");

                        if is_redirect || meta_redirect || js_redirect {
                            let method = if is_redirect {
                                "HTTP 3xx redirect"
                            } else if meta_redirect {
                                "Meta refresh redirect"
                            } else {
                                "JavaScript redirect"
                            };

                            findings.push(
                                Finding::new(
                                    format!("Open Redirect in '{param}'"),
                                    format!(
                                        "Parameter '{param}' allows redirecting users to arbitrary external URLs via {method}."
                                    ),
                                    Severity::Medium,
                                    "Open Redirect",
                                    &point.url,
                                )
                                .with_evidence(format!(
                                    "Param: {param}\nPayload: {payload}\nMethod: {method}\nLocation: {location}"
                                ))
                                .with_request(format!("GET {test_url}"))
                                .with_recommendation(
                                    "Validate redirect URLs against an allowlist of permitted domains. Avoid using user input directly in redirect targets.",
                                )
                                .with_cwe("CWE-601")
                                .with_owasp("A01:2021 Broken Access Control"),
                            );
                            break 'redirect;
                        }
                    }
                }
            }
        }
    }

    findings
}
