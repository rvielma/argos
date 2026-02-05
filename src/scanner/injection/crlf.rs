//! CRLF Injection detection

use crate::http::HttpClient;
use crate::models::{Finding, Severity};
use std::collections::HashMap;

use super::BaselineResponse;
use super::InjectionPoint;
use super::InjectionScanner;

/// CRLF injection payloads — each attempts to inject a custom header
const CRLF_PAYLOADS: &[&str] = &[
    "%0d%0aX-Injected:%20argos",
    "%0aX-Injected:%20argos",
    "%0d%0aSet-Cookie:%20argos=injected",
    "\r\nX-Injected: argos",
    "%E5%98%8A%E5%98%8DX-Injected:%20argos",
];

/// Scans for CRLF injection vulnerabilities
pub async fn scan(
    client: &HttpClient,
    points: &[InjectionPoint],
    _baselines: &HashMap<(String, String), BaselineResponse>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for point in points.iter().take(10) {
        for param in &point.params {
            'crlf: for payload in CRLF_PAYLOADS {
                if let Some(test_url) =
                    InjectionScanner::build_test_url(&point.url, param, payload)
                {
                    if let Ok(resp) = client.get(&test_url).await {
                        let has_injected_header = resp
                            .headers()
                            .get("x-injected")
                            .and_then(|v| v.to_str().ok())
                            .map(|v| v.contains("argos"))
                            .unwrap_or(false);

                        let has_set_cookie = resp
                            .headers()
                            .get("set-cookie")
                            .and_then(|v| v.to_str().ok())
                            .map(|v| v.contains("argos=injected"))
                            .unwrap_or(false);

                        let _ = resp.text().await;

                        if has_injected_header || has_set_cookie {
                            let severity = if has_set_cookie {
                                Severity::High
                            } else {
                                Severity::Medium
                            };

                            let detail = if has_set_cookie {
                                "Set-Cookie header injection (session fixation risk)"
                            } else {
                                "Custom header injection"
                            };

                            findings.push(
                                Finding::new(
                                    format!("CRLF Injection in '{param}'"),
                                    format!(
                                        "Parameter '{param}' is vulnerable to CRLF injection allowing HTTP response header manipulation. {detail}."
                                    ),
                                    severity,
                                    "CRLF Injection",
                                    &point.url,
                                )
                                .with_evidence(format!(
                                    "Param: {param}\nPayload: {payload}\nDetected: {detail}"
                                ))
                                .with_request(format!("GET {test_url}"))
                                .with_recommendation(
                                    "Strip or encode CRLF characters (\\r\\n) from user input before including it in HTTP headers.",
                                )
                                .with_cwe("CWE-93")
                                .with_owasp("A03:2021 Injection"),
                            );
                            break 'crlf;
                        }
                    }
                }
            }
        }
    }

    findings
}
