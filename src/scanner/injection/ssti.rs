//! Server-Side Template Injection detection

use crate::http::HttpClient;
use crate::models::{Finding, Severity};
use std::collections::HashMap;

use super::BaselineResponse;
use super::InjectionPoint;
use super::InjectionScanner;

/// Expected responses for template injection payloads
const SSTI_CHECKS: &[(&str, &str)] = &[
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("#{7*7}", "49"),
    ("{{7*'7'}}", "7777777"),
];

/// Scans for Server-Side Template Injection vulnerabilities
pub async fn scan(
    client: &HttpClient,
    points: &[InjectionPoint],
    baselines: &HashMap<(String, String), BaselineResponse>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let extra_payloads = InjectionScanner::load_payloads(
        "wordlists/payloads/ssti.txt",
        vec![
            "{{7*7}}".to_string(),
            "${7*7}".to_string(),
            "<%= 7*7 %>".to_string(),
        ],
    );

    for point in points.iter().take(10) {
        for param in &point.params {
            let baseline = baselines.get(&(point.url.clone(), param.clone()));

            // Check known payload/response pairs first
            'ssti: for (payload, expected) in SSTI_CHECKS {
                // If the expected result already exists in the baseline, skip this check
                // (e.g., "49" appears naturally in almost any HTML page)
                if let Some(bl) = baseline {
                    if bl.body.contains(expected) {
                        continue;
                    }
                }

                if let Some(test_url) = InjectionScanner::build_test_url(&point.url, param, payload)
                {
                    if let Ok(resp) = client.get(&test_url).await {
                        let resp_body = resp.text().await.unwrap_or_default();
                        if resp_body.contains(expected) && !resp_body.contains(payload) {
                            // Anti-FP: if response body length is very similar to baseline,
                            // the server ignored our input (e.g., endpoints with dynamic numbers)
                            if let Some(bl) = baseline {
                                let bl_diff = (bl.body.len() as i64 - resp_body.len() as i64).unsigned_abs();
                                if bl_diff < 100 {
                                    continue;
                                }
                            }
                            findings.push(
                                Finding::new(
                                    format!("Server-Side Template Injection in '{param}'"),
                                    format!(
                                        "Parameter '{param}' is vulnerable to SSTI. Template expression was evaluated."
                                    ),
                                    Severity::Critical,
                                    "Injection",
                                    &point.url,
                                )
                                .with_evidence(format!(
                                    "Param: {param}\nPayload: {payload}\nExpected: {expected}\nPayload was evaluated server-side"
                                ))
                                .with_request(format!("GET {test_url}"))
                                .with_recommendation(
                                    "Never pass user input directly to template engines. Use sandboxed templates.",
                                )
                                .with_cwe("CWE-1336")
                                .with_owasp("A03:2021 Injection"),
                            );
                            break 'ssti;
                        }
                    }
                }
            }

            // Check additional payloads for config/class leaks
            for payload in extra_payloads.iter().take(5) {
                if SSTI_CHECKS.iter().any(|(p, _)| p == payload) {
                    continue;
                }

                if let Some(test_url) = InjectionScanner::build_test_url(&point.url, param, payload)
                {
                    if let Ok(resp) = client.get(&test_url).await {
                        let resp_body = resp.text().await.unwrap_or_default();
                        let leak_indicators = [
                            "SECRET_KEY",
                            "__class__",
                            "__mro__",
                            "java.lang.Runtime",
                            "__globals__",
                            "__subclasses__",
                        ];

                        // Only flag if the indicator is NOT in the baseline
                        for indicator in &leak_indicators {
                            let in_baseline = baseline
                                .map(|bl| bl.body.contains(indicator))
                                .unwrap_or(false);

                            if !in_baseline && resp_body.contains(indicator) {
                                findings.push(
                                    Finding::new(
                                        format!("SSTI Information Leak in '{param}'"),
                                        format!(
                                            "Parameter '{param}' leaks server-side template internals."
                                        ),
                                        Severity::High,
                                        "Injection",
                                        &point.url,
                                    )
                                    .with_evidence(format!(
                                        "Param: {param}\nPayload: {payload}\nLeak indicator: {indicator}"
                                    ))
                                    .with_request(format!("GET {test_url}"))
                                    .with_recommendation(
                                        "Do not pass user input to template engines.",
                                    )
                                    .with_cwe("CWE-1336")
                                    .with_owasp("A03:2021 Injection"),
                                );
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}
