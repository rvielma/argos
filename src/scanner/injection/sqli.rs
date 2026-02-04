//! SQL Injection detection (error-based, boolean-based, time-based)

use crate::http::HttpClient;
use crate::models::{Finding, Severity};
use std::collections::HashMap;
use std::time::Instant;
use tracing::debug;

use super::BaselineResponse;
use super::InjectionPoint;
use super::InjectionScanner;

/// Scans injection points for SQL injection vulnerabilities
pub async fn scan(
    client: &HttpClient,
    points: &[InjectionPoint],
    baselines: &HashMap<(String, String), BaselineResponse>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let payloads = InjectionScanner::load_payloads(
        "wordlists/payloads/sqli.txt",
        vec![
            "'".to_string(),
            "\"".to_string(),
            "' OR '1'='1".to_string(),
            "1' OR '1'='1' --".to_string(),
            "' UNION SELECT NULL--".to_string(),
        ],
    );

    let time_payloads = vec![
        "' OR SLEEP(3)--",
        "1; WAITFOR DELAY '0:0:3'--",
        "' OR pg_sleep(3)--",
    ];

    for point in points.iter().take(10) {
        for param in &point.params {
            let baseline = baselines.get(&(point.url.clone(), param.clone()));

            // Error-based SQLi
            let mut found_sqli = false;
            'sqli: for payload in payloads.iter().take(5) {
                if let Some(test_url) = InjectionScanner::build_test_url(&point.url, param, payload)
                {
                    if let Ok(resp) = client.get(&test_url).await {
                        let resp_body = resp.text().await.unwrap_or_default();
                        if let Some(db_type) = InjectionScanner::check_sql_errors(&resp_body) {
                            // Verify the SQL error is NOT in the baseline
                            let in_baseline = baseline
                                .map(|bl| InjectionScanner::check_sql_errors(&bl.body).is_some())
                                .unwrap_or(false);

                            if in_baseline {
                                debug!("Skipping SQLi for {param}: SQL error pattern exists in baseline");
                                continue;
                            }

                            findings.push(
                                Finding::new(
                                    format!("SQL Injection (Error-Based) in '{param}'"),
                                    format!(
                                        "Parameter '{param}' is vulnerable to error-based SQL injection ({db_type})."
                                    ),
                                    Severity::Critical,
                                    "Injection",
                                    &point.url,
                                )
                                .with_evidence(format!(
                                    "Param: {param}\nPayload: {payload}\nDB: {db_type}"
                                ))
                                .with_request(format!("GET {test_url}"))
                                .with_recommendation("Use parameterized queries or prepared statements.")
                                .with_cwe("CWE-89")
                                .with_owasp("A03:2021 Injection"),
                            );
                            found_sqli = true;
                            break 'sqli;
                        }
                    }
                }
            }

            if found_sqli {
                continue;
            }

            // Boolean-based SQLi — requires baseline comparison
            let true_payload = "' OR '1'='1";
            let false_payload = "' OR '1'='2";

            if let (Some(true_url), Some(false_url)) = (
                InjectionScanner::build_test_url(&point.url, param, true_payload),
                InjectionScanner::build_test_url(&point.url, param, false_payload),
            ) {
                if let (Ok(true_resp), Ok(false_resp)) =
                    (client.get(&true_url).await, client.get(&false_url).await)
                {
                    let true_body = true_resp.text().await.unwrap_or_default();
                    let false_body = false_resp.text().await.unwrap_or_default();

                    let len_diff =
                        (true_body.len() as i64 - false_body.len() as i64).unsigned_abs();

                    // Compare against baseline: if the baseline response length is similar
                    // to the true response, then the "true" condition isn't changing behavior
                    let baseline_similar = baseline.map(|bl| {
                        let bl_diff = (bl.body.len() as i64 - true_body.len() as i64).unsigned_abs();
                        // If baseline and true response are within 500 bytes, not SQLi
                        bl_diff < 500
                    }).unwrap_or(false);

                    // Require: significant diff between true/false, AND true response
                    // differs from baseline (meaning the SQL condition actually changed behavior)
                    if len_diff > 500 && true_body.len() > 100 && !baseline_similar {
                        findings.push(
                            Finding::new(
                                format!("Potential SQL Injection (Boolean-Based) in '{param}'"),
                                format!(
                                    "Parameter '{param}' shows different responses for true/false SQL conditions."
                                ),
                                Severity::High,
                                "Injection",
                                &point.url,
                            )
                            .with_evidence(format!(
                                "Param: {param}\nTrue payload length: {}\nFalse payload length: {}\nDiff: {len_diff}",
                                true_body.len(),
                                false_body.len()
                            ))
                            .with_recommendation("Use parameterized queries or prepared statements.")
                            .with_cwe("CWE-89")
                            .with_owasp("A03:2021 Injection"),
                        );
                        continue;
                    }
                }
            }

            // Time-based blind SQLi — compare against baseline latency
            let baseline_ms = baseline.map(|bl| bl.elapsed_ms).unwrap_or(0);

            for time_payload in &time_payloads {
                if let Some(test_url) =
                    InjectionScanner::build_test_url(&point.url, param, time_payload)
                {
                    let start = Instant::now();
                    if let Ok(resp) = client.get(&test_url).await {
                        let elapsed = start.elapsed();
                        let _ = resp.text().await;
                        let elapsed_ms = elapsed.as_millis() as u64;

                        debug!(
                            "Time-based SQLi test: {param} -> {:.2}s (baseline: {:.2}s)",
                            elapsed.as_secs_f64(),
                            baseline_ms as f64 / 1000.0
                        );

                        // Only flag if: elapsed >= 3s AND elapsed exceeds baseline by at least 2.5s
                        let excess_ms = elapsed_ms.saturating_sub(baseline_ms);
                        if elapsed.as_secs() >= 3 && excess_ms >= 2500 {
                            findings.push(
                                Finding::new(
                                    format!("SQL Injection (Time-Based Blind) in '{param}'"),
                                    format!(
                                        "Parameter '{param}' caused a delayed response ({:.1}s vs {:.1}s baseline), indicating time-based blind SQLi.",
                                        elapsed.as_secs_f64(),
                                        baseline_ms as f64 / 1000.0
                                    ),
                                    Severity::Critical,
                                    "Injection",
                                    &point.url,
                                )
                                .with_evidence(format!(
                                    "Param: {param}\nPayload: {time_payload}\nDelay: {:.1}s\nBaseline: {:.1}s\nExcess: {:.1}s",
                                    elapsed.as_secs_f64(),
                                    baseline_ms as f64 / 1000.0,
                                    excess_ms as f64 / 1000.0
                                ))
                                .with_request(format!("GET {test_url}"))
                                .with_recommendation("Use parameterized queries or prepared statements.")
                                .with_cwe("CWE-89")
                                .with_owasp("A03:2021 Injection"),
                            );
                            break;
                        }
                    }
                }
            }
        }
    }

    findings
}
