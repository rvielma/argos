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

                            // Quote-balanced confirmation: escaping the quotes in the
                            // payload should make a genuine SQL error disappear. If the
                            // same error still shows, the pattern is likely static page
                            // content (docs, WAF block page) -> false positive.
                            let balanced = payload.replace('\'', "''");
                            if balanced != *payload {
                                if let Some(balanced_url) =
                                    InjectionScanner::build_test_url(&point.url, param, &balanced)
                                {
                                    if let Ok(bresp) = client.get(&balanced_url).await {
                                        let bbody = bresp.text().await.unwrap_or_default();
                                        if InjectionScanner::check_sql_errors(&bbody).is_some() {
                                            debug!("Skipping SQLi for {param}: error persists with balanced quotes (static content)");
                                            continue;
                                        }
                                    }
                                }
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

            // Boolean-based SQLi — requires baseline comparison.
            // Test both string context (' OR '1'='1) and numeric context (OR 1=1) so
            // numeric parameters aren't missed (they'd only throw a syntax error with
            // the quoted payloads).
            let bool_pairs: &[(&str, &str)] =
                &[("' OR '1'='1", "' OR '1'='2"), (" OR 1=1", " OR 1=2")];

            let mut found_boolean = false;
            'boolean: for (true_payload, false_payload) in bool_pairs {
                if let (Some(true_url), Some(false_url)) = (
                    InjectionScanner::build_test_url(&point.url, param, true_payload),
                    InjectionScanner::build_test_url(&point.url, param, false_payload),
                ) {
                    if let (Ok(true_resp), Ok(false_resp)) =
                        (client.get(&true_url).await, client.get(&false_url).await)
                    {
                        let true_body = true_resp.text().await.unwrap_or_default();
                        let false_body = false_resp.text().await.unwrap_or_default();

                        // Compare normalized bodies to ignore volatile tokens.
                        let true_norm = InjectionScanner::normalize_body(&true_body).len();
                        let false_norm = InjectionScanner::normalize_body(&false_body).len();
                        let len_diff = true_norm.abs_diff(false_norm);

                        // Threshold is relative to the page: at least 3x the observed
                        // natural variance, and at least 5% of the baseline size. This
                        // avoids flagging normal per-request jitter on large pages and
                        // avoids missing small API responses.
                        let (variance, norm_len) = baseline
                            .map(|bl| (bl.len_variance, bl.norm_len))
                            .unwrap_or((0, true_norm));
                        let threshold = (variance.saturating_mul(3)).max(norm_len / 20).max(32);

                        // Semantic check: the TRUE condition should resemble the normal
                        // (baseline) page while the FALSE condition should differ from it.
                        // That is the real signature of boolean-based SQLi.
                        let (true_like_baseline, false_unlike_baseline) = baseline
                            .map(|bl| {
                                let tol = (bl.len_variance.saturating_mul(3))
                                    .max(bl.norm_len / 20)
                                    .max(32);
                                (
                                    InjectionScanner::similar_len(true_norm, bl.norm_len, tol),
                                    !InjectionScanner::similar_len(false_norm, bl.norm_len, tol),
                                )
                            })
                            // Without a baseline we can't verify semantics -> stay conservative.
                            .unwrap_or((false, false));

                        if len_diff > threshold
                            && true_norm > 100
                            && true_like_baseline
                            && false_unlike_baseline
                        {
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
                                    "Param: {param}\nTrue payload: {true_payload}\nFalse payload: {false_payload}\nTrue norm length: {true_norm}\nFalse norm length: {false_norm}\nDiff: {len_diff} (threshold: {threshold})"
                                ))
                                .with_recommendation("Use parameterized queries or prepared statements.")
                                .with_cwe("CWE-89")
                                .with_owasp("A03:2021 Injection"),
                            );
                            found_boolean = true;
                            break 'boolean;
                        }
                    }
                }
            }
            if found_boolean {
                continue;
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
                            // Confirmation pass to rule out a one-off slow response:
                            //  1) a SLEEP(0) control must come back fast (< 2.5s excess),
                            //  2) re-sending the delay payload must reproduce the delay.
                            let control_payload =
                                time_payload.replace("(3)", "(0)").replace("0:0:3", "0:0:0");
                            let control_ok = match InjectionScanner::build_test_url(
                                &point.url,
                                param,
                                &control_payload,
                            ) {
                                Some(curl) => {
                                    let cstart = Instant::now();
                                    match client.get(&curl).await {
                                        Ok(cresp) => {
                                            let celapsed = cstart.elapsed();
                                            let _ = cresp.text().await;
                                            // control is valid only if it's clearly fast
                                            (celapsed.as_millis() as u64) < baseline_ms + 2500
                                        }
                                        Err(_) => false,
                                    }
                                }
                                None => false,
                            };

                            let rstart = Instant::now();
                            let replay_slow = match client.get(&test_url).await {
                                Ok(rresp) => {
                                    let relapsed = rstart.elapsed();
                                    let _ = rresp.text().await;
                                    relapsed.as_secs() >= 3
                                }
                                Err(_) => false,
                            };

                            if !(control_ok && replay_slow) {
                                debug!("Skipping time-based SQLi for {param}: not reproducible (control_ok={control_ok}, replay_slow={replay_slow})");
                                continue;
                            }

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
