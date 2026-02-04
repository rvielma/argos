//! OS Command Injection detection

use crate::http::HttpClient;
use crate::models::{Finding, Severity};
use regex::Regex;
use std::collections::HashMap;

use super::BaselineResponse;
use super::InjectionPoint;
use super::InjectionScanner;

/// Command output patterns that indicate successful injection
const CMD_OUTPUT_PATTERNS: &[(&str, &str)] = &[
    (r"uid=\d+\(\w+\)", "Unix id command output"),
    (r"root:x:0:0:", "/etc/passwd content"),
    (r"(?i)(linux|darwin|gnu|unix)", "OS information from uname"),
    (r"(?i)volume\s+serial\s+number", "Windows dir output"),
    (r"(?i)windows_nt", "Windows environment variable"),
    (r"total\s+\d+", "ls -la output"),
];

/// Scans for OS command injection vulnerabilities
pub async fn scan(
    client: &HttpClient,
    points: &[InjectionPoint],
    baselines: &HashMap<(String, String), BaselineResponse>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let payloads = InjectionScanner::load_payloads(
        "wordlists/payloads/command_injection.txt",
        vec![
            ";id".to_string(),
            "|id".to_string(),
            "$(id)".to_string(),
            ";whoami".to_string(),
            "|whoami".to_string(),
        ],
    );

    for point in points.iter().take(10) {
        for param in &point.params {
            let baseline = baselines.get(&(point.url.clone(), param.clone()));

            'cmd: for payload in payloads.iter().take(8) {
                if let Some(test_url) = InjectionScanner::build_test_url(&point.url, param, payload)
                {
                    if let Ok(resp) = client.get(&test_url).await {
                        let resp_body = resp.text().await.unwrap_or_default();

                        for (pattern, description) in CMD_OUTPUT_PATTERNS {
                            if let Ok(re) = Regex::new(pattern) {
                                if re.is_match(&resp_body) {
                                    // Check if this pattern already matches in the baseline
                                    // (e.g., "linux" appearing naturally in the page)
                                    let in_baseline = baseline
                                        .map(|bl| re.is_match(&bl.body))
                                        .unwrap_or(false);

                                    if in_baseline {
                                        continue;
                                    }

                                    findings.push(
                                        Finding::new(
                                            format!("OS Command Injection in '{param}'"),
                                            format!(
                                                "Parameter '{param}' is vulnerable to OS command injection."
                                            ),
                                            Severity::Critical,
                                            "Injection",
                                            &point.url,
                                        )
                                        .with_evidence(format!(
                                            "Param: {param}\nPayload: {payload}\nDetected: {description}"
                                        ))
                                        .with_request(format!("GET {test_url}"))
                                        .with_recommendation(
                                            "Never pass user input to OS commands. Use safe APIs instead.",
                                        )
                                        .with_cwe("CWE-78")
                                        .with_owasp("A03:2021 Injection"),
                                    );
                                    break 'cmd;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}
