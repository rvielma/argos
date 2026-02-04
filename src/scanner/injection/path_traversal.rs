//! Path Traversal / Local File Inclusion detection

use crate::http::HttpClient;
use crate::models::{Finding, Severity};
use regex::Regex;

use super::InjectionPoint;
use super::InjectionScanner;

/// Patterns that indicate successful path traversal
const FILE_CONTENT_PATTERNS: &[(&str, &str)] = &[
    (r"root:.:0:0:", "/etc/passwd content (Unix)"),
    (r"\[extensions\]", "win.ini content (Windows)"),
    (r"(?i)\[boot\s*loader\]", "boot.ini content (Windows)"),
    (r"(?:HOME|PATH|USER|SHELL)=", "/proc/self/environ content"),
    (r"localhost", "/etc/hosts content"),
];

/// Scans for path traversal / local file inclusion vulnerabilities
pub async fn scan(client: &HttpClient, points: &[InjectionPoint]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let payloads = InjectionScanner::load_payloads(
        "wordlists/payloads/path_traversal.txt",
        vec![
            "../../../etc/passwd".to_string(),
            "..%2f..%2f..%2fetc%2fpasswd".to_string(),
            "....//....//....//etc/passwd".to_string(),
            "../../../windows/win.ini".to_string(),
        ],
    );

    for point in points.iter().take(10) {
        for param in &point.params {
            'pt: for payload in payloads.iter().take(8) {
                if let Some(test_url) = InjectionScanner::build_test_url(&point.url, param, payload)
                {
                    if let Ok(resp) = client.get(&test_url).await {
                        let resp_body = resp.text().await.unwrap_or_default();

                        for (pattern, description) in FILE_CONTENT_PATTERNS {
                            if let Ok(re) = Regex::new(pattern) {
                                if re.is_match(&resp_body) {
                                    findings.push(
                                        Finding::new(
                                            format!("Path Traversal in '{param}'"),
                                            format!(
                                                "Parameter '{param}' is vulnerable to path traversal / local file inclusion."
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
                                            "Validate and sanitize file paths. Use allowlists for permitted files.",
                                        )
                                        .with_cwe("CWE-22")
                                        .with_owasp("A01:2021 Broken Access Control"),
                                    );
                                    break 'pt;
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
