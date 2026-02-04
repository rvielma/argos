//! Security headers analysis module

use crate::error::Result;
use crate::http::HttpClient;
use crate::models::{Finding, ScanConfig, Severity};
use async_trait::async_trait;
use tracing::debug;

/// Analyzes HTTP security headers
pub struct HeadersScanner;

enum HeaderResult {
    Missing,
    Invalid(String),
    Weak(String),
    Ok,
}

fn validate_csp(value: Option<&str>) -> HeaderResult {
    match value {
        None => HeaderResult::Missing,
        Some(v) => {
            if v.contains("unsafe-inline") || v.contains("unsafe-eval") {
                HeaderResult::Weak(format!("CSP contains unsafe directives: {v}"))
            } else {
                HeaderResult::Ok
            }
        }
    }
}

fn validate_hsts(value: Option<&str>) -> HeaderResult {
    match value {
        None => HeaderResult::Missing,
        Some(v) => {
            if let Some(max_age_str) = v
                .split(';')
                .find_map(|part| part.trim().strip_prefix("max-age="))
            {
                if let Ok(max_age) = max_age_str.trim().parse::<u64>() {
                    if max_age < 31_536_000 {
                        return HeaderResult::Weak(format!(
                            "HSTS max-age is {max_age} (should be >= 31536000)"
                        ));
                    }
                    if !v.to_lowercase().contains("includesubdomains") {
                        return HeaderResult::Weak(
                            "HSTS missing includeSubDomains directive".to_string(),
                        );
                    }
                    HeaderResult::Ok
                } else {
                    HeaderResult::Invalid("Invalid max-age value".to_string())
                }
            } else {
                HeaderResult::Invalid("Missing max-age directive".to_string())
            }
        }
    }
}

fn validate_x_content_type(value: Option<&str>) -> HeaderResult {
    match value {
        None => HeaderResult::Missing,
        Some(v) if v.to_lowercase() == "nosniff" => HeaderResult::Ok,
        Some(v) => HeaderResult::Invalid(format!("Expected 'nosniff', got '{v}'")),
    }
}

fn validate_x_frame_options(value: Option<&str>) -> HeaderResult {
    match value {
        None => HeaderResult::Missing,
        Some(v) => {
            let upper = v.to_uppercase();
            if upper == "DENY" || upper == "SAMEORIGIN" {
                HeaderResult::Ok
            } else {
                HeaderResult::Weak(format!("Unexpected value: {v}"))
            }
        }
    }
}

fn validate_referrer_policy(value: Option<&str>) -> HeaderResult {
    match value {
        None => HeaderResult::Missing,
        Some(v) => {
            let valid = [
                "no-referrer",
                "no-referrer-when-downgrade",
                "origin",
                "origin-when-cross-origin",
                "same-origin",
                "strict-origin",
                "strict-origin-when-cross-origin",
            ];
            if valid
                .iter()
                .any(|&valid_val| v.to_lowercase().contains(valid_val))
            {
                HeaderResult::Ok
            } else {
                HeaderResult::Invalid(format!("Unexpected referrer policy: {v}"))
            }
        }
    }
}

fn validate_permissions_policy(value: Option<&str>) -> HeaderResult {
    match value {
        None => HeaderResult::Missing,
        Some(_) => HeaderResult::Ok,
    }
}

fn check_server_header(value: Option<&str>) -> HeaderResult {
    match value {
        None => HeaderResult::Ok,
        Some(v) => {
            let has_version = v.chars().any(|c| c.is_ascii_digit());
            if has_version {
                HeaderResult::Weak(format!("Server header reveals version: {v}"))
            } else {
                HeaderResult::Ok
            }
        }
    }
}

fn check_x_powered_by(value: Option<&str>) -> HeaderResult {
    match value {
        None => HeaderResult::Ok,
        Some(v) => HeaderResult::Weak(format!("X-Powered-By reveals technology: {v}")),
    }
}

struct HeaderCheck {
    name: &'static str,
    severity: Severity,
    cwe: &'static str,
    owasp: &'static str,
    recommendation: &'static str,
    description: &'static str,
    validator: fn(Option<&str>) -> HeaderResult,
}

#[async_trait]
impl super::Scanner for HeadersScanner {
    fn name(&self) -> &str {
        "headers"
    }

    fn description(&self) -> &str {
        "Analyzes HTTP security headers for missing or misconfigured protections"
    }

    async fn scan(
        &self,
        client: &HttpClient,
        config: &ScanConfig,
        _crawled_urls: &[String],
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let response = client.get(&config.target).await?;
        let headers = response.headers().clone();

        let checks: Vec<HeaderCheck> = vec![
            HeaderCheck {
                name: "Content-Security-Policy",
                severity: Severity::Medium,
                cwe: "CWE-693",
                owasp: "A05:2021 Security Misconfiguration",
                recommendation: "Implement a strict Content-Security-Policy header. Avoid 'unsafe-inline' and 'unsafe-eval' directives.",
                description: "Content-Security-Policy (CSP) header is missing or misconfigured.",
                validator: validate_csp,
            },
            HeaderCheck {
                name: "Strict-Transport-Security",
                severity: Severity::High,
                cwe: "CWE-319",
                owasp: "A02:2021 Cryptographic Failures",
                recommendation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
                description: "HSTS header is missing or misconfigured. Users may connect via HTTP.",
                validator: validate_hsts,
            },
            HeaderCheck {
                name: "X-Content-Type-Options",
                severity: Severity::Low,
                cwe: "CWE-693",
                owasp: "A05:2021 Security Misconfiguration",
                recommendation: "Add 'X-Content-Type-Options: nosniff' header.",
                description: "X-Content-Type-Options header is missing.",
                validator: validate_x_content_type,
            },
            HeaderCheck {
                name: "X-Frame-Options",
                severity: Severity::Medium,
                cwe: "CWE-1021",
                owasp: "A05:2021 Security Misconfiguration",
                recommendation: "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking.",
                description: "X-Frame-Options header is missing, enabling potential clickjacking.",
                validator: validate_x_frame_options,
            },
            HeaderCheck {
                name: "Referrer-Policy",
                severity: Severity::Low,
                cwe: "CWE-200",
                owasp: "A01:2021 Broken Access Control",
                recommendation: "Add 'Referrer-Policy: strict-origin-when-cross-origin'.",
                description: "Referrer-Policy header is missing.",
                validator: validate_referrer_policy,
            },
            HeaderCheck {
                name: "Permissions-Policy",
                severity: Severity::Low,
                cwe: "CWE-693",
                owasp: "A05:2021 Security Misconfiguration",
                recommendation: "Add a Permissions-Policy header to restrict browser features.",
                description: "Permissions-Policy header is missing.",
                validator: validate_permissions_policy,
            },
        ];

        for check in &checks {
            let header_value = headers.get(check.name).and_then(|v| v.to_str().ok());
            debug!("Checking header '{}': {:?}", check.name, header_value);

            match (check.validator)(header_value) {
                HeaderResult::Missing => {
                    findings.push(
                        Finding::new(
                            format!("Missing {} Header", check.name),
                            check.description,
                            check.severity.clone(),
                            "Security Headers",
                            &config.target,
                        )
                        .with_evidence(format!(
                            "Header '{}' was not found in the response",
                            check.name
                        ))
                        .with_recommendation(check.recommendation)
                        .with_cwe(check.cwe)
                        .with_owasp(check.owasp),
                    );
                }
                HeaderResult::Invalid(detail) | HeaderResult::Weak(detail) => {
                    findings.push(
                        Finding::new(
                            format!("Misconfigured {} Header", check.name),
                            check.description,
                            check.severity.clone(),
                            "Security Headers",
                            &config.target,
                        )
                        .with_evidence(detail)
                        .with_recommendation(check.recommendation)
                        .with_cwe(check.cwe)
                        .with_owasp(check.owasp),
                    );
                }
                HeaderResult::Ok => {
                    debug!("Header '{}' is properly configured", check.name);
                }
            }
        }

        if let HeaderResult::Weak(detail) =
            check_server_header(headers.get("Server").and_then(|v| v.to_str().ok()))
        {
            findings.push(
                Finding::new(
                    "Server Header Information Disclosure",
                    "Server header reveals software version information.",
                    Severity::Low,
                    "Security Headers",
                    &config.target,
                )
                .with_evidence(detail)
                .with_recommendation("Remove or genericize the Server header.")
                .with_cwe("CWE-200")
                .with_owasp("A01:2021 Broken Access Control"),
            );
        }

        if let HeaderResult::Weak(detail) =
            check_x_powered_by(headers.get("X-Powered-By").and_then(|v| v.to_str().ok()))
        {
            findings.push(
                Finding::new(
                    "X-Powered-By Header Information Disclosure",
                    "X-Powered-By header reveals the technology stack.",
                    Severity::Low,
                    "Security Headers",
                    &config.target,
                )
                .with_evidence(detail)
                .with_recommendation("Remove the X-Powered-By header from responses.")
                .with_cwe("CWE-200")
                .with_owasp("A01:2021 Broken Access Control"),
            );
        }

        Ok(findings)
    }
}
