//! Broken Access Control detection
//!
//! Tests whether authenticated-only resources are accessible without credentials.

use crate::http::HttpClient;
use crate::models::{Confidence, Finding, Severity};
use regex::Regex;
use tracing::debug;

/// URL patterns that typically require authentication
const PROTECTED_PATTERNS: &[&str] = &[
    r"(?i)/admin",
    r"(?i)/dashboard",
    r"(?i)/settings",
    r"(?i)/account",
    r"(?i)/profile",
    r"(?i)/manage",
    r"(?i)/config",
    r"(?i)/internal",
    r"(?i)/panel",
    r"(?i)/control",
    r"(?i)/users/\d+",
    r"(?i)/api/admin",
    r"(?i)/api/private",
    r"(?i)/api/internal",
];

/// Login page indicators — if we see these in the response, it's not a real bypass
const LOGIN_INDICATORS: &[&str] = &[
    "login",
    "sign in",
    "signin",
    "log in",
    "authenticate",
    "password",
    "username",
    "credentials",
];

/// Checks crawled URLs for broken access control by re-requesting without auth
pub async fn check_access_control(
    unauth_client: &HttpClient,
    crawled_urls: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let protected_regexes: Vec<Regex> = PROTECTED_PATTERNS
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect();

    for url in crawled_urls.iter().take(100) {
        let is_protected = protected_regexes.iter().any(|re| re.is_match(url));
        if !is_protected {
            continue;
        }

        debug!("Testing access control for: {}", url);

        match unauth_client.get(url).await {
            Ok(response) => {
                let status = response.status().as_u16();
                if status != 200 {
                    continue;
                }

                let body = response.text().await.unwrap_or_default();

                // Check if this is just a login redirect/page
                let lower_body = body.to_lowercase();
                let is_login_page = LOGIN_INDICATORS
                    .iter()
                    .filter(|indicator| lower_body.contains(*indicator))
                    .count()
                    >= 2;

                if is_login_page {
                    continue;
                }

                // If body is too short, likely not real content
                if body.len() < 200 {
                    continue;
                }

                let finding = Finding::new(
                    "Broken Access Control",
                    format!(
                        "The protected resource at {} is accessible without authentication. \
                         An unauthenticated request returned HTTP 200 with content.",
                        url
                    ),
                    Severity::High,
                    "Access Control",
                    url,
                )
                .with_confidence(Confidence::Confirmed)
                .with_evidence(format!(
                    "Unauthenticated GET returned 200 OK with {} bytes of content",
                    body.len()
                ))
                .with_recommendation(
                    "Implement proper access control checks on all protected resources. \
                     Verify authentication and authorization on the server side for every request.",
                )
                .with_cwe("CWE-284")
                .with_owasp("A01:2021 Broken Access Control");

                findings.push(finding);
            }
            Err(e) => {
                debug!("Access control check failed for {}: {}", url, e);
            }
        }
    }

    findings
}
