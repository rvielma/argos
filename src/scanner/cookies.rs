//! Cookie security analysis module

use crate::error::Result;
use crate::http::HttpClient;
use crate::models::{Finding, ScanConfig, Severity};
use async_trait::async_trait;
use tracing::debug;

/// Analyzes cookie security flags and attributes
pub struct CookiesScanner;

#[async_trait]
impl super::Scanner for CookiesScanner {
    fn name(&self) -> &str {
        "cookies"
    }

    fn description(&self) -> &str {
        "Analyzes cookie security flags (Secure, HttpOnly, SameSite) and attributes"
    }

    async fn scan(
        &self,
        client: &HttpClient,
        config: &ScanConfig,
        _crawled_urls: &[String],
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let response = client.get(&config.target).await?;

        let set_cookie_headers: Vec<String> = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok().map(String::from))
            .collect();

        if set_cookie_headers.is_empty() {
            debug!("No Set-Cookie headers found");
            return Ok(findings);
        }

        for cookie_str in &set_cookie_headers {
            let parts: Vec<&str> = cookie_str.split(';').collect();
            let cookie_name = parts
                .first()
                .and_then(|p| p.split('=').next())
                .unwrap_or("unknown")
                .trim();

            let lower = cookie_str.to_lowercase();
            let is_session_cookie = cookie_name.to_lowercase().contains("session")
                || cookie_name.to_lowercase().contains("sid")
                || cookie_name.to_lowercase().contains("token")
                || cookie_name.to_lowercase().contains("auth");

            let severity = if is_session_cookie {
                Severity::High
            } else {
                Severity::Medium
            };

            if !lower.contains("secure") {
                findings.push(
                    Finding::new(
                        format!("Cookie '{cookie_name}' Missing Secure Flag"),
                        "Cookie can be sent over unencrypted HTTP connections.",
                        severity.clone(),
                        "Cookies",
                        &config.target,
                    )
                    .with_evidence(format!("Set-Cookie: {cookie_str}"))
                    .with_recommendation(
                        "Add the 'Secure' flag to ensure the cookie is only sent over HTTPS.",
                    )
                    .with_cwe("CWE-614")
                    .with_owasp("A05:2021 Security Misconfiguration"),
                );
            }

            if !lower.contains("httponly") {
                findings.push(
                    Finding::new(
                        format!("Cookie '{cookie_name}' Missing HttpOnly Flag"),
                        "Cookie is accessible to JavaScript, vulnerable to XSS-based theft.",
                        severity.clone(),
                        "Cookies",
                        &config.target,
                    )
                    .with_evidence(format!("Set-Cookie: {cookie_str}"))
                    .with_recommendation("Add the 'HttpOnly' flag to prevent JavaScript access.")
                    .with_cwe("CWE-1004")
                    .with_owasp("A05:2021 Security Misconfiguration"),
                );
            }

            if !lower.contains("samesite") {
                findings.push(
                    Finding::new(
                        format!("Cookie '{cookie_name}' Missing SameSite Attribute"),
                        "Cookie lacks SameSite attribute, may allow CSRF attacks.",
                        Severity::Medium,
                        "Cookies",
                        &config.target,
                    )
                    .with_evidence(format!("Set-Cookie: {cookie_str}"))
                    .with_recommendation("Add 'SameSite=Strict' or 'SameSite=Lax' attribute.")
                    .with_cwe("CWE-352")
                    .with_owasp("A01:2021 Broken Access Control"),
                );
            } else if lower.contains("samesite=none") && !lower.contains("secure") {
                findings.push(
                    Finding::new(
                        format!("Cookie '{cookie_name}' SameSite=None Without Secure"),
                        "Cookie uses SameSite=None but lacks the Secure flag.",
                        Severity::Medium,
                        "Cookies",
                        &config.target,
                    )
                    .with_evidence(format!("Set-Cookie: {cookie_str}"))
                    .with_recommendation(
                        "When using SameSite=None, the Secure flag must also be set.",
                    )
                    .with_cwe("CWE-614")
                    .with_owasp("A05:2021 Security Misconfiguration"),
                );
            }
        }

        Ok(findings)
    }
}
