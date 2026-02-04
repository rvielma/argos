//! DAST (Dynamic Application Security Testing) module
//!
//! Detects CSRF, broken access control, session management issues, and IDOR.

pub mod access;
pub mod csrf;
pub mod idor;
pub mod session;

use crate::error::Result;
use crate::http::HttpClient;
use crate::models::{Finding, ScanConfig};
use async_trait::async_trait;
use tracing::{debug, info};

/// DAST scanner covering CSRF, access control, session, and IDOR checks
pub struct DastScanner;

#[async_trait]
impl super::Scanner for DastScanner {
    fn name(&self) -> &str {
        "dast"
    }

    fn description(&self) -> &str {
        "DAST checks: CSRF, broken access control, session management, IDOR"
    }

    async fn scan(
        &self,
        client: &HttpClient,
        config: &ScanConfig,
        crawled_urls: &[String],
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let urls_to_check: Vec<&str> = if crawled_urls.is_empty() {
            vec![config.target.as_str()]
        } else {
            crawled_urls.iter().map(|s| s.as_str()).collect()
        };

        // Collect forms and injection points from crawled pages
        let mut forms_html: Vec<(String, String)> = Vec::new();
        for url in urls_to_check.iter().take(50) {
            if let Ok(response) = client.get(url).await {
                let body = response.text().await.unwrap_or_default();
                if !body.is_empty() {
                    forms_html.push((url.to_string(), body));
                }
            }
        }

        info!(
            "DAST: analyzing {} pages for security issues",
            forms_html.len()
        );

        // CSRF checks
        for (url, html) in &forms_html {
            let csrf_findings = csrf::check_csrf(client, url, html).await;
            findings.extend(csrf_findings);
        }

        // Access control checks (only if auth is configured)
        if !matches!(config.auth, crate::http::AuthConfig::None) {
            let unauth_client = client.without_auth();
            let access_findings =
                access::check_access_control(&unauth_client, crawled_urls).await;
            findings.extend(access_findings);
        } else {
            debug!("DAST: skipping access control checks (no auth configured)");
        }

        // Session management checks
        let session_findings = session::check_session(client, &config.target).await;
        findings.extend(session_findings);

        // IDOR checks
        for url in crawled_urls.iter().take(30) {
            let idor_findings = idor::check_idor(client, url).await;
            findings.extend(idor_findings);
        }

        Ok(findings)
    }
}
