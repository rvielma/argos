//! Out-of-Band (OOB) scanner module
//!
//! Uses callback servers to detect blind SSRF, XXE, and blind SQLi.

use crate::error::Result;
use crate::http::HttpClient;
use crate::models::{Confidence, Finding, ScanConfig, Severity};
use crate::oob::{self, OobServer};
use crate::scanner::injection::InjectionScanner;
use async_trait::async_trait;
use tracing::{debug, info};

/// OOB-based vulnerability scanner
pub struct OobScanner;

#[async_trait]
impl super::Scanner for OobScanner {
    fn name(&self) -> &str {
        "oob"
    }

    fn description(&self) -> &str {
        "Detects blind SSRF, XXE, and blind SQLi using out-of-band callbacks"
    }

    async fn scan(
        &self,
        client: &HttpClient,
        config: &ScanConfig,
        crawled_urls: &[String],
    ) -> Result<Vec<Finding>> {
        if !config.oob_enabled {
            debug!("OOB testing disabled, skipping");
            return Ok(Vec::new());
        }

        let callback_host = match &config.oob_host {
            Some(host) => host.clone(),
            None => {
                info!("OOB: no callback host configured, skipping");
                return Ok(Vec::new());
            }
        };

        let server = OobServer::new(
            callback_host,
            config.oob_http_port,
            config.oob_dns_port,
            config.oob_smtp_port,
            config.oob_ftp_port,
        );
        server.start().await?;

        let mut findings = Vec::new();

        // Collect injection points
        let urls_to_check: Vec<&str> = if crawled_urls.is_empty() {
            vec![config.target.as_str()]
        } else {
            crawled_urls.iter().map(|s| s.as_str()).collect()
        };

        let mut injection_points = Vec::new();
        for url in urls_to_check.iter().take(30) {
            if let Ok(response) = client.get(url).await {
                let body = response.text().await.unwrap_or_default();
                let points = InjectionScanner::extract_injection_points(url, &body);
                injection_points.extend(points);
            }
        }

        injection_points.sort_by(|a, b| a.url.cmp(&b.url));
        injection_points.dedup_by(|a, b| a.url == b.url);

        info!(
            "OOB: testing {} injection points with {} timeout",
            injection_points.len(),
            config.oob_timeout_secs
        );

        // SSRF testing: inject callback URLs into parameters
        for point in injection_points.iter().take(20) {
            for param in &point.params {
                let id = oob::generate_id();
                let callback_url = server.callback_url(&id);

                let ssrf_payloads = oob::payloads::ssrf_payloads(&callback_url);
                for (payload_param, payload_value) in &ssrf_payloads {
                    if payload_param == param {
                        if let Some(test_url) =
                            InjectionScanner::build_test_url(&point.url, param, payload_value)
                        {
                            let _ = client.get(&test_url).await;
                        }
                    }
                }

                // Check for interaction
                if let Some(interactions) =
                    server.check_interaction(&id, config.oob_timeout_secs).await
                {
                    let finding = Finding::new(
                        "Blind SSRF (Out-of-Band)",
                        format!(
                            "The parameter '{}' at {} triggered an out-of-band HTTP callback, \
                             confirming a blind SSRF vulnerability.",
                            param, point.url
                        ),
                        Severity::High,
                        "SSRF",
                        &point.url,
                    )
                    .with_confidence(Confidence::Confirmed)
                    .with_evidence(format!(
                        "Received {} OOB interaction(s) from {:?}",
                        interactions.len(),
                        interactions.first().map(|i| i.remote_addr)
                    ))
                    .with_recommendation(
                        "Validate and sanitize all URL parameters. Use allowlists for \
                         permitted domains. Block internal network access from the application.",
                    )
                    .with_cwe("CWE-918")
                    .with_owasp("A10:2021 Server-Side Request Forgery");

                    findings.push(finding);
                }
            }
        }

        // Blind SQLi OOB testing
        for point in injection_points.iter().take(10) {
            for param in &point.params {
                let id = oob::generate_id();
                let callback_url = server.callback_url(&id);
                let callback_dns = server.callback_dns(&id);

                let sqli_payloads =
                    oob::payloads::sqli_oob_payloads(&callback_url, &callback_dns);

                for (_db_type, payload) in &sqli_payloads {
                    if let Some(test_url) =
                        InjectionScanner::build_test_url(&point.url, param, payload)
                    {
                        let _ = client.get(&test_url).await;
                    }
                }

                if let Some(interactions) =
                    server.check_interaction(&id, config.oob_timeout_secs).await
                {
                    let finding = Finding::new(
                        "Blind SQL Injection (Out-of-Band)",
                        format!(
                            "The parameter '{}' at {} triggered an OOB callback via SQL injection, \
                             confirming blind SQLi.",
                            param, point.url
                        ),
                        Severity::Critical,
                        "SQL Injection",
                        &point.url,
                    )
                    .with_confidence(Confidence::Confirmed)
                    .with_evidence(format!(
                        "OOB interaction received from {:?}",
                        interactions.first().map(|i| i.remote_addr)
                    ))
                    .with_recommendation(
                        "Use parameterized queries or prepared statements. \
                         Never concatenate user input into SQL queries.",
                    )
                    .with_cwe("CWE-89")
                    .with_owasp("A03:2021 Injection");

                    findings.push(finding);
                }
            }
        }

        // XXE testing: send XML payloads to endpoints that might accept XML
        for url in crawled_urls.iter().take(10) {
            let id = oob::generate_id();
            let callback_url = server.callback_url(&id);

            let xxe_payloads = oob::payloads::xxe_payloads(&callback_url);
            for payload in &xxe_payloads {
                let headers = vec![
                    ("Content-Type".to_string(), "application/xml".to_string()),
                ];
                let _ = client
                    .request(reqwest::Method::POST, url, &headers, Some(payload))
                    .await;
            }

            if let Some(interactions) =
                server.check_interaction(&id, config.oob_timeout_secs).await
            {
                let finding = Finding::new(
                    "XXE (Out-of-Band)",
                    format!(
                        "Sending XML with external entity references to {} triggered an \
                         OOB callback, confirming XXE.",
                        url
                    ),
                    Severity::High,
                    "XXE",
                    url,
                )
                .with_confidence(Confidence::Confirmed)
                .with_evidence(format!(
                    "OOB interaction received from {:?}",
                    interactions.first().map(|i| i.remote_addr)
                ))
                .with_recommendation(
                    "Disable external entity processing in XML parsers. \
                     Use less complex data formats like JSON when possible.",
                )
                .with_cwe("CWE-611")
                .with_owasp("A05:2021 Security Misconfiguration");

                findings.push(finding);
            }
        }

        Ok(findings)
    }
}
