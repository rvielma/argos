//! CORS misconfiguration detection module

use crate::error::Result;
use crate::http::HttpClient;
use crate::models::{Finding, ScanConfig, Severity};
use async_trait::async_trait;
use tracing::debug;

/// Detects CORS misconfigurations
pub struct CorsScanner;

#[async_trait]
impl super::Scanner for CorsScanner {
    fn name(&self) -> &str {
        "cors"
    }

    fn description(&self) -> &str {
        "Detects CORS misconfigurations that could allow unauthorized cross-origin access"
    }

    async fn scan(
        &self,
        client: &HttpClient,
        config: &ScanConfig,
        _crawled_urls: &[String],
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let evil_origins: &[(&str, &str)] = &[
            ("https://evil.com", "arbitrary origin"),
            ("null", "null origin"),
        ];

        for (origin, desc) in evil_origins {
            let headers = vec![("Origin".to_string(), origin.to_string())];
            let response = client.get_with_headers(&config.target, &headers).await?;

            let resp_headers = response.headers();

            if let Some(acao) = resp_headers.get("access-control-allow-origin") {
                let acao_str = acao.to_str().unwrap_or("");
                debug!("ACAO for origin '{origin}': '{acao_str}'");

                let reflects_origin = acao_str == *origin;
                let is_wildcard = acao_str == "*";
                let allows_credentials = resp_headers
                    .get("access-control-allow-credentials")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.to_lowercase() == "true")
                    .unwrap_or(false);

                if reflects_origin && *origin == "null" {
                    findings.push(
                        Finding::new(
                            "CORS Allows Null Origin",
                            "The server reflects 'null' as an allowed origin, exploitable via sandboxed iframes.",
                            Severity::High,
                            "CORS",
                            &config.target,
                        )
                        .with_evidence(format!(
                            "Request Origin: {origin}\nAccess-Control-Allow-Origin: {acao_str}"
                        ))
                        .with_recommendation("Do not reflect 'null' as an allowed origin. Use a strict whitelist.")
                        .with_cwe("CWE-942")
                        .with_owasp("A05:2021 Security Misconfiguration"),
                    );
                } else if reflects_origin {
                    let severity = if allows_credentials {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    findings.push(
                        Finding::new(
                            format!("CORS Reflects Arbitrary Origin ({desc})"),
                            format!(
                                "The server reflects the {desc} in the ACAO header{}.",
                                if allows_credentials {
                                    " with credentials"
                                } else {
                                    ""
                                }
                            ),
                            severity,
                            "CORS",
                            &config.target,
                        )
                        .with_evidence(format!(
                            "Request Origin: {origin}\nAccess-Control-Allow-Origin: {acao_str}\nAccess-Control-Allow-Credentials: {allows_credentials}"
                        ))
                        .with_recommendation("Implement a strict whitelist of allowed origins.")
                        .with_cwe("CWE-942")
                        .with_owasp("A05:2021 Security Misconfiguration"),
                    );
                }

                if is_wildcard && allows_credentials {
                    findings.push(
                        Finding::new(
                            "CORS Wildcard with Credentials",
                            "Server uses ACAO: * with Allow-Credentials: true, indicating misconfigured CORS.",
                            Severity::Medium,
                            "CORS",
                            &config.target,
                        )
                        .with_evidence(
                            "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true"
                                .to_string(),
                        )
                        .with_recommendation("Use specific origins instead of wildcard when credentials are needed.")
                        .with_cwe("CWE-942")
                        .with_owasp("A05:2021 Security Misconfiguration"),
                    );
                }
            }
        }

        Ok(findings)
    }
}
