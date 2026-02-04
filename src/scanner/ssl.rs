//! SSL/TLS analysis module

use crate::error::Result;
use crate::http::HttpClient;
use crate::models::{Finding, ScanConfig, Severity};
use async_trait::async_trait;
use native_tls::TlsConnector;
use std::net::ToSocketAddrs;
use tokio::net::TcpStream;
use tracing::{debug, warn};
use url::Url;

/// Analyzes SSL/TLS configuration and certificate validity
pub struct SslScanner;

#[async_trait]
impl super::Scanner for SslScanner {
    fn name(&self) -> &str {
        "ssl"
    }

    fn description(&self) -> &str {
        "Analyzes SSL/TLS configuration, certificate validity, and protocol versions"
    }

    async fn scan(
        &self,
        _client: &HttpClient,
        config: &ScanConfig,
        _crawled_urls: &[String],
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let url = Url::parse(&config.target)?;

        let scheme = url.scheme();
        if scheme != "https" {
            findings.push(
                Finding::new(
                    "Site Not Using HTTPS",
                    "The target site is not using HTTPS. All communication is in plaintext.",
                    Severity::High,
                    "SSL/TLS",
                    &config.target,
                )
                .with_evidence(format!("Target URL uses scheme: {scheme}"))
                .with_recommendation("Enable HTTPS with a valid TLS certificate.")
                .with_cwe("CWE-319")
                .with_owasp("A02:2021 Cryptographic Failures"),
            );
            return Ok(findings);
        }

        let host = url.host_str().unwrap_or("localhost");
        let port = url.port().unwrap_or(443);
        let addr = format!("{host}:{port}");

        let socket_addr = match addr.to_socket_addrs() {
            Ok(mut addrs) => match addrs.next() {
                Some(a) => a,
                None => {
                    findings.push(
                        Finding::new(
                            "DNS Resolution Failed",
                            "Could not resolve the target hostname.",
                            Severity::Info,
                            "SSL/TLS",
                            &config.target,
                        )
                        .with_evidence(format!("Failed to resolve: {addr}")),
                    );
                    return Ok(findings);
                }
            },
            Err(e) => {
                findings.push(
                    Finding::new(
                        "DNS Resolution Failed",
                        "Could not resolve the target hostname.",
                        Severity::Info,
                        "SSL/TLS",
                        &config.target,
                    )
                    .with_evidence(format!("DNS error for {addr}: {e}")),
                );
                return Ok(findings);
            }
        };

        // Connect with permissive TLS to get certificate info
        let connector = TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(crate::error::ArgosError::TlsError)?;

        let tcp_stream = match TcpStream::connect(socket_addr).await {
            Ok(s) => s,
            Err(e) => {
                findings.push(
                    Finding::new(
                        "TCP Connection Failed",
                        "Could not establish a TCP connection to the target.",
                        Severity::Info,
                        "SSL/TLS",
                        &config.target,
                    )
                    .with_evidence(format!("TCP error: {e}")),
                );
                return Ok(findings);
            }
        };

        let connector = tokio_native_tls::TlsConnector::from(connector);
        if let Err(e) = connector.connect(host, tcp_stream).await {
            findings.push(
                Finding::new(
                    "TLS Handshake Failed",
                    "The TLS handshake failed. The server may have an invalid or unsupported TLS configuration.",
                    Severity::High,
                    "SSL/TLS",
                    &config.target,
                )
                .with_evidence(format!("TLS error: {e}"))
                .with_recommendation("Ensure the server supports TLS 1.2 or higher with a valid certificate.")
                .with_cwe("CWE-295")
                .with_owasp("A02:2021 Cryptographic Failures"),
            );
            return Ok(findings);
        }

        debug!("Permissive TLS connection succeeded for {host}");

        // Now connect with strict validation
        let strict_connector = TlsConnector::builder()
            .danger_accept_invalid_certs(false)
            .build()
            .map_err(crate::error::ArgosError::TlsError)?;

        let strict_connector = tokio_native_tls::TlsConnector::from(strict_connector);

        let tcp_stream2 = match TcpStream::connect(socket_addr).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Could not create second connection for strict validation: {e}");
                return Ok(findings);
            }
        };

        if let Err(e) = strict_connector.connect(host, tcp_stream2).await {
            let error_str = e.to_string().to_lowercase();
            if error_str.contains("expired") {
                findings.push(
                    Finding::new(
                        "SSL Certificate Expired",
                        "The SSL/TLS certificate has expired.",
                        Severity::Critical,
                        "SSL/TLS",
                        &config.target,
                    )
                    .with_evidence(format!("Certificate validation error: {e}"))
                    .with_recommendation("Renew the SSL/TLS certificate immediately.")
                    .with_cwe("CWE-295")
                    .with_owasp("A02:2021 Cryptographic Failures"),
                );
            } else if error_str.contains("self signed") || error_str.contains("self-signed") {
                findings.push(
                    Finding::new(
                        "Self-Signed Certificate Detected",
                        "The server uses a self-signed certificate not trusted by browsers.",
                        Severity::High,
                        "SSL/TLS",
                        &config.target,
                    )
                    .with_evidence(format!("Certificate validation error: {e}"))
                    .with_recommendation("Replace with a certificate from a trusted CA.")
                    .with_cwe("CWE-295")
                    .with_owasp("A02:2021 Cryptographic Failures"),
                );
            } else if error_str.contains("hostname") || error_str.contains("name") {
                findings.push(
                    Finding::new(
                        "Certificate Hostname Mismatch",
                        "The certificate CN/SAN does not match the target hostname.",
                        Severity::High,
                        "SSL/TLS",
                        &config.target,
                    )
                    .with_evidence(format!("Certificate validation error: {e}"))
                    .with_recommendation(
                        "Ensure the certificate includes the correct hostname in its SAN field.",
                    )
                    .with_cwe("CWE-295")
                    .with_owasp("A02:2021 Cryptographic Failures"),
                );
            } else {
                findings.push(
                    Finding::new(
                        "SSL Certificate Validation Error",
                        "The SSL/TLS certificate failed validation checks.",
                        Severity::High,
                        "SSL/TLS",
                        &config.target,
                    )
                    .with_evidence(format!("Validation error: {e}"))
                    .with_recommendation("Review and fix the certificate configuration.")
                    .with_cwe("CWE-295")
                    .with_owasp("A02:2021 Cryptographic Failures"),
                );
            }
        } else {
            debug!("Certificate validation passed for {host}");
        }

        Ok(findings)
    }
}
