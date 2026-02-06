//! SSL/TLS analysis module

use crate::error::Result;
use crate::http::HttpClient;
use crate::models::{Confidence, Finding, ScanConfig, Severity};
use async_trait::async_trait;
use native_tls::TlsConnector;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, SupportedProtocolVersion};
use std::net::ToSocketAddrs;
use std::sync::Arc;
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

        // --- TLS version probing with rustls ---
        let tls_findings = probe_tls_versions(host, socket_addr, &config.target).await;
        findings.extend(tls_findings);

        // --- Certificate info extraction with rustls + x509-parser ---
        let cert_findings = extract_cert_info(host, socket_addr, &config.target).await;
        findings.extend(cert_findings);

        Ok(findings)
    }
}

/// Probes TLS 1.2 and 1.3 support using rustls
async fn probe_tls_versions(
    host: &str,
    socket_addr: std::net::SocketAddr,
    target_url: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut supported_versions = Vec::new();

    // Probe TLS 1.2
    if probe_single_version(host, socket_addr, &rustls::version::TLS12).await {
        supported_versions.push("TLS 1.2");
    }

    // Probe TLS 1.3
    let tls13_supported =
        probe_single_version(host, socket_addr, &rustls::version::TLS13).await;
    if tls13_supported {
        supported_versions.push("TLS 1.3");
    }

    if supported_versions.is_empty() {
        // Could not connect with either — might be TLS 1.0/1.1 only
        findings.push(
            Finding::new(
                "Only Legacy TLS Versions Supported",
                "The server does not support TLS 1.2 or TLS 1.3. It may only support deprecated TLS 1.0/1.1.",
                Severity::High,
                "SSL/TLS",
                target_url,
            )
            .with_confidence(Confidence::Confirmed)
            .with_evidence("Neither TLS 1.2 nor TLS 1.3 handshake succeeded".to_string())
            .with_recommendation("Enable TLS 1.2 and TLS 1.3 on the server.")
            .with_cwe("CWE-326")
            .with_owasp("A02:2021 Cryptographic Failures"),
        );
    } else {
        // Report supported versions as info
        findings.push(
            Finding::new(
                "TLS Versions Supported",
                format!(
                    "The server supports the following TLS versions: {}",
                    supported_versions.join(", ")
                ),
                Severity::Info,
                "SSL/TLS",
                target_url,
            )
            .with_confidence(Confidence::Confirmed)
            .with_evidence(format!("Supported: {}", supported_versions.join(", "))),
        );

        if !tls13_supported {
            findings.push(
                Finding::new(
                    "TLS 1.3 Not Supported",
                    "The server does not support TLS 1.3. While TLS 1.2 is still acceptable, TLS 1.3 provides improved security and performance.",
                    Severity::Low,
                    "SSL/TLS",
                    target_url,
                )
                .with_confidence(Confidence::Confirmed)
                .with_evidence("TLS 1.3 handshake failed")
                .with_recommendation("Enable TLS 1.3 on the server for improved security and performance.")
                .with_cwe("CWE-326")
                .with_owasp("A02:2021 Cryptographic Failures"),
            );
        }
    }

    findings
}

/// Attempts a TLS connection with a specific protocol version
async fn probe_single_version(
    host: &str,
    socket_addr: std::net::SocketAddr,
    version: &'static SupportedProtocolVersion,
) -> bool {
    let provider = default_provider();
    let config = match ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[version])
    {
        Ok(builder) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth(),
        Err(_) => return false,
    };

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = match ServerName::try_from(host.to_string()) {
        Ok(name) => name,
        Err(_) => return false,
    };

    let tcp = match TcpStream::connect(socket_addr).await {
        Ok(s) => s,
        Err(_) => return false,
    };

    connector.connect(server_name, tcp).await.is_ok()
}

/// Extracts certificate details using rustls + x509-parser
async fn extract_cert_info(
    host: &str,
    socket_addr: std::net::SocketAddr,
    target_url: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let provider = default_provider();
    let config = match ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
    {
        Ok(builder) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(CertCaptureVerifier))
            .with_no_client_auth(),
        Err(_) => return findings,
    };

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = match ServerName::try_from(host.to_string()) {
        Ok(name) => name,
        Err(_) => return findings,
    };

    let tcp = match TcpStream::connect(socket_addr).await {
        Ok(s) => s,
        Err(_) => return findings,
    };

    let tls_stream = match connector.connect(server_name, tcp).await {
        Ok(s) => s,
        Err(_) => return findings,
    };

    // Get negotiated cipher suite
    let conn = tls_stream.get_ref().1;
    if let Some(cipher) = conn.negotiated_cipher_suite() {
        findings.push(
            Finding::new(
                "Negotiated Cipher Suite",
                format!("The server negotiated cipher suite: {:?}", cipher.suite()),
                Severity::Info,
                "SSL/TLS",
                target_url,
            )
            .with_confidence(Confidence::Confirmed)
            .with_evidence(format!("Cipher: {:?}", cipher.suite())),
        );
    }

    // Get peer certificates
    let peer_certs = conn.peer_certificates();
    if let Some(certs) = peer_certs {
        if let Some(leaf) = certs.first() {
            match x509_parser::parse_x509_certificate(leaf.as_ref()) {
                Ok((_, cert)) => {
                    let subject = cert.subject().to_string();
                    let issuer = cert.issuer().to_string();
                    let not_before = cert.validity().not_before.to_string();
                    let not_after = cert.validity().not_after.to_string();

                    // Key size
                    let key_info = cert.public_key();
                    let key_bits = key_info.parsed().map_or(0u32, |pk| match pk {
                        x509_parser::public_key::PublicKey::RSA(rsa) => {
                            (rsa.modulus.len() as u32) * 8
                        }
                        x509_parser::public_key::PublicKey::EC(ec) => {
                            (ec.data().len() as u32) * 4 // approximate
                        }
                        _ => 0,
                    });

                    let sig_algo = cert
                        .signature_algorithm
                        .algorithm
                        .to_id_string();

                    let evidence = format!(
                        "Subject: {}\nIssuer: {}\nValid: {} to {}\nKey size: {} bits\nSignature: {}",
                        subject, issuer, not_before, not_after, key_bits, sig_algo
                    );

                    findings.push(
                        Finding::new(
                            "Certificate Details",
                            format!("Certificate for {} issued by {}", subject, issuer),
                            Severity::Info,
                            "SSL/TLS",
                            target_url,
                        )
                        .with_confidence(Confidence::Confirmed)
                        .with_evidence(evidence),
                    );

                    // Check RSA key size
                    if key_bits > 0 && key_bits < 2048 {
                        findings.push(
                            Finding::new(
                                "Weak RSA Key Size",
                                format!(
                                    "The server certificate uses a {}-bit RSA key, which is below the recommended minimum of 2048 bits.",
                                    key_bits
                                ),
                                Severity::Medium,
                                "SSL/TLS",
                                target_url,
                            )
                            .with_confidence(Confidence::Confirmed)
                            .with_evidence(format!("RSA key size: {} bits", key_bits))
                            .with_recommendation("Use at least a 2048-bit RSA key or switch to ECDSA with P-256 or higher.")
                            .with_cwe("CWE-326")
                            .with_owasp("A02:2021 Cryptographic Failures"),
                        );
                    }

                    // Check certificate expiry (< 30 days)
                    {
                        let not_after_ts = cert.validity().not_after.timestamp();
                        let now_ts = chrono::Utc::now().timestamp();
                        let days_remaining = (not_after_ts - now_ts) / 86400;
                        if days_remaining < 30 && days_remaining > 0 {
                            findings.push(
                                Finding::new(
                                    "Certificate Expiring Soon",
                                    format!(
                                        "The SSL/TLS certificate expires in {} days.",
                                        days_remaining
                                    ),
                                    Severity::Medium,
                                    "SSL/TLS",
                                    target_url,
                                )
                                .with_confidence(Confidence::Confirmed)
                                .with_evidence(format!(
                                    "Certificate expires: {} ({} days remaining)",
                                    not_after, days_remaining
                                ))
                                .with_recommendation("Renew the SSL/TLS certificate before it expires.")
                                .with_cwe("CWE-298")
                                .with_owasp("A02:2021 Cryptographic Failures"),
                            );
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to parse X.509 certificate: {}", e);
                }
            }
        }
    }

    findings
}

/// A TLS certificate verifier that accepts everything (for probing only)
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A TLS certificate verifier that accepts everything but allows cert capture
#[derive(Debug)]
struct CertCaptureVerifier;

impl rustls::client::danger::ServerCertVerifier for CertCaptureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
