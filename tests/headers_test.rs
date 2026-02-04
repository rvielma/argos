//! Integration tests for the headers scanner module

use argos::http::{AuthConfig, HttpClient};
use argos::models::ScanConfig;
use argos::scanner::headers::HeadersScanner;
use argos::scanner::Scanner;
use std::collections::HashMap;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

fn test_config(target: &str) -> ScanConfig {
    ScanConfig {
        target: target.to_string(),
        threads: 2,
        timeout_secs: 10,
        user_agent: "Argos-Test/0.1.0".to_string(),
        modules: vec!["headers".to_string()],
        follow_redirects: true,
        max_depth: 1,
        headers: HashMap::new(),
        rate_limit: None,
        auth: AuthConfig::None,
        ..ScanConfig::default()
    }
}

#[tokio::test]
async fn test_missing_security_headers() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).insert_header("Content-Type", "text/html"))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config)
        .await
        .expect("Failed to create client");
    let scanner = HeadersScanner;

    let findings = scanner
        .scan(&client, &config, &[])
        .await
        .expect("Scan failed");

    assert!(
        !findings.is_empty(),
        "Expected findings for missing headers"
    );

    let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
    assert!(
        titles
            .iter()
            .any(|t| t.contains("Strict-Transport-Security")),
        "Expected HSTS finding"
    );
    assert!(
        titles.iter().any(|t| t.contains("Content-Security-Policy")),
        "Expected CSP finding"
    );
}

#[tokio::test]
async fn test_proper_security_headers() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/html")
                .insert_header("Content-Security-Policy", "default-src 'self'")
                .insert_header(
                    "Strict-Transport-Security",
                    "max-age=31536000; includeSubDomains",
                )
                .insert_header("X-Content-Type-Options", "nosniff")
                .insert_header("X-Frame-Options", "DENY")
                .insert_header("Referrer-Policy", "strict-origin-when-cross-origin")
                .insert_header("Permissions-Policy", "camera=(), microphone=()"),
        )
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config)
        .await
        .expect("Failed to create client");
    let scanner = HeadersScanner;

    let findings = scanner
        .scan(&client, &config, &[])
        .await
        .expect("Scan failed");

    let header_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == "Security Headers")
        .collect();
    assert!(
        header_findings.is_empty(),
        "Expected no findings, got: {:?}",
        header_findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_information_disclosure_headers() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Server", "Apache/2.4.51 (Ubuntu)")
                .insert_header("X-Powered-By", "PHP/8.1.2"),
        )
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config)
        .await
        .expect("Failed to create client");
    let scanner = HeadersScanner;

    let findings = scanner
        .scan(&client, &config, &[])
        .await
        .expect("Scan failed");

    let disclosure: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains("Information Disclosure"))
        .collect();
    assert!(
        disclosure.len() >= 2,
        "Expected Server and X-Powered-By disclosure findings"
    );
}
