//! Integration tests for the SSL scanner module

use argos::http::{AuthConfig, HttpClient};
use argos::models::ScanConfig;
use argos::scanner::ssl::SslScanner;
use argos::scanner::Scanner;
use std::collections::HashMap;

fn test_config(target: &str) -> ScanConfig {
    ScanConfig {
        target: target.to_string(),
        threads: 2,
        timeout_secs: 10,
        user_agent: "Argos-Test/0.1.0".to_string(),
        modules: vec!["ssl".to_string()],
        follow_redirects: true,
        max_depth: 1,
        headers: HashMap::new(),
        rate_limit: None,
        auth: AuthConfig::None,
        ..ScanConfig::default()
    }
}

#[tokio::test]
async fn test_http_target_no_ssl() {
    let config = test_config("http://example.com");
    let client = HttpClient::from_config(&config)
        .await
        .expect("Failed to create client");
    let scanner = SslScanner;

    let findings = scanner
        .scan(&client, &config, &[])
        .await
        .expect("Scan failed");

    assert!(
        findings.iter().any(|f| f.title.contains("Not Using HTTPS")),
        "Expected finding about missing HTTPS"
    );
}
