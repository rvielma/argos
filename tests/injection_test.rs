//! Integration tests for the injection scanner module

use argos::http::{AuthConfig, HttpClient};
use argos::models::ScanConfig;
use argos::scanner::injection::InjectionScanner;
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
        modules: vec!["injection".to_string()],
        follow_redirects: true,
        max_depth: 1,
        headers: HashMap::new(),
        rate_limit: None,
        auth: AuthConfig::None,
        ..ScanConfig::default()
    }
}

#[tokio::test]
async fn test_no_injection_points() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<html><body><h1>Hello</h1></body></html>"),
        )
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config)
        .await
        .expect("Failed to create client");
    let scanner = InjectionScanner;

    let findings = scanner
        .scan(&client, &config, &[])
        .await
        .expect("Scan failed");

    assert!(
        findings.is_empty(),
        "Expected no injection findings on static page"
    );
}

#[tokio::test]
async fn test_page_with_form() {
    let mock_server = MockServer::start().await;

    let form_html = r#"<html><body>
        <form action="/search" method="get">
            <input name="q" type="text" />
            <button type="submit">Search</button>
        </form>
    </body></html>"#;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(form_html))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config)
        .await
        .expect("Failed to create client");
    let scanner = InjectionScanner;

    let result = scanner.scan(&client, &config, &[]).await;
    assert!(
        result.is_ok(),
        "Scanner should not crash on pages with forms"
    );
}
