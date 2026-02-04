//! Tests for the OOB (Out-of-Band) infrastructure and scanner

use argos::http::{AuthConfig, HttpClient};
use argos::models::ScanConfig;
use argos::oob::{self, OobServer};
use argos::scanner::oob_scanner::OobScanner;
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
        modules: vec!["oob".to_string()],
        rate_limit: None,
        headers: HashMap::new(),
        auth: AuthConfig::None,
        ..ScanConfig::default()
    }
}

// ── generate_id tests ──

#[test]
fn test_generate_id_length() {
    let id = oob::generate_id();
    assert_eq!(id.len(), 12, "Interaction ID should be 12 chars");
}

#[test]
fn test_generate_id_uniqueness() {
    let ids: Vec<String> = (0..100).map(|_| oob::generate_id()).collect();
    let unique: std::collections::HashSet<&String> = ids.iter().collect();
    assert_eq!(ids.len(), unique.len(), "Generated IDs should be unique");
}

#[test]
fn test_generate_id_hex() {
    let id = oob::generate_id();
    assert!(
        id.chars().all(|c| c.is_ascii_hexdigit()),
        "ID should be hex: {}",
        id
    );
}

// ── OobServer URL construction ──

#[test]
fn test_callback_url() {
    let server = OobServer::new("10.0.0.1".to_string(), 8888, 5353);
    let url = server.callback_url("abc123def456");
    assert_eq!(url, "http://10.0.0.1:8888/abc123def456");
}

#[test]
fn test_callback_dns() {
    let server = OobServer::new("attacker.com".to_string(), 8888, 5353);
    let dns = server.callback_dns("abc123def456");
    assert_eq!(dns, "abc123def456.attacker.com");
}

// ── Payload generation tests ──

#[test]
fn test_ssrf_payloads_coverage() {
    let payloads = oob::payloads::ssrf_payloads("http://callback.test/id123");

    let params: Vec<&str> = payloads.iter().map(|(p, _)| p.as_str()).collect();
    assert!(params.contains(&"url"), "Should include 'url' param");
    assert!(
        params.contains(&"redirect"),
        "Should include 'redirect' param"
    );
    assert!(
        params.contains(&"callback"),
        "Should include 'callback' param"
    );
    assert!(params.contains(&"dest"), "Should include 'dest' param");

    // All values should be the callback URL
    for (_, value) in &payloads {
        assert_eq!(value, "http://callback.test/id123");
    }
}

#[test]
fn test_xxe_payloads_content() {
    let payloads = oob::payloads::xxe_payloads("http://callback.test/xxe123");

    assert!(payloads.len() >= 3, "Should have at least 3 XXE variants");

    for payload in &payloads {
        assert!(
            payload.contains("http://callback.test/xxe123"),
            "XXE payload should contain callback URL"
        );
        assert!(
            payload.contains("<?xml"),
            "XXE payload should be valid XML"
        );
    }

    // Verify specific patterns
    assert!(
        payloads.iter().any(|p| p.contains("ENTITY xxe SYSTEM")),
        "Should have standard XXE entity"
    );
    assert!(
        payloads.iter().any(|p| p.contains("ENTITY % xxe")),
        "Should have parameter entity XXE"
    );
}

#[test]
fn test_sqli_oob_payloads() {
    let payloads =
        oob::payloads::sqli_oob_payloads("http://callback.test/sqli", "sqli.callback.test");

    assert!(
        payloads.len() >= 4,
        "Should have payloads for MySQL, MSSQL, Oracle, PostgreSQL"
    );

    let db_types: Vec<&str> = payloads.iter().map(|(t, _)| t.as_str()).collect();
    assert!(
        db_types.iter().any(|t| t.contains("MySQL")),
        "Should have MySQL payload"
    );
    assert!(
        db_types.iter().any(|t| t.contains("MSSQL")),
        "Should have MSSQL payload"
    );
    assert!(
        db_types.iter().any(|t| t.contains("Oracle")),
        "Should have Oracle payload"
    );
    assert!(
        db_types.iter().any(|t| t.contains("PostgreSQL")),
        "Should have PostgreSQL payload"
    );

    // MySQL uses callback URL
    let mysql = payloads.iter().find(|(t, _)| t.contains("MySQL")).unwrap();
    assert!(mysql.1.contains("LOAD_FILE"));

    // MSSQL uses DNS callback
    let mssql = payloads.iter().find(|(t, _)| t.contains("MSSQL")).unwrap();
    assert!(mssql.1.contains("xp_dirtree"));
    assert!(mssql.1.contains("sqli.callback.test"));
}

// ── OOB HTTP callback server integration ──

#[tokio::test]
async fn test_oob_http_callback_records_interaction() {
    // Use port 0 approach — start server on a random free port
    let store = oob::new_interaction_store();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();

    let http_store = store.clone();
    tokio::spawn(async move {
        // Re-bind the server on the same port (drop listener first)
        drop(listener);
        if let Err(e) = oob::http_server::start_http_server(port, http_store).await {
            eprintln!("HTTP server error: {}", e);
        }
    });

    // Give server time to start
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Send a request to the callback server
    let client = reqwest::Client::new();
    let res = client
        .get(format!("http://127.0.0.1:{}/testinteraction123", port))
        .send()
        .await;
    assert!(res.is_ok(), "Callback request should succeed");

    // Give server time to process
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let s = store.lock().await;
    assert!(
        s.contains_key("testinteraction123"),
        "Store should contain the interaction ID"
    );
    let interactions = &s["testinteraction123"];
    assert_eq!(interactions.len(), 1, "Should have exactly 1 interaction");
    assert_eq!(interactions[0].id, "testinteraction123");
}

// ── OobServer check_interaction ──

#[tokio::test]
async fn test_check_interaction_timeout() {
    let server = OobServer::new("127.0.0.1".to_string(), 19999, 19998);
    // Don't start — just test the polling timeout
    let result = server.check_interaction("nonexistent", 1).await;
    assert!(
        result.is_none(),
        "Should return None when no interaction received"
    );
}

#[tokio::test]
async fn test_check_interaction_found() {
    let server = OobServer::new("127.0.0.1".to_string(), 19997, 19996);

    // Manually insert an interaction into the store
    {
        let mut s = server.store.lock().await;
        s.entry("found123".to_string())
            .or_default()
            .push(oob::Interaction {
                id: "found123".to_string(),
                interaction_type: oob::InteractionType::Http,
                remote_addr: "127.0.0.1:12345".parse().unwrap(),
                timestamp: chrono::Utc::now(),
                raw_data: "test".to_string(),
            });
    }

    let result = server.check_interaction("found123", 2).await;
    assert!(result.is_some(), "Should find the pre-inserted interaction");
    let interactions = result.unwrap();
    assert_eq!(interactions.len(), 1);
    assert_eq!(interactions[0].id, "found123");
}

// ── OobScanner integration ──

#[tokio::test]
async fn test_oob_scanner_skips_when_disabled() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let config = ScanConfig {
        oob_enabled: false,
        ..test_config(&mock_server.uri())
    };

    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = OobScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");
    assert!(
        findings.is_empty(),
        "OOB scanner should return empty when disabled"
    );
}

#[tokio::test]
async fn test_oob_scanner_skips_without_host() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let config = ScanConfig {
        oob_enabled: true,
        oob_host: None,
        ..test_config(&mock_server.uri())
    };

    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = OobScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");
    assert!(
        findings.is_empty(),
        "OOB scanner should return empty when no host configured"
    );
}

#[tokio::test]
async fn test_oob_scanner_runs_with_config() {
    let mock_server = MockServer::start().await;

    let html = r#"<html><body>
        <form action="/search" method="get">
            <input name="url" type="text" />
        </form>
    </body></html>"#;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let config = ScanConfig {
        oob_enabled: true,
        oob_host: Some("127.0.0.1".to_string()),
        oob_http_port: 0, // will fail to bind but shouldn't crash
        oob_dns_port: 0,
        oob_timeout_secs: 1,
        ..test_config(&mock_server.uri())
    };

    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = OobScanner;

    // Should not panic even if OOB servers fail to start on port 0
    let result = scanner.scan(&client, &config, &[]).await;
    // We don't assert findings — just that it doesn't crash
    assert!(
        result.is_ok(),
        "OOB scanner should not crash: {:?}",
        result.err()
    );
}
