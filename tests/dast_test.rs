//! Integration tests for the DAST scanner module

use argos::http::{AuthConfig, HttpClient};
use argos::models::ScanConfig;
use argos::scanner::dast::DastScanner;
use argos::scanner::Scanner;
use std::collections::HashMap;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn test_config(target: &str) -> ScanConfig {
    ScanConfig {
        target: target.to_string(),
        threads: 2,
        timeout_secs: 10,
        user_agent: "Argos-Test/0.1.0".to_string(),
        modules: vec!["dast".to_string()],
        follow_redirects: true,
        max_depth: 1,
        headers: HashMap::new(),
        rate_limit: None,
        auth: AuthConfig::None,
        ..ScanConfig::default()
    }
}

// ── CSRF Tests ──

#[tokio::test]
async fn test_csrf_missing_token() {
    let mock_server = MockServer::start().await;

    let html = r#"<html><body>
        <form method="post" action="/submit">
            <input name="username" type="text" />
            <input name="email" type="text" />
            <button type="submit">Submit</button>
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

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = DastScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    let csrf_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains("CSRF"))
        .collect();
    assert!(
        !csrf_findings.is_empty(),
        "Expected CSRF finding for form without token"
    );
    assert!(
        csrf_findings
            .iter()
            .any(|f| f.title.contains("Missing CSRF Token")),
        "Expected 'Missing CSRF Token' finding"
    );
}

#[tokio::test]
async fn test_csrf_with_token_present() {
    let mock_server = MockServer::start().await;

    let html = r#"<html><body>
        <form method="post" action="/submit">
            <input type="hidden" name="csrf_token" value="abc123xyz" />
            <input name="username" type="text" />
            <button type="submit">Submit</button>
        </form>
    </body></html>"#;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    // Server rejects without token = properly enforced
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = DastScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    let csrf_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains("CSRF"))
        .collect();
    assert!(
        csrf_findings.is_empty(),
        "Expected no CSRF findings when token is present and enforced, got: {:?}",
        csrf_findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_csrf_token_not_enforced() {
    let mock_server = MockServer::start().await;

    let html = r#"<html><body>
        <form method="post" action="/submit">
            <input type="hidden" name="_token" value="abc123xyz" />
            <input name="data" type="text" value="hello" />
            <button type="submit">Submit</button>
        </form>
    </body></html>"#;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    // Server accepts POST without token (200 = not enforced)
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = DastScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    let enforced: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains("Not Enforced"))
        .collect();
    assert!(
        !enforced.is_empty(),
        "Expected 'CSRF Token Not Enforced' finding"
    );
}

#[tokio::test]
async fn test_csrf_ignores_get_forms() {
    let mock_server = MockServer::start().await;

    let html = r#"<html><body>
        <form method="get" action="/search">
            <input name="q" type="text" />
            <button type="submit">Search</button>
        </form>
    </body></html>"#;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = DastScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    let csrf_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == "CSRF")
        .collect();
    assert!(
        csrf_findings.is_empty(),
        "Expected no CSRF findings for GET forms"
    );
}

// ── Access Control Tests ──

#[tokio::test]
async fn test_access_control_detects_unprotected_admin() {
    let mock_server = MockServer::start().await;

    let admin_content = "a]".repeat(200); // >200 bytes, not a login page

    Mock::given(method("GET"))
        .and(path("/admin/dashboard"))
        .respond_with(ResponseTemplate::new(200).set_body_string(&admin_content))
        .mount(&mock_server)
        .await;

    let config = ScanConfig {
        target: mock_server.uri(),
        threads: 2,
        timeout_secs: 10,
        user_agent: "Argos-Test/0.1.0".to_string(),
        modules: vec!["dast".to_string()],
        auth: AuthConfig::BearerToken {
            token: "test-token".to_string(),
        },
        rate_limit: None,
        headers: HashMap::new(),
        ..ScanConfig::default()
    };

    let client = HttpClient::from_config(&config).await.expect("client");
    let unauth_client = client.without_auth();

    let crawled = vec![format!("{}/admin/dashboard", mock_server.uri())];
    let findings =
        argos::scanner::dast::access::check_access_control(&unauth_client, &crawled).await;

    assert!(
        !findings.is_empty(),
        "Expected broken access control finding for /admin/dashboard"
    );
    assert!(findings[0].title.contains("Broken Access Control"));
}

#[tokio::test]
async fn test_access_control_ignores_login_redirect() {
    let mock_server = MockServer::start().await;

    let login_page = r#"<html><body>
        <h1>Login</h1>
        <form><input name="username"/><input name="password" type="password"/></form>
        <p>Please sign in to continue</p>
    </body></html>"#;

    Mock::given(method("GET"))
        .and(path("/admin/settings"))
        .respond_with(ResponseTemplate::new(200).set_body_string(login_page))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");

    let crawled = vec![format!("{}/admin/settings", mock_server.uri())];
    let findings = argos::scanner::dast::access::check_access_control(&client, &crawled).await;

    assert!(
        findings.is_empty(),
        "Should not flag login pages as broken access control"
    );
}

#[tokio::test]
async fn test_access_control_ignores_non_protected_urls() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Public content here"))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");

    let crawled = vec![
        format!("{}/about", mock_server.uri()),
        format!("{}/contact", mock_server.uri()),
        format!("{}/products", mock_server.uri()),
    ];
    let findings = argos::scanner::dast::access::check_access_control(&client, &crawled).await;

    assert!(
        findings.is_empty(),
        "Should not check non-protected URL patterns"
    );
}

// ── Session Tests ──

#[tokio::test]
async fn test_session_weak_entropy() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Set-Cookie", "sessionid=abc123; Path=/; HttpOnly"),
        )
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");

    let findings = argos::scanner::dast::session::check_session(&client, &mock_server.uri()).await;

    let entropy: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains("Weak Session ID Entropy"))
        .collect();
    assert!(
        !entropy.is_empty(),
        "Expected weak entropy finding for short session ID"
    );
}

#[tokio::test]
async fn test_session_good_entropy() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200).insert_header(
                "Set-Cookie",
                "sessionid=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6; Path=/; HttpOnly",
            ),
        )
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");

    let findings = argos::scanner::dast::session::check_session(&client, &mock_server.uri()).await;

    let entropy: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains("Weak Session ID Entropy"))
        .collect();
    assert!(
        entropy.is_empty(),
        "Should not flag session IDs with good entropy"
    );
}

#[tokio::test]
async fn test_session_no_cookies() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");

    let findings = argos::scanner::dast::session::check_session(&client, &mock_server.uri()).await;

    let session_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.category == "Session Management")
        .collect();
    assert!(
        session_findings.is_empty(),
        "Should not generate findings when no session cookies exist"
    );
}

// ── IDOR Tests ──

#[tokio::test]
async fn test_idor_detects_different_content() {
    let mock_server = MockServer::start().await;

    let user_100 = format!("User profile data for user 100. {}", "x".repeat(200));
    let user_101 = format!("User profile data for user 101. {}", "y".repeat(200));

    Mock::given(method("GET"))
        .and(wiremock::matchers::query_param("id", "100"))
        .respond_with(ResponseTemplate::new(200).set_body_string(&user_100))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(wiremock::matchers::query_param("id", "101"))
        .respond_with(ResponseTemplate::new(200).set_body_string(&user_101))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(wiremock::matchers::query_param("id", "99"))
        .respond_with(ResponseTemplate::new(200).set_body_string(&user_101))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");

    let test_url = format!("{}/profile?id=100", mock_server.uri());
    let findings = argos::scanner::dast::idor::check_idor(&client, &test_url).await;

    let idor: Vec<_> = findings.iter().filter(|f| f.category == "IDOR").collect();
    assert!(
        !idor.is_empty(),
        "Expected IDOR finding when adjacent IDs return different content"
    );
}

#[tokio::test]
async fn test_idor_no_numeric_params() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");

    let test_url = format!("{}/page?name=test", mock_server.uri());
    let findings = argos::scanner::dast::idor::check_idor(&client, &test_url).await;

    assert!(
        findings.is_empty(),
        "Should not generate IDOR findings for non-numeric/non-id params"
    );
}

#[tokio::test]
async fn test_idor_identical_responses() {
    let mock_server = MockServer::start().await;

    let same_content = format!("Same page for everyone. {}", "z".repeat(200));

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(&same_content))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");

    let test_url = format!("{}/item?id=50", mock_server.uri());
    let findings = argos::scanner::dast::idor::check_idor(&client, &test_url).await;

    let idor: Vec<_> = findings.iter().filter(|f| f.category == "IDOR").collect();
    assert!(
        idor.is_empty(),
        "Should not flag IDOR when all IDs return identical content"
    );
}

// ── DastScanner Integration ──

#[tokio::test]
async fn test_dast_scanner_no_crash_on_empty() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html><body>Hello</body></html>"))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = DastScanner;

    let result = scanner.scan(&client, &config, &[]).await;
    assert!(result.is_ok(), "DAST scanner should not crash on empty page");
}

#[tokio::test]
async fn test_dast_skips_access_control_without_auth() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("<html><body>Admin panel content</body></html>"),
        )
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri()); // auth = None
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = DastScanner;

    let crawled = vec![format!("{}/admin/dashboard", mock_server.uri())];
    let findings = scanner
        .scan(&client, &config, &crawled)
        .await
        .expect("scan");

    let access: Vec<_> = findings
        .iter()
        .filter(|f| f.category == "Access Control")
        .collect();
    assert!(
        access.is_empty(),
        "Should skip access control checks when no auth is configured"
    );
}
