//! Integration tests for cookies, cors, info_disclosure, discovery, api, and waf scanners

use argos::http::{AuthConfig, HttpClient};
use argos::models::ScanConfig;
use argos::scanner::cookies::CookiesScanner;
use argos::scanner::cors::CorsScanner;
use argos::scanner::info_disclosure::InfoDisclosureScanner;
use argos::scanner::discovery::DiscoveryScanner;
use argos::scanner::api::ApiScanner;
use argos::scanner::waf::WafScanner;
use argos::scanner::Scanner;
use std::collections::HashMap;
use wiremock::matchers::{method, path, header};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn test_config(target: &str) -> ScanConfig {
    ScanConfig {
        target: target.to_string(),
        threads: 2,
        timeout_secs: 10,
        user_agent: "Argos-Test/0.1.0".to_string(),
        modules: vec![],
        follow_redirects: true,
        max_depth: 1,
        headers: HashMap::new(),
        rate_limit: None,
        auth: AuthConfig::None,
        ..ScanConfig::default()
    }
}

// ============================================================================
// Cookies Scanner Tests
// ============================================================================

#[tokio::test]
async fn test_cookies_missing_secure() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Set-Cookie", "track=abc123; HttpOnly; SameSite=Lax"),
        )
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = CookiesScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    let secure_finding = findings.iter().find(|f| f.title.contains("Missing Secure Flag"));
    assert!(
        secure_finding.is_some(),
        "Expected finding for missing Secure flag, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_cookies_missing_httponly() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Set-Cookie", "track=abc123; Secure; SameSite=Lax"),
        )
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = CookiesScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    let httponly_finding = findings.iter().find(|f| f.title.contains("Missing HttpOnly Flag"));
    assert!(
        httponly_finding.is_some(),
        "Expected finding for missing HttpOnly flag, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_cookies_missing_samesite() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Set-Cookie", "track=abc123; Secure; HttpOnly"),
        )
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = CookiesScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    let samesite_finding = findings.iter().find(|f| f.title.contains("Missing SameSite"));
    assert!(
        samesite_finding.is_some(),
        "Expected finding for missing SameSite, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_cookies_all_flags_present() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Set-Cookie", "track=abc123; Secure; HttpOnly; SameSite=Strict"),
        )
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = CookiesScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    assert!(
        findings.is_empty(),
        "Expected no findings when all flags are present, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_cookies_session_cookie_higher_severity() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Set-Cookie", "session_id=xyz789; SameSite=Lax"),
        )
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = CookiesScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    // session_id contains "session" so it should get High severity
    let high_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == argos::models::Severity::High)
        .collect();
    assert!(
        !high_findings.is_empty(),
        "Expected High severity findings for session cookie, got severities: {:?}",
        findings.iter().map(|f| (&f.title, &f.severity)).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_cookies_no_cookies() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = CookiesScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    assert!(
        findings.is_empty(),
        "Expected no findings when no cookies are set"
    );
}

// ============================================================================
// CORS Scanner Tests
// ============================================================================

#[tokio::test]
async fn test_cors_reflects_arbitrary_origin() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(header("Origin", "https://evil.com"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Access-Control-Allow-Origin", "https://evil.com"),
        )
        .mount(&mock_server)
        .await;

    // Also mount a fallback for the "null" origin test that the scanner makes
    Mock::given(method("GET"))
        .and(header("Origin", "null"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = CorsScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    let reflects = findings
        .iter()
        .find(|f| f.title.contains("Reflects Arbitrary Origin"));
    assert!(
        reflects.is_some(),
        "Expected CORS arbitrary origin reflection finding, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
    assert_eq!(reflects.expect("checked above").severity, argos::models::Severity::High);
}

#[tokio::test]
async fn test_cors_null_origin() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(header("Origin", "https://evil.com"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(header("Origin", "null"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Access-Control-Allow-Origin", "null"),
        )
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = CorsScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    let null_finding = findings
        .iter()
        .find(|f| f.title.contains("Null Origin"));
    assert!(
        null_finding.is_some(),
        "Expected CORS null origin finding, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
    assert_eq!(null_finding.expect("checked above").severity, argos::models::Severity::High);
}

#[tokio::test]
async fn test_cors_no_reflection() {
    let mock_server = MockServer::start().await;

    // No ACAO header at all
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = CorsScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    assert!(
        findings.is_empty(),
        "Expected no findings when CORS doesn't reflect, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_cors_wildcard_with_credentials() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(header("Origin", "https://evil.com"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Access-Control-Allow-Origin", "*")
                .insert_header("Access-Control-Allow-Credentials", "true"),
        )
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(header("Origin", "null"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Access-Control-Allow-Origin", "*")
                .insert_header("Access-Control-Allow-Credentials", "true"),
        )
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = CorsScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    let wildcard_finding = findings
        .iter()
        .find(|f| f.title.contains("Wildcard with Credentials"));
    assert!(
        wildcard_finding.is_some(),
        "Expected wildcard with credentials finding, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
    assert_eq!(
        wildcard_finding.expect("checked above").severity,
        argos::models::Severity::Medium
    );
}

// ============================================================================
// Info Disclosure Scanner Tests
// ============================================================================

#[tokio::test]
async fn test_info_disclosure_stack_trace() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("<html><body>Error: stack trace at com.example.Main(Main.java:42)</body></html>"),
        )
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = InfoDisclosureScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    let stack_finding = findings
        .iter()
        .find(|f| f.title.contains("Information Disclosure"));
    assert!(
        stack_finding.is_some(),
        "Expected stack trace info disclosure finding, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_info_disclosure_html_comment_password() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("<html><body><!-- password: admin123 --><p>Hello</p></body></html>"),
        )
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = InfoDisclosureScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    let comment_finding = findings
        .iter()
        .find(|f| f.title.contains("Sensitive HTML Comment"));
    assert!(
        comment_finding.is_some(),
        "Expected sensitive HTML comment finding, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_info_disclosure_directory_listing() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("<html><body><h1>Index of /uploads</h1><ul><li>file1.txt</li></ul></body></html>"),
        )
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = InfoDisclosureScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    let dir_finding = findings
        .iter()
        .find(|f| f.title.contains("Directory Listing"));
    assert!(
        dir_finding.is_some(),
        "Expected directory listing finding, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_info_disclosure_generator_meta() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(
                    r#"<html><head><meta name="generator" content="WordPress 6.0"></head><body>Hello</body></html>"#,
                ),
        )
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = InfoDisclosureScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    let gen_finding = findings
        .iter()
        .find(|f| f.title.contains("Generator Meta Tag"));
    assert!(
        gen_finding.is_some(),
        "Expected generator meta tag finding, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_info_disclosure_clean_page() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("<html><head><title>Welcome</title></head><body><p>Clean page.</p></body></html>"),
        )
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = InfoDisclosureScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    assert!(
        findings.is_empty(),
        "Expected no findings on clean page, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

// ============================================================================
// Discovery Scanner Tests
// ============================================================================

#[tokio::test]
async fn test_discovery_robots_txt() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/robots.txt"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("User-agent: *\nDisallow: /admin/\nDisallow: /private/"),
        )
        .mount(&mock_server)
        .await;

    // Default 404 for everything else
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
        .mount(&mock_server)
        .await;

    // OPTIONS returns 404 too
    Mock::given(method("OPTIONS"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = DiscoveryScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    let robots_finding = findings
        .iter()
        .find(|f| f.title.contains("Robots.txt"));
    assert!(
        robots_finding.is_some(),
        "Expected robots.txt finding, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
    assert!(
        robots_finding
            .expect("checked above")
            .evidence
            .contains("/admin/"),
        "Expected evidence to contain /admin/"
    );
}

#[tokio::test]
async fn test_discovery_env_file() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/.env"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("DB_HOST=localhost\nDB_PASS=secret123\nAPP_KEY=base64key"),
        )
        .mount(&mock_server)
        .await;

    // Default 404 for everything else
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404).set_body_string(""))
        .mount(&mock_server)
        .await;

    Mock::given(method("OPTIONS"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = DiscoveryScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    let env_finding = findings
        .iter()
        .find(|f| f.title.contains(".env"));
    assert!(
        env_finding.is_some(),
        "Expected .env sensitive file finding, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
    assert_eq!(
        env_finding.expect("checked above").severity,
        argos::models::Severity::Critical
    );
}

#[tokio::test]
async fn test_discovery_git_config() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/.git/config"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@github.com:example/repo.git"),
        )
        .mount(&mock_server)
        .await;

    // Default 404 for everything else
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404).set_body_string(""))
        .mount(&mock_server)
        .await;

    Mock::given(method("OPTIONS"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = DiscoveryScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    let git_finding = findings
        .iter()
        .find(|f| f.title.contains(".git/config"));
    assert!(
        git_finding.is_some(),
        "Expected .git/config finding, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
    assert_eq!(
        git_finding.expect("checked above").severity,
        argos::models::Severity::Critical
    );
}

#[tokio::test]
async fn test_discovery_soft_404() {
    let mock_server = MockServer::start().await;

    // Sensitive path returns 200 but body says "page not found" = soft 404
    Mock::given(method("GET"))
        .and(path("/.env"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("<html><body><h1>page not found</h1></body></html>"),
        )
        .mount(&mock_server)
        .await;

    // Default 404 for everything else
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404).set_body_string(""))
        .mount(&mock_server)
        .await;

    Mock::given(method("OPTIONS"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = DiscoveryScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    let env_finding = findings.iter().find(|f| f.title.contains(".env"));
    assert!(
        env_finding.is_none(),
        "Should NOT flag .env when body is a soft 404, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

// ============================================================================
// API Scanner Tests
// ============================================================================

#[tokio::test]
async fn test_api_swagger_docs_exposed() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/swagger"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(
                    r#"<html><head><title>Swagger UI</title></head><body><div id="swagger-ui"></div></body></html>"#,
                ),
        )
        .mount(&mock_server)
        .await;

    // OPTIONS for the discovered endpoint
    Mock::given(method("OPTIONS"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    // Default 404 for other endpoints
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404).set_body_string(""))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = ApiScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    let swagger_finding = findings
        .iter()
        .find(|f| f.title.contains("API Documentation Publicly Accessible"));
    assert!(
        swagger_finding.is_some(),
        "Expected swagger docs finding, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_api_unauthenticated_json() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(r#"{"users": [{"id": 1, "name": "admin"}]}"#),
        )
        .mount(&mock_server)
        .await;

    // OPTIONS for the discovered endpoint
    Mock::given(method("OPTIONS"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    // Default 404 for other endpoints
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404).set_body_string(""))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = ApiScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    let api_finding = findings
        .iter()
        .find(|f| f.title.contains("API Endpoint Without Authentication"));
    assert!(
        api_finding.is_some(),
        "Expected unauthenticated API finding, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_api_no_endpoints() {
    let mock_server = MockServer::start().await;

    // All API endpoints return 404
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404).set_body_string(""))
        .mount(&mock_server)
        .await;

    Mock::given(method("OPTIONS"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = ApiScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    assert!(
        findings.is_empty(),
        "Expected no findings when no API endpoints exist, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

// ============================================================================
// WAF Scanner Tests
// ============================================================================

#[tokio::test]
async fn test_waf_cloudflare_detection() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("cf-ray", "abc123-LAX")
                .insert_header("server", "cloudflare"),
        )
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = WafScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    let cf_finding = findings
        .iter()
        .find(|f| f.title.contains("Cloudflare"));
    assert!(
        cf_finding.is_some(),
        "Expected Cloudflare WAF detection finding, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
    assert_eq!(
        cf_finding.expect("checked above").severity,
        argos::models::Severity::Info
    );
}

#[tokio::test]
async fn test_waf_active_blocking() {
    let mock_server = MockServer::start().await;

    // The WAF scanner makes 2 baseline GETs (passive + active baseline),
    // then 5 probe GETs with malicious payloads.
    // We use up_to_n_times to make the first 2 requests return 200,
    // then subsequent requests fall through to the catch-all 403.
    // wiremock 0.6 matches mocks in FIFO order, so mount the limited one first.

    // Mount 200 response that only serves the first 2 requests (passive + baseline).
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Welcome"))
        .up_to_n_times(2)
        .mount(&mock_server)
        .await;

    // Mount catch-all 403 as fallback (matched after the above is exhausted).
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(403).set_body_string("Blocked"))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = WafScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    let blocking_finding = findings
        .iter()
        .find(|f| f.title.contains("Active Blocking"));
    assert!(
        blocking_finding.is_some(),
        "Expected WAF active blocking finding, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_waf_no_detection() {
    let mock_server = MockServer::start().await;

    // Clean server: no WAF headers, no blocking
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("server", "nginx")
                .set_body_string("<html><body>Hello World</body></html>"),
        )
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config).await.expect("client");
    let scanner = WafScanner;

    let findings = scanner.scan(&client, &config, &[]).await.expect("scan");

    assert!(
        findings.is_empty(),
        "Expected no WAF findings on clean server, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}
