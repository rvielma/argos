//! Integration tests for HttpClient and Crawler modules

use argos::crawler::Crawler;
use argos::http::{AuthConfig, HttpClient};
use argos::models::ScanConfig;
use std::collections::HashMap;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Helper to create a ScanConfig pointing at the given target
fn test_config(target: &str) -> ScanConfig {
    ScanConfig {
        target: target.to_string(),
        threads: 2,
        timeout_secs: 10,
        user_agent: "Argos-Test/0.1.0".to_string(),
        modules: vec![],
        rate_limit: None,
        headers: HashMap::new(),
        auth: AuthConfig::None,
        ..ScanConfig::default()
    }
}

// ---------------------------------------------------------------------------
// HttpClient tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_http_get_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/hello"))
        .respond_with(ResponseTemplate::new(200).set_body_string("hello world"))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config)
        .await
        .expect("failed to create client");

    let response = client
        .get(&format!("{}/hello", mock_server.uri()))
        .await
        .expect("GET request failed");

    assert_eq!(response.status().as_u16(), 200);
    let body = response.text().await.expect("failed to read body");
    assert_eq!(body, "hello world");
}

#[tokio::test]
async fn test_http_post_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/submit"))
        .respond_with(ResponseTemplate::new(201).set_body_string("created"))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config)
        .await
        .expect("failed to create client");

    let response = client
        .post(&format!("{}/submit", mock_server.uri()), "key=value")
        .await
        .expect("POST request failed");

    assert_eq!(response.status().as_u16(), 201);
    let body = response.text().await.expect("failed to read body");
    assert_eq!(body, "created");
}

#[tokio::test]
async fn test_http_request_count() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config)
        .await
        .expect("failed to create client");

    assert_eq!(client.request_count(), 0);

    for i in 1..=5 {
        let _ = client
            .get(&format!("{}/page{}", mock_server.uri(), i))
            .await;
    }

    assert_eq!(client.request_count(), 5);
}

#[tokio::test]
async fn test_http_without_auth() {
    // Server that requires Authorization header
    let auth_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/protected"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_string("authed"))
        .mount(&auth_server)
        .await;

    // Fallback for requests without the Authorization header
    Mock::given(method("GET"))
        .and(path("/public"))
        .respond_with(ResponseTemplate::new(200).set_body_string("public"))
        .mount(&auth_server)
        .await;

    let config = ScanConfig {
        target: auth_server.uri(),
        auth: AuthConfig::BearerToken {
            token: "test-token".to_string(),
        },
        rate_limit: None,
        ..test_config(&auth_server.uri())
    };

    let client = HttpClient::from_config(&config)
        .await
        .expect("failed to create client with auth");

    // Request with auth should carry the header
    let resp = client
        .get(&format!("{}/protected", auth_server.uri()))
        .await
        .expect("authed GET failed");
    assert_eq!(resp.text().await.expect("body"), "authed");

    // Create a no-auth clone and hit the public endpoint
    let no_auth_client = client.without_auth();
    let resp = no_auth_client
        .get(&format!("{}/public", auth_server.uri()))
        .await
        .expect("public GET failed");
    assert_eq!(resp.text().await.expect("body"), "public");
}

#[tokio::test]
async fn test_http_get_with_headers() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/custom"))
        .and(header("X-Custom-Header", "custom-value"))
        .respond_with(ResponseTemplate::new(200).set_body_string("headers ok"))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config)
        .await
        .expect("failed to create client");

    let headers = vec![("X-Custom-Header".to_string(), "custom-value".to_string())];

    let response = client
        .get_with_headers(&format!("{}/custom", mock_server.uri()), &headers)
        .await
        .expect("GET with headers failed");

    assert_eq!(response.status().as_u16(), 200);
    let body = response.text().await.expect("body");
    assert_eq!(body, "headers ok");
}

#[tokio::test]
async fn test_http_options() {
    let mock_server = MockServer::start().await;

    Mock::given(method("OPTIONS"))
        .and(path("/api"))
        .respond_with(
            ResponseTemplate::new(204).append_header("Allow", "GET, POST, OPTIONS"),
        )
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config)
        .await
        .expect("failed to create client");

    let response = client
        .options(&format!("{}/api", mock_server.uri()))
        .await
        .expect("OPTIONS request failed");

    assert_eq!(response.status().as_u16(), 204);
}

#[tokio::test]
async fn test_http_retry_on_rate_limit() {
    // The retry logic retries on 429 (TOO_MANY_REQUESTS) up to MAX_RETRIES (2).
    // When all attempts return 429, the client returns RateLimitExceeded.
    // We verify the client made exactly 2 attempts.
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/retry"))
        .respond_with(ResponseTemplate::new(429))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config)
        .await
        .expect("failed to create client");

    let result = client.get(&format!("{}/retry", mock_server.uri())).await;

    // All retries exhausted with 429 should yield an error
    assert!(result.is_err(), "expected error after all retries return 429");

    // The client should have made exactly 2 attempts (MAX_RETRIES)
    assert_eq!(client.request_count(), 2);
}

#[tokio::test]
async fn test_http_rate_limit_config() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("limited"))
        .mount(&mock_server)
        .await;

    let config = ScanConfig {
        rate_limit: Some(10),
        ..test_config(&mock_server.uri())
    };

    let client = HttpClient::from_config(&config)
        .await
        .expect("failed to create client with rate limit");

    // Even with rate limiting enabled, requests should complete successfully
    for _ in 0..3 {
        let response = client
            .get(&format!("{}/", mock_server.uri()))
            .await
            .expect("rate-limited GET failed");
        assert_eq!(response.status().as_u16(), 200);
    }

    assert_eq!(client.request_count(), 3);
}

// ---------------------------------------------------------------------------
// Crawler tests
// ---------------------------------------------------------------------------

/// Helper to create an HTML response with correct Content-Type.
/// wiremock's `set_body_string` forces Content-Type to text/plain,
/// so we use `set_body_raw` to set both body and content-type.
fn html_response(body: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(body, "text/html")
}

#[tokio::test]
async fn test_crawler_discovers_links() {
    let mock_server = MockServer::start().await;

    let root_html = r#"<html><body>
        <a href="/about">About</a>
        <a href="/contact">Contact</a>
        <a href="/services">Services</a>
    </body></html>"#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(html_response(root_html))
        .mount(&mock_server)
        .await;

    for p in ["/about", "/contact", "/services"] {
        Mock::given(method("GET"))
            .and(path(p))
            .respond_with(html_response("<html><body>leaf</body></html>"))
            .mount(&mock_server)
            .await;
    }

    let config = ScanConfig {
        max_depth: 2,
        ..test_config(&mock_server.uri())
    };
    let client = HttpClient::from_config(&config)
        .await
        .expect("client");

    let mut crawler = Crawler::new(&client, &config);
    let urls = crawler.crawl(&format!("{}/", mock_server.uri())).await;

    assert!(
        urls.len() >= 4,
        "expected at least 4 URLs, got {}: {:?}",
        urls.len(),
        urls
    );

    let urls_str = urls.join(" ");
    assert!(urls_str.contains("/about"), "missing /about");
    assert!(urls_str.contains("/contact"), "missing /contact");
    assert!(urls_str.contains("/services"), "missing /services");
}

#[tokio::test]
async fn test_crawler_depth_limiting() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(html_response(
            r#"<html><body><a href="/level1">Level 1</a></body></html>"#,
        ))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/level1"))
        .respond_with(html_response(
            r#"<html><body><a href="/level2">Level 2</a></body></html>"#,
        ))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/level2"))
        .respond_with(html_response(
            r#"<html><body><a href="/level3">Level 3</a></body></html>"#,
        ))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/level3"))
        .respond_with(html_response("<html><body>deep</body></html>"))
        .mount(&mock_server)
        .await;

    // max_depth=1: loop runs for depth 0 only, discovers /level1 from root
    let config = ScanConfig {
        max_depth: 1,
        ..test_config(&mock_server.uri())
    };
    let client = HttpClient::from_config(&config)
        .await
        .expect("client");

    let mut crawler = Crawler::new(&client, &config);
    let urls = crawler.crawl(&format!("{}/", mock_server.uri())).await;

    let urls_str = urls.join(" ");
    assert!(urls_str.contains("/level1"), "should discover /level1");
    assert!(
        !urls_str.contains("/level3"),
        "/level3 should NOT be reached at depth 1"
    );
}

#[tokio::test]
async fn test_crawler_deduplication() {
    let mock_server = MockServer::start().await;

    let root_html = r#"<html><body>
        <a href="/about">About 1</a>
        <a href="/about">About 2</a>
        <a href="/about/">About 3 (trailing slash)</a>
    </body></html>"#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(html_response(root_html))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/about"))
        .respond_with(html_response("<html><body>about</body></html>"))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/about/"))
        .respond_with(html_response("<html><body>about</body></html>"))
        .mount(&mock_server)
        .await;

    let config = ScanConfig {
        max_depth: 2,
        ..test_config(&mock_server.uri())
    };
    let client = HttpClient::from_config(&config)
        .await
        .expect("client");

    let mut crawler = Crawler::new(&client, &config);
    let urls = crawler.crawl(&format!("{}/", mock_server.uri())).await;

    let about_count = urls.iter().filter(|u| u.contains("/about")).count();

    assert_eq!(
        about_count, 1,
        "duplicate URLs should be deduplicated, but found {about_count}: {:?}",
        urls
    );
}

#[tokio::test]
async fn test_crawler_same_host_filter() {
    let mock_server = MockServer::start().await;

    let root_html = r#"<html><body>
        <a href="/internal">Internal</a>
        <a href="https://external-site.example.com/page">External</a>
    </body></html>"#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(html_response(root_html))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/internal"))
        .respond_with(html_response("<html><body>internal page</body></html>"))
        .mount(&mock_server)
        .await;

    let config = ScanConfig {
        max_depth: 2,
        ..test_config(&mock_server.uri())
    };
    let client = HttpClient::from_config(&config)
        .await
        .expect("client");

    let mut crawler = Crawler::new(&client, &config);
    let urls = crawler.crawl(&format!("{}/", mock_server.uri())).await;

    let urls_str = urls.join(" ");
    assert!(urls_str.contains("/internal"), "should discover /internal");

    let has_external = urls
        .iter()
        .any(|u| u.contains("external-site.example.com"));
    assert!(
        !has_external,
        "external URLs should be filtered out: {:?}",
        urls
    );
}

#[tokio::test]
async fn test_crawler_invalid_url() {
    let config = test_config("not-a-valid-url");
    let client = HttpClient::from_config(&config)
        .await
        .expect("client");

    let mut crawler = Crawler::new(&client, &config);
    let urls = crawler.crawl("not-a-valid-url").await;

    assert_eq!(urls.len(), 1);
    assert_eq!(urls[0], "not-a-valid-url");
}
