//! Full integration tests for injection sub-modules: SQLi, XSS, SSTI, Command, Path Traversal

use argos::http::{AuthConfig, HttpClient};
use argos::models::ScanConfig;
use argos::scanner::injection::InjectionScanner;
use argos::scanner::Scanner;
use std::collections::HashMap;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn test_config(target: &str) -> ScanConfig {
    ScanConfig {
        target: target.to_string(),
        threads: 2,
        timeout_secs: 10,
        user_agent: "Argos-Test/0.1.0".to_string(),
        modules: vec!["injection".to_string()],
        rate_limit: None,
        headers: HashMap::new(),
        auth: AuthConfig::None,
        ..ScanConfig::default()
    }
}

// ---------------------------------------------------------------------------
// InjectionScanner unit tests
// ---------------------------------------------------------------------------

#[test]
fn test_extract_injection_points_from_form() {
    let html = r#"<html><body>
        <form action="/search" method="get">
            <input name="q" type="text" />
            <input name="lang" type="hidden" value="en" />
            <button type="submit">Go</button>
        </form>
    </body></html>"#;

    let points = InjectionScanner::extract_injection_points("http://example.com", html);
    assert!(
        !points.is_empty(),
        "Should extract at least one injection point from form"
    );

    let form_point = &points[0];
    assert!(
        form_point.url.contains("/search"),
        "Form action URL should contain /search, got: {}",
        form_point.url
    );
    assert!(
        form_point.params.contains(&"q".to_string()),
        "Should extract param 'q'"
    );
    assert!(
        form_point.params.contains(&"lang".to_string()),
        "Should extract param 'lang'"
    );
}

#[test]
fn test_extract_injection_points_from_query_params() {
    let html = "<html><body>Nothing here</body></html>";
    let points =
        InjectionScanner::extract_injection_points("http://example.com/page?id=1&name=test", html);

    let query_point = points
        .iter()
        .find(|p| p.params.contains(&"id".to_string()))
        .expect("Should extract query params from base URL");

    assert!(
        query_point.params.contains(&"id".to_string()),
        "Should contain param 'id'"
    );
    assert!(
        query_point.params.contains(&"name".to_string()),
        "Should contain param 'name'"
    );
}

#[test]
fn test_extract_injection_points_from_links() {
    let html = r#"<html><body>
        <a href="/items?category=books&sort=asc">Books</a>
    </body></html>"#;

    let points = InjectionScanner::extract_injection_points("http://example.com", html);

    let link_point = points
        .iter()
        .find(|p| p.params.contains(&"category".to_string()))
        .expect("Should extract query params from links");

    assert!(
        link_point.params.contains(&"category".to_string()),
        "Should contain param 'category'"
    );
    assert!(
        link_point.params.contains(&"sort".to_string()),
        "Should contain param 'sort'"
    );
}

#[test]
fn test_build_test_url() {
    let result = InjectionScanner::build_test_url(
        "http://example.com/search?q=hello&lang=en",
        "q",
        "' OR 1=1--",
    );

    assert!(result.is_some(), "Should produce a valid URL");
    let url = result.unwrap();
    // The payload gets URL-encoded. The exact encoding depends on the URL library,
    // but the param 'q' should no longer contain the original value 'hello'.
    assert!(
        !url.contains("q=hello"),
        "Should replace original param value, got: {}",
        url
    );
    assert!(
        url.contains("lang=en"),
        "Should preserve other params, got: {}",
        url
    );
    // Verify the payload is encoded somewhere in the q param
    assert!(
        url.contains("q="),
        "Should still have q= parameter, got: {}",
        url
    );
}

#[test]
fn test_build_test_url_adds_param() {
    let result =
        InjectionScanner::build_test_url("http://example.com/page", "newparam", "testvalue");

    assert!(result.is_some(), "Should produce a valid URL");
    let url = result.unwrap();
    assert!(
        url.contains("newparam=testvalue"),
        "Should add the new param when not already present, got: {}",
        url
    );
}

#[test]
fn test_check_sql_errors_mysql() {
    let body = "Error: You have an error in your SQL syntax near 'test'";
    let result = InjectionScanner::check_sql_errors(body);
    assert_eq!(result, Some("MySQL"), "Should detect MySQL error");
}

#[test]
fn test_check_sql_errors_mssql() {
    let body = "Server error: Unclosed quotation mark after the character string 'x'.";
    let result = InjectionScanner::check_sql_errors(body);
    assert_eq!(result, Some("MSSQL"), "Should detect MSSQL error");
}

#[test]
fn test_check_sql_errors_oracle() {
    let body = "ORA-01756: quoted string not properly terminated";
    let result = InjectionScanner::check_sql_errors(body);
    assert_eq!(result, Some("Oracle"), "Should detect Oracle error");
}

#[test]
fn test_check_sql_errors_none() {
    let body = "<html><body><h1>Welcome to our site</h1><p>Normal content here.</p></body></html>";
    let result = InjectionScanner::check_sql_errors(body);
    assert!(result.is_none(), "Should return None for normal HTML body");
}

// ---------------------------------------------------------------------------
// SQLi integration tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_sqli_error_based_detection() {
    let mock_server = MockServer::start().await;

    // Main page with a form
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body><form action="/search"><input name="q" type="text"/></form></body></html>"#,
        ))
        .mount(&mock_server)
        .await;

    // Baseline request (benign value) returns a clean page
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("q", "argosbaselinetest123"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("<html><body><p>No results found.</p></body></html>"),
        )
        .mount(&mock_server)
        .await;

    // Any other request to /search returns a SQL error (simulating vulnerable endpoint)
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                "You have an error in your SQL syntax near 'test' at line 1",
            ),
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

    let sqli_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains("SQL Injection"))
        .collect();

    assert!(
        !sqli_findings.is_empty(),
        "Should detect error-based SQL injection. All findings: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_sqli_no_finding_when_error_in_baseline() {
    let mock_server = MockServer::start().await;

    // Main page with a form
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body><form action="/search"><input name="q" type="text"/></form></body></html>"#,
        ))
        .mount(&mock_server)
        .await;

    // ALL requests to /search return a SQL error (including baseline),
    // so the scanner should NOT report it as injection.
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                "Debug: You have an error in your SQL syntax near 'default_value'",
            ),
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

    let sqli_error_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains("SQL Injection (Error-Based)"))
        .collect();

    assert!(
        sqli_error_findings.is_empty(),
        "Should NOT report error-based SQLi when the error exists in baseline too. Found: {:?}",
        sqli_error_findings
            .iter()
            .map(|f| &f.title)
            .collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// XSS integration tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_xss_reflected_detection() {
    let mock_server = MockServer::start().await;

    let xss_payload = "<script>alert(1)</script>";

    // Main page with a form
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body><form action="/search"><input name="q" type="text"/></form></body></html>"#,
        ))
        .mount(&mock_server)
        .await;

    // Baseline request returns a clean page (no XSS payload)
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("q", "argosbaselinetest123"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("<html><body><p>No results found.</p></body></html>"),
        )
        .mount(&mock_server)
        .await;

    // Other requests to /search reflect the XSS payload back in the body
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"<html><body><p>Results for: {xss_payload}</p></body></html>"#
        )))
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

    let xss_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains("XSS"))
        .collect();

    assert!(
        !xss_findings.is_empty(),
        "Should detect reflected XSS. All findings: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_xss_no_finding_when_in_baseline() {
    let mock_server = MockServer::start().await;

    let xss_payload = "<script>alert(1)</script>";

    // Main page with a form
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body><form action="/search"><input name="q" type="text"/></form></body></html>"#,
        ))
        .mount(&mock_server)
        .await;

    // ALL responses from /search include the XSS payload (including baseline),
    // so the scanner should NOT flag it.
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"<html><body><p>Example: {xss_payload}</p></body></html>"#
        )))
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

    let reflected_xss: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains("Reflected XSS"))
        .collect();

    assert!(
        reflected_xss.is_empty(),
        "Should NOT report reflected XSS when the payload already exists in the baseline. Found: {:?}",
        reflected_xss.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_dom_xss_detection() {
    let mock_server = MockServer::start().await;

    // Main page with a form (so injection_points is not empty and the scanner
    // does not return early before reaching the DOM XSS checks)
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body><form action="/search"><input name="q" type="text"/></form></body></html>"#,
        ))
        .mount(&mock_server)
        .await;

    // Generic mock for /search so baseline and payload requests don't fail
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("<html><body><p>No results.</p></body></html>"),
        )
        .mount(&mock_server)
        .await;

    // Page with dangerous DOM sink + user-controlled source
    let dom_xss_html = r#"<html><body>
        <div id="output"></div>
        <script>
            var data = location.hash.substring(1);
            document.getElementById('output').innerHTML = data;
        </script>
    </body></html>"#;

    Mock::given(method("GET"))
        .and(path("/vulnerable"))
        .respond_with(ResponseTemplate::new(200).set_body_string(dom_xss_html))
        .mount(&mock_server)
        .await;

    let config = test_config(&mock_server.uri());
    let client = HttpClient::from_config(&config)
        .await
        .expect("Failed to create client");
    let scanner = InjectionScanner;

    // Pass both the main page (for injection points) and the vulnerable page (for DOM XSS)
    let crawled = vec![
        mock_server.uri(),
        format!("{}/vulnerable", mock_server.uri()),
    ];

    let findings = scanner
        .scan(&client, &config, &crawled)
        .await
        .expect("Scan failed");

    let dom_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains("DOM-Based XSS"))
        .collect();

    assert!(
        !dom_findings.is_empty(),
        "Should detect DOM-based XSS (innerHTML + location.hash). All findings: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// SSTI integration tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_ssti_detection() {
    let mock_server = MockServer::start().await;

    // Main page with a form
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body><form action="/render"><input name="tpl" type="text"/></form></body></html>"#,
        ))
        .mount(&mock_server)
        .await;

    // Baseline request returns a clean page without "49"
    Mock::given(method("GET"))
        .and(path("/render"))
        .and(query_param("tpl", "argosbaselinetest123"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("<html><body><p>Result: none</p></body></html>"),
        )
        .mount(&mock_server)
        .await;

    // Other requests to /render return "49" (simulating template evaluation)
    // Note: the response must NOT contain the raw payload "{{7*7}}"
    Mock::given(method("GET"))
        .and(path("/render"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("<html><body><p>Result: 49</p></body></html>"),
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

    let ssti_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains("Template Injection"))
        .collect();

    assert!(
        !ssti_findings.is_empty(),
        "Should detect SSTI when template expression evaluates to 49. All findings: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_ssti_no_finding_when_49_in_baseline() {
    let mock_server = MockServer::start().await;

    // Main page with a form
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body><form action="/render"><input name="tpl" type="text"/></form></body></html>"#,
        ))
        .mount(&mock_server)
        .await;

    // ALL responses from /render contain "49" (including baseline),
    // so the scanner should NOT flag it as SSTI.
    Mock::given(method("GET"))
        .and(path("/render"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                "<html><body><p>Item count: 49 products available</p></body></html>",
            ),
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

    let ssti_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains("Server-Side Template Injection"))
        .collect();

    assert!(
        ssti_findings.is_empty(),
        "Should NOT report SSTI when '49' is already in the baseline. Found: {:?}",
        ssti_findings
            .iter()
            .map(|f| &f.title)
            .collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// Command injection integration tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_command_injection_detection() {
    let mock_server = MockServer::start().await;

    // Main page with a form
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body><form action="/ping"><input name="host" type="text"/></form></body></html>"#,
        ))
        .mount(&mock_server)
        .await;

    // Baseline request returns a clean page
    Mock::given(method("GET"))
        .and(path("/ping"))
        .and(query_param("host", "argosbaselinetest123"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("<html><body><pre>PING argosbaselinetest123: unknown host</pre></body></html>"),
        )
        .mount(&mock_server)
        .await;

    // Other requests to /ping return command output (simulating injection)
    Mock::given(method("GET"))
        .and(path("/ping"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                "<html><body><pre>uid=1000(user) gid=1000(user) groups=1000(user)</pre></body></html>",
            ),
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

    let cmd_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains("Command Injection"))
        .collect();

    assert!(
        !cmd_findings.is_empty(),
        "Should detect OS command injection (uid= pattern). All findings: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_command_injection_baseline_filter() {
    let mock_server = MockServer::start().await;

    // Main page with a form
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body><form action="/info"><input name="detail" type="text"/></form></body></html>"#,
        ))
        .mount(&mock_server)
        .await;

    // ALL responses from /info contain the command output pattern (including baseline),
    // so the scanner should NOT report it.
    Mock::given(method("GET"))
        .and(path("/info"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                "<html><body><pre>uid=1000(webuser) gid=1000(webuser)</pre></body></html>",
            ),
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

    let cmd_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains("OS Command Injection"))
        .collect();

    assert!(
        cmd_findings.is_empty(),
        "Should NOT report command injection when pattern exists in baseline. Found: {:?}",
        cmd_findings
            .iter()
            .map(|f| &f.title)
            .collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// Path traversal integration tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_path_traversal_detection() {
    let mock_server = MockServer::start().await;

    // Main page with a form
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body><form action="/download"><input name="file" type="text"/></form></body></html>"#,
        ))
        .mount(&mock_server)
        .await;

    // Path traversal does not use baselines (see path_traversal.rs: scan takes no baselines param),
    // so all requests to /download return /etc/passwd content.
    Mock::given(method("GET"))
        .and(path("/download"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            ),
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

    let pt_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains("Path Traversal"))
        .collect();

    assert!(
        !pt_findings.is_empty(),
        "Should detect path traversal (root:x:0:0: pattern). All findings: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}
