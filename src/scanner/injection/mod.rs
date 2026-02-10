//! Advanced injection detection module
//!
//! Detects SQL Injection, XSS, Command Injection, SSTI, and Path Traversal.

pub mod command;
pub mod crlf;
pub mod open_redirect;
pub mod path_traversal;
pub mod sqli;
pub mod ssti;
pub mod xss;

use crate::error::Result;
use crate::http::HttpClient;
use crate::models::{Finding, ScanConfig};
use async_trait::async_trait;
use regex::Regex;
use scraper::{Html, Selector};
use std::collections::HashMap;
use tracing::{debug, info};
use url::Url;

// Re-export serde_json for JSON body injection point extraction
use serde_json;

/// Represents a prepared test request: (method, url, headers, optional body)
pub type TestRequest = (reqwest::Method, String, Vec<(String, String)>, Option<String>);

/// Detects injection vulnerabilities across multiple categories
pub struct InjectionScanner;

/// Type of injection point — determines how payloads are delivered
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointType {
    /// Query string parameter or form field
    QueryParam,
    /// HTTP header injection (Referer, X-Forwarded-For, etc.)
    Header,
    /// Cookie value injection
    Cookie,
    /// JSON body field injection
    JsonBody,
}

/// An injection point: URL + parameter names + delivery type
#[derive(Debug, Clone)]
pub struct InjectionPoint {
    pub url: String,
    pub params: Vec<String>,
    pub point_type: PointType,
    /// Original request body (used for JSON body fuzzing)
    pub original_body: Option<String>,
}

/// Baseline response for a specific (URL, param) pair.
/// Used to reduce false positives by comparing against normal responses.
#[derive(Debug, Clone)]
pub struct BaselineResponse {
    pub body: String,
    pub elapsed_ms: u64,
}

impl InjectionScanner {
    /// Parameters that should never be injection-tested (security tokens, nonces, CSRF, etc.)
    fn is_security_param(name: &str) -> bool {
        let lower = name.to_lowercase();
        lower.contains("nonce")
            || lower.contains("csrf")
            || lower.contains("token")
            || lower.contains("_wpnonce")
            || lower.contains("authenticity")
            || lower.contains("__requestverificationtoken")
            || lower.contains("viewstate")
            || lower.contains("eventvalidation")
            || lower.contains("antiforgery")
            || lower.contains("captcha")
            || lower.contains("recaptcha")
            || lower.contains("g-recaptcha")
            || lower.contains("h-captcha")
            || lower == "state"
            || lower == "sid"
            || lower == "_token"
    }

    /// Checks if a URL points to an OAuth/SSO flow (Google, Microsoft, GitHub, etc.)
    /// These URLs are often proxied through the target host, so same-host filtering
    /// doesn't catch them. We require BOTH a path pattern AND a param/domain indicator.
    pub fn is_oauth_url(url: &str) -> bool {
        let lower = url.to_lowercase();

        // Path patterns typical of OAuth/SSO flows
        let has_oauth_path = lower.contains("/oauth/")
            || lower.contains("/auth/callback")
            || lower.contains("/sso/")
            || lower.contains("/saml/")
            || lower.contains("/signin/")
            || lower.contains("/sign-in/")
            || lower.contains("/.well-known/openid")
            || lower.contains("/authorize")
            || lower.contains("/login/oauth");

        if !has_oauth_path {
            return false;
        }

        // Query param indicators of OAuth protocol
        let has_oauth_params = lower.contains("client_id=")
            || lower.contains("redirect_uri=")
            || lower.contains("response_type=")
            || lower.contains("scope=openid")
            || lower.contains("scope=email")
            || lower.contains("code_challenge=")
            || lower.contains("nonce=");

        // Known OAuth provider domains embedded in the URL
        let has_known_provider = lower.contains("accounts.google.com")
            || lower.contains("login.microsoftonline.com")
            || lower.contains("github.com/login/oauth")
            || lower.contains("login.live.com")
            || lower.contains("appleid.apple.com")
            || lower.contains("facebook.com/dialog/oauth")
            || lower.contains("login.yahoo.com");

        // Known provider names in the URL path (e.g., /oauth/google, /sso/microsoft)
        let has_provider_in_path = lower.contains("/oauth/google")
            || lower.contains("/oauth/microsoft")
            || lower.contains("/oauth/github")
            || lower.contains("/oauth/facebook")
            || lower.contains("/oauth/apple")
            || lower.contains("/oauth/yahoo")
            || lower.contains("/oauth/okta")
            || lower.contains("/oauth/auth0")
            || lower.contains("/oauth/keycloak")
            || lower.contains("/sso/google")
            || lower.contains("/sso/microsoft")
            || lower.contains("/sso/saml");

        has_oauth_params || has_known_provider || has_provider_in_path
    }

    /// Checks if a URL looks like garbage (JS code, template literals, etc.)
    fn is_junk_url(url: &str) -> bool {
        // JS string concatenation patterns crawled as URLs
        url.contains("' +") || url.contains("+ '")
            || url.contains("\" +") || url.contains("+ \"")
            // Template literals
            || url.contains("${") || url.contains("#{")
            // Clearly broken paths
            || url.contains("javascript:") || url.contains("data:")
            // Angular/Vue template expressions
            || url.contains("{{") || url.contains("}}")
    }

    /// Extracts injection points from HTML (forms, query params, links)
    pub fn extract_injection_points(base_url: &str, html: &str) -> Vec<InjectionPoint> {
        let document = Html::parse_document(html);
        let mut points = Vec::new();

        // Forms
        if let Ok(form_selector) = Selector::parse("form") {
            for form in document.select(&form_selector) {
                let action = form.value().attr("action").unwrap_or("");
                let form_url = if action.is_empty() || action == "#" {
                    base_url.to_string()
                } else if action.starts_with("http") {
                    action.to_string()
                } else {
                    format!(
                        "{}/{}",
                        base_url.trim_end_matches('/'),
                        action.trim_start_matches('/')
                    )
                };

                let mut params = Vec::new();
                if let Ok(input_sel) = Selector::parse("input[name]") {
                    for input in form.select(&input_sel) {
                        if let Some(name) = input.value().attr("name") {
                            if !Self::is_security_param(name) {
                                params.push(name.to_string());
                            }
                        }
                    }
                }
                if let Ok(ta_sel) = Selector::parse("textarea[name]") {
                    for ta in form.select(&ta_sel) {
                        if let Some(name) = ta.value().attr("name") {
                            if !Self::is_security_param(name) {
                                params.push(name.to_string());
                            }
                        }
                    }
                }
                if !params.is_empty() {
                    points.push(InjectionPoint {
                        url: form_url,
                        params,
                        point_type: PointType::QueryParam,
                        original_body: None,
                    });
                }
            }
        }

        // Query params from the URL itself
        if let Ok(parsed) = Url::parse(base_url) {
            if Self::is_oauth_url(base_url) {
                return points;
            }
            let params: Vec<String> = parsed.query_pairs()
                .map(|(k, _)| k.to_string())
                .filter(|k| !k.is_empty() && !Self::is_security_param(k))
                .collect();
            if !params.is_empty() {
                points.push(InjectionPoint {
                    url: base_url.to_string(),
                    params,
                    point_type: PointType::QueryParam,
                    original_body: None,
                });
            }
        }

        // Links with query params
        if let Ok(link_sel) = Selector::parse("a[href]") {
            for link in document.select(&link_sel) {
                if let Some(href) = link.value().attr("href") {
                    // Skip junk hrefs (JS code, template expressions) and OAuth/SSO
                    if Self::is_junk_url(href) || Self::is_oauth_url(href) {
                        continue;
                    }

                    let full_url = if href.starts_with("http") {
                        href.to_string()
                    } else if href.starts_with('/') {
                        if let Ok(base) = Url::parse(base_url) {
                            format!(
                                "{}://{}{}",
                                base.scheme(),
                                base.host_str().unwrap_or(""),
                                href
                            )
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    };

                    if let Ok(parsed) = Url::parse(&full_url) {
                        if let Ok(base_parsed) = Url::parse(base_url) {
                            if parsed.host_str() != base_parsed.host_str() {
                                continue;
                            }
                        }
                        let params: Vec<String> =
                            parsed.query_pairs()
                                .map(|(k, _)| k.to_string())
                                .filter(|k| !k.is_empty() && !Self::is_security_param(k))
                                .collect();
                        if !params.is_empty() {
                            points.push(InjectionPoint {
                                url: full_url,
                                params,
                                point_type: PointType::QueryParam,
                                original_body: None,
                            });
                        }
                    }
                }
            }
        }

        points
    }

    /// Builds a test URL by injecting a payload into a specific parameter
    pub fn build_test_url(base_url: &str, param: &str, payload: &str) -> Option<String> {
        let mut parsed = Url::parse(base_url).ok()?;
        let pairs: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| {
                if k == param {
                    (k.to_string(), payload.to_string())
                } else {
                    (k.to_string(), v.to_string())
                }
            })
            .collect();

        let has_param = pairs.iter().any(|(k, _)| k == param);
        parsed.set_query(None);
        let mut query_parts: Vec<String> = pairs.iter().map(|(k, v)| format!("{k}={v}")).collect();
        if !has_param {
            query_parts.push(format!("{param}={payload}"));
        }
        parsed.set_query(Some(&query_parts.join("&")));
        Some(parsed.to_string())
    }

    /// Loads payloads from a file, falling back to defaults
    pub fn load_payloads(path: &str, defaults: Vec<String>) -> Vec<String> {
        match std::fs::read_to_string(path) {
            Ok(content) => content
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect(),
            Err(_) => defaults,
        }
    }

    /// Gets a baseline response by sending a benign value for a parameter.
    /// Returns the response body and elapsed time for comparison.
    pub async fn get_baseline(
        client: &HttpClient,
        url: &str,
        param: &str,
    ) -> Option<BaselineResponse> {
        let benign_value = "argosbaselinetest123";
        let test_url = Self::build_test_url(url, param, benign_value)?;
        let start = std::time::Instant::now();
        let resp = client.get(&test_url).await.ok()?;
        let elapsed_ms = start.elapsed().as_millis() as u64;
        let body = resp.text().await.unwrap_or_default();
        Some(BaselineResponse { body, elapsed_ms })
    }

    /// Headers commonly injectable by attackers
    const INJECTABLE_HEADERS: &'static [&'static str] = &[
        "Referer",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "User-Agent",
        "Origin",
        "X-Original-URL",
        "X-Rewrite-URL",
    ];

    /// Extracts header-based injection points for a URL
    pub fn extract_header_points(url: &str) -> InjectionPoint {
        InjectionPoint {
            url: url.to_string(),
            params: Self::INJECTABLE_HEADERS
                .iter()
                .map(|h| h.to_string())
                .collect(),
            point_type: PointType::Header,
            original_body: None,
        }
    }

    /// Extracts cookie-based injection points from response Set-Cookie headers
    pub fn extract_cookie_points(url: &str, set_cookie_headers: &[String]) -> Option<InjectionPoint> {
        let mut cookie_names = Vec::new();
        for header in set_cookie_headers {
            // Parse "name=value; ..." format
            if let Some(name_value) = header.split(';').next() {
                if let Some(name) = name_value.split('=').next() {
                    let name = name.trim().to_string();
                    if !name.is_empty() {
                        cookie_names.push(name);
                    }
                }
            }
        }

        if cookie_names.is_empty() {
            return None;
        }

        Some(InjectionPoint {
            url: url.to_string(),
            params: cookie_names,
            point_type: PointType::Cookie,
            original_body: None,
        })
    }

    /// Extracts JSON body injection points from a response body
    pub fn extract_json_points(url: &str, json_body: &str) -> Option<InjectionPoint> {
        let parsed: serde_json::Value = serde_json::from_str(json_body).ok()?;
        let mut field_names = Vec::new();

        if let Some(obj) = parsed.as_object() {
            for key in obj.keys() {
                field_names.push(key.clone());
            }
        }

        if field_names.is_empty() {
            return None;
        }

        Some(InjectionPoint {
            url: url.to_string(),
            params: field_names,
            point_type: PointType::JsonBody,
            original_body: Some(json_body.to_string()),
        })
    }

    /// Builds a test request for non-query injection points.
    /// Returns (method, url, headers, body) tuple.
    pub fn build_test_request(
        point: &InjectionPoint,
        param: &str,
        payload: &str,
    ) -> Option<TestRequest> {
        match point.point_type {
            PointType::QueryParam => {
                let url = Self::build_test_url(&point.url, param, payload)?;
                Some((reqwest::Method::GET, url, vec![], None))
            }
            PointType::Header => {
                let headers = vec![(param.to_string(), payload.to_string())];
                Some((reqwest::Method::GET, point.url.clone(), headers, None))
            }
            PointType::Cookie => {
                let cookie_value = format!("{param}={payload}");
                let headers = vec![("Cookie".to_string(), cookie_value)];
                Some((reqwest::Method::GET, point.url.clone(), headers, None))
            }
            PointType::JsonBody => {
                let original = point.original_body.as_deref().unwrap_or("{}");
                let mut parsed: serde_json::Value =
                    serde_json::from_str(original).unwrap_or(serde_json::Value::Object(
                        serde_json::Map::new(),
                    ));
                if let Some(obj) = parsed.as_object_mut() {
                    obj.insert(
                        param.to_string(),
                        serde_json::Value::String(payload.to_string()),
                    );
                }
                let body = serde_json::to_string(&parsed).unwrap_or_default();
                let headers = vec![(
                    "Content-Type".to_string(),
                    "application/json".to_string(),
                )];
                Some((reqwest::Method::POST, point.url.clone(), headers, Some(body)))
            }
        }
    }

    /// Sends a test request using the appropriate method for the injection point type.
    /// Returns the response body and elapsed time.
    pub async fn send_test_request(
        client: &HttpClient,
        point: &InjectionPoint,
        param: &str,
        payload: &str,
    ) -> Option<(String, u64)> {
        let (method, url, headers, body) = Self::build_test_request(point, param, payload)?;
        let start = std::time::Instant::now();
        let resp = client
            .request(method, &url, &headers, body.as_deref())
            .await
            .ok()?;
        let elapsed_ms = start.elapsed().as_millis() as u64;
        let resp_body = resp.text().await.unwrap_or_default();
        Some((resp_body, elapsed_ms))
    }

    /// Gets a baseline response for any injection point type
    pub async fn get_baseline_generic(
        client: &HttpClient,
        point: &InjectionPoint,
        param: &str,
    ) -> Option<BaselineResponse> {
        let benign_value = "argosbaselinetest123";
        let (body, elapsed_ms) =
            Self::send_test_request(client, point, param, benign_value).await?;
        Some(BaselineResponse { body, elapsed_ms })
    }

    /// Checks response body for SQL error patterns and returns the DB type
    pub fn check_sql_errors(body: &str) -> Option<&'static str> {
        let patterns: &[(&str, &str)] = &[
            (r"(?i)you have an error in your sql syntax", "MySQL"),
            (r"(?i)warning:.*mysql", "MySQL"),
            (r"(?i)unclosed quotation mark", "MSSQL"),
            (r"(?i)microsoft sql server", "MSSQL"),
            (r"(?i)ora-\d{5}", "Oracle"),
            (r"(?i)postgresql.*error", "PostgreSQL"),
            (r"(?i)sqlite3?\.OperationalError", "SQLite"),
            (r"(?i)sql syntax.*error", "Generic SQL"),
            (r"(?i)sqlstate\[", "Generic SQL (PDO)"),
            (r"(?i)odbc.*driver", "ODBC"),
        ];

        for (pattern, db_type) in patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(body) {
                    return Some(db_type);
                }
            }
        }
        None
    }
}

#[async_trait]
impl super::Scanner for InjectionScanner {
    fn name(&self) -> &str {
        "injection"
    }

    fn description(&self) -> &str {
        "Detects injection vulnerabilities: SQLi, XSS, Command Injection, SSTI, Path Traversal, Open Redirect, CRLF"
    }

    async fn scan(
        &self,
        client: &HttpClient,
        config: &ScanConfig,
        crawled_urls: &[String],
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Collect injection points from all crawled URLs
        let mut injection_points = Vec::new();

        let urls_to_check: Vec<&str> = if crawled_urls.is_empty() {
            vec![config.target.as_str()]
        } else {
            crawled_urls.iter().map(|s| s.as_str()).collect()
        };

        for url in urls_to_check.iter().take(50) {
            // Skip junk URLs (JS code, template literals, etc.) and OAuth/SSO flows
            if Self::is_junk_url(url) || Self::is_oauth_url(url) {
                debug!("Skipping URL: {url}");
                continue;
            }
            if let Ok(response) = client.get(url).await {
                // Extract Set-Cookie headers for cookie injection points
                let set_cookies: Vec<String> = response
                    .headers()
                    .get_all("set-cookie")
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .map(|s| s.to_string())
                    .collect();

                let content_type = response
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();

                let body = response.text().await.unwrap_or_default();

                // Standard injection points (forms, query params, links)
                let points = Self::extract_injection_points(url, &body);
                injection_points.extend(points);

                // Header injection points (one per URL)
                injection_points.push(Self::extract_header_points(url));

                // Cookie injection points
                if !set_cookies.is_empty() {
                    if let Some(cookie_point) = Self::extract_cookie_points(url, &set_cookies) {
                        injection_points.push(cookie_point);
                    }
                }

                // JSON body injection points
                if content_type.contains("application/json") {
                    if let Some(json_point) = Self::extract_json_points(url, &body) {
                        injection_points.push(json_point);
                    }
                }
            }
        }

        // Filter out OAuth/SSO injection points (forms on non-OAuth pages can point to OAuth URLs)
        injection_points.retain(|p| !Self::is_oauth_url(&p.url));

        // Deduplicate query param points by URL
        injection_points.sort_by(|a, b| {
            a.url.cmp(&b.url).then(format!("{:?}", a.point_type).cmp(&format!("{:?}", b.point_type)))
        });
        injection_points.dedup_by(|a, b| a.url == b.url && a.point_type == b.point_type);

        info!("Found {} injection points", injection_points.len());

        if injection_points.is_empty() {
            debug!("No injection points found");
            return Ok(findings);
        }

        // Pre-compute baselines for each (url, param) pair
        info!("Computing baselines for injection point comparison");
        let mut baselines: HashMap<(String, String), BaselineResponse> = HashMap::new();
        for point in injection_points.iter().take(10) {
            for param in &point.params {
                let baseline = match point.point_type {
                    PointType::QueryParam => {
                        InjectionScanner::get_baseline(client, &point.url, param).await
                    }
                    _ => {
                        InjectionScanner::get_baseline_generic(client, point, param).await
                    }
                };
                if let Some(bl) = baseline {
                    baselines.insert((point.url.clone(), param.clone()), bl);
                }
            }
        }

        // Split injection points by type:
        // - Existing sub-scanners (sqli, xss, cmd, ssti, path_traversal) only support QueryParam
        // - Open redirect and CRLF support QueryParam only (URL-based)
        let query_points: Vec<InjectionPoint> = injection_points
            .iter()
            .filter(|p| p.point_type == PointType::QueryParam)
            .cloned()
            .collect();

        // Run sub-scanners with QueryParam points only
        let sqli_findings = sqli::scan(client, &query_points, &baselines).await;
        findings.extend(sqli_findings);

        let xss_findings = xss::scan(client, &query_points, crawled_urls, &baselines).await;
        findings.extend(xss_findings);

        let cmd_findings = command::scan(client, &query_points, &baselines).await;
        findings.extend(cmd_findings);

        let ssti_findings = ssti::scan(client, &query_points, &baselines).await;
        findings.extend(ssti_findings);

        let pt_findings = path_traversal::scan(client, &query_points).await;
        findings.extend(pt_findings);

        let redirect_findings =
            open_redirect::scan(client, &query_points, &baselines).await;
        findings.extend(redirect_findings);

        let crlf_findings = crlf::scan(client, &query_points, &baselines).await;
        findings.extend(crlf_findings);

        Ok(findings)
    }
}
