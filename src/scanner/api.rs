//! API security analysis module

use crate::error::Result;
use crate::http::HttpClient;
use crate::models::{Finding, ScanConfig, Severity};
use async_trait::async_trait;
use tracing::debug;

/// Analyzes API security characteristics
pub struct ApiScanner;

const API_ENDPOINTS: &[&str] = &[
    "/api",
    "/api/v1",
    "/api/v2",
    "/graphql",
    "/swagger",
    "/swagger-ui",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/docs",
];

/// Patterns in the response body that indicate a soft 404 / "not found" page
const SOFT_404_PATTERNS: &[&str] = &[
    "page not found",
    "not found",
    "404",
    "página no encontrada",
    "no encontrada",
    "does not exist",
    "no existe",
    "nothing here",
    "page doesn't exist",
    "we couldn't find",
    "no pudimos encontrar",
    "the page you",
    "la página que",
    "error 404",
    "recurso no encontrado",
    "resource not found",
];

/// Content type patterns that indicate actual API docs (not a generic HTML page)
const API_DOC_CONTENT_INDICATORS: &[&str] = &[
    "swagger",
    "openapi",
    "api-docs",
    "application/json",
    "\"paths\"",
    "\"info\"",
    "\"swagger\"",
    "\"openapi\"",
    "swagger-ui",
    "redoc",
    "try it out",
];

#[async_trait]
impl super::Scanner for ApiScanner {
    fn name(&self) -> &str {
        "api"
    }

    fn description(&self) -> &str {
        "Analyzes API security: authentication, rate limiting, methods, and error handling"
    }

    async fn scan(
        &self,
        client: &HttpClient,
        config: &ScanConfig,
        _crawled_urls: &[String],
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let base_url = config.target.trim_end_matches('/');

        // Get a baseline: request a known-nonexistent path to fingerprint the soft 404 page
        let baseline_body = get_soft_404_baseline(client, base_url).await;

        let mut api_endpoints: Vec<String> = Vec::new();
        for endpoint in API_ENDPOINTS {
            let url = format!("{base_url}{endpoint}");
            if let Ok(response) = client.get(&url).await {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();

                // Skip if this looks like a soft 404
                if status.is_success() && is_soft_404(&body, &baseline_body) {
                    debug!("Skipping {url}: HTTP 200 but detected as soft 404");
                    continue;
                }

                if status.is_success() || status.as_u16() == 401 || status.as_u16() == 403 {
                    debug!("API endpoint found: {url} ({status})");
                    api_endpoints.push(url.clone());

                    if (endpoint.contains("swagger")
                        || endpoint.contains("api-docs")
                        || endpoint.contains("openapi"))
                        && status.is_success()
                    {
                        // Verify the body actually contains API doc content
                        let body_lower = body.to_lowercase();
                        let has_api_content = API_DOC_CONTENT_INDICATORS
                            .iter()
                            .any(|indicator| body_lower.contains(indicator));

                        if has_api_content {
                            findings.push(
                                Finding::new(
                                    format!(
                                        "API Documentation Publicly Accessible: {endpoint}"
                                    ),
                                    "API documentation is publicly accessible, exposing the API surface.",
                                    Severity::Medium,
                                    "API Security",
                                    &url,
                                )
                                .with_evidence(format!("GET {url} returned HTTP {status}"))
                                .with_recommendation(
                                    "Restrict API docs to authenticated users or internal networks.",
                                )
                                .with_cwe("CWE-200")
                                .with_owasp("A01:2021 Broken Access Control"),
                            );
                        } else {
                            debug!("Skipping {url}: HTTP 200 but body has no API doc indicators");
                        }
                    }

                    if status.is_success()
                        && (endpoint.contains("/api") || endpoint.contains("/graphql"))
                        && (body.starts_with('{') || body.starts_with('['))
                    {
                        findings.push(
                            Finding::new(
                                format!("API Endpoint Without Authentication: {endpoint}"),
                                "An API endpoint returns data without authentication.",
                                Severity::Medium,
                                "API Security",
                                &url,
                            )
                            .with_evidence(format!("GET {url} returned HTTP 200 with JSON"))
                            .with_recommendation("Implement authentication for all API endpoints.")
                            .with_cwe("CWE-306")
                            .with_owasp("A07:2021 Identification and Authentication Failures"),
                        );
                    }
                }
            }
        }

        // Test HTTP methods on discovered endpoints
        for url in api_endpoints.iter().take(5) {
            if let Ok(response) = client.options(url).await {
                if let Some(allow) = response.headers().get("allow") {
                    let allow_str = allow.to_str().unwrap_or("");
                    debug!("Allowed methods for {url}: {allow_str}");

                    if allow_str.to_uppercase().contains("TRACE") {
                        findings.push(
                            Finding::new(
                                "HTTP TRACE Method Enabled",
                                "TRACE method is enabled, can be used for Cross-Site Tracing attacks.",
                                Severity::Medium,
                                "API Security",
                                url,
                            )
                            .with_evidence(format!("Allow: {allow_str}"))
                            .with_recommendation("Disable the TRACE HTTP method.")
                            .with_cwe("CWE-693")
                            .with_owasp("A05:2021 Security Misconfiguration"),
                        );
                    }
                }
            }
        }

        // Check for verbose error responses
        for url in api_endpoints.iter().take(3) {
            let error_url = format!("{url}/nonexistent-endpoint-argos-test");
            if let Ok(response) = client.get(&error_url).await {
                let status = response.status();
                if status.is_client_error() || status.is_server_error() {
                    let body = response.text().await.unwrap_or_default();
                    let verbose_indicators = [
                        "stack",
                        "trace",
                        "exception",
                        "debug",
                        "internal",
                        "file",
                        "line",
                    ];
                    let found: usize = verbose_indicators
                        .iter()
                        .filter(|i| body.to_lowercase().contains(&i.to_lowercase()))
                        .count();

                    if found >= 2 {
                        findings.push(
                            Finding::new(
                                "API Returns Verbose Error Information",
                                "API error responses contain detailed internal information.",
                                Severity::Medium,
                                "API Security",
                                &error_url,
                            )
                            .with_evidence(format!("HTTP {status} with verbose error indicators"))
                            .with_recommendation("Return generic error messages in production.")
                            .with_cwe("CWE-209")
                            .with_owasp("A05:2021 Security Misconfiguration"),
                        );
                    }
                }
            }
        }

        Ok(findings)
    }
}

/// Get a baseline response body for a known-nonexistent URL to detect soft 404s
async fn get_soft_404_baseline(client: &HttpClient, base_url: &str) -> Option<String> {
    let nonexistent = format!(
        "{}/argos-nonexistent-baseline-check-{}",
        base_url,
        uuid::Uuid::new_v4().simple()
    );

    match client.get(&nonexistent).await {
        Ok(response) => {
            if response.status().is_success() {
                // Server returns 200 for nonexistent pages — this is the soft 404 body
                Some(response.text().await.unwrap_or_default())
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

/// Determine if a response body is a soft 404
fn is_soft_404(body: &str, baseline_body: &Option<String>) -> bool {
    let body_lower = body.to_lowercase();

    // Check for common "not found" text patterns
    let has_not_found_text = SOFT_404_PATTERNS
        .iter()
        .any(|pattern| body_lower.contains(pattern));

    if has_not_found_text {
        return true;
    }

    // Compare against baseline soft 404 body if available
    if let Some(ref baseline) = baseline_body {
        // If the body is very similar to the baseline, it's a soft 404
        let similarity = body_similarity(body, baseline);
        if similarity > 0.85 {
            return true;
        }
    }

    false
}

/// Simple similarity ratio between two strings (0.0 to 1.0)
fn body_similarity(a: &str, b: &str) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }

    let len_a = a.len();
    let len_b = b.len();

    // Quick length-based check: if lengths differ by more than 20%, low similarity
    let len_ratio = len_a.min(len_b) as f64 / len_a.max(len_b) as f64;
    if len_ratio < 0.8 {
        return len_ratio;
    }

    // Compare a sample of the content (first 2000 chars)
    let sample_a: String = a.chars().take(2000).collect();
    let sample_b: String = b.chars().take(2000).collect();

    let matching_chars = sample_a
        .chars()
        .zip(sample_b.chars())
        .filter(|(ca, cb)| ca == cb)
        .count();

    matching_chars as f64 / sample_a.len().max(sample_b.len()) as f64
}
