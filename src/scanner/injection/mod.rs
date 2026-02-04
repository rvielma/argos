//! Advanced injection detection module
//!
//! Detects SQL Injection, XSS, Command Injection, SSTI, and Path Traversal.

pub mod command;
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

/// Detects injection vulnerabilities across multiple categories
pub struct InjectionScanner;

/// An injection point: URL + parameter names
#[derive(Debug, Clone)]
pub struct InjectionPoint {
    pub url: String,
    pub params: Vec<String>,
}

/// Baseline response for a specific (URL, param) pair.
/// Used to reduce false positives by comparing against normal responses.
#[derive(Debug, Clone)]
pub struct BaselineResponse {
    pub body: String,
    pub elapsed_ms: u64,
}

impl InjectionScanner {
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
                            params.push(name.to_string());
                        }
                    }
                }
                if let Ok(ta_sel) = Selector::parse("textarea[name]") {
                    for ta in form.select(&ta_sel) {
                        if let Some(name) = ta.value().attr("name") {
                            params.push(name.to_string());
                        }
                    }
                }
                if !params.is_empty() {
                    points.push(InjectionPoint {
                        url: form_url,
                        params,
                    });
                }
            }
        }

        // Query params from the URL itself
        if let Ok(parsed) = Url::parse(base_url) {
            let params: Vec<String> = parsed.query_pairs().map(|(k, _)| k.to_string()).collect();
            if !params.is_empty() {
                points.push(InjectionPoint {
                    url: base_url.to_string(),
                    params,
                });
            }
        }

        // Links with query params
        if let Ok(link_sel) = Selector::parse("a[href]") {
            for link in document.select(&link_sel) {
                if let Some(href) = link.value().attr("href") {
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
                            parsed.query_pairs().map(|(k, _)| k.to_string()).collect();
                        if !params.is_empty() {
                            points.push(InjectionPoint {
                                url: full_url,
                                params,
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
        "Detects injection vulnerabilities: SQLi, XSS, Command Injection, SSTI, Path Traversal"
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
            if let Ok(response) = client.get(url).await {
                let body = response.text().await.unwrap_or_default();
                let points = Self::extract_injection_points(url, &body);
                injection_points.extend(points);
            }
        }

        // Deduplicate
        injection_points.sort_by(|a, b| a.url.cmp(&b.url));
        injection_points.dedup_by(|a, b| a.url == b.url);

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
                if let Some(baseline) =
                    InjectionScanner::get_baseline(client, &point.url, param).await
                {
                    baselines.insert((point.url.clone(), param.clone()), baseline);
                }
            }
        }

        // Run all injection sub-scanners
        let sqli_findings = sqli::scan(client, &injection_points, &baselines).await;
        findings.extend(sqli_findings);

        let xss_findings = xss::scan(client, &injection_points, crawled_urls, &baselines).await;
        findings.extend(xss_findings);

        let cmd_findings = command::scan(client, &injection_points, &baselines).await;
        findings.extend(cmd_findings);

        let ssti_findings = ssti::scan(client, &injection_points, &baselines).await;
        findings.extend(ssti_findings);

        let pt_findings = path_traversal::scan(client, &injection_points).await;
        findings.extend(pt_findings);

        Ok(findings)
    }
}
