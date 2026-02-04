//! Directory and endpoint discovery module

use crate::error::Result;
use crate::http::HttpClient;
use crate::models::{Finding, ScanConfig, Severity};
use async_trait::async_trait;
use futures::stream::{self, StreamExt};
use tracing::{debug, info};

/// Discovers hidden directories, endpoints, and sensitive files
pub struct DiscoveryScanner;

const SENSITIVE_FILES: &[(&str, &str, Severity)] = &[
    (".env", "Environment configuration file", Severity::Critical),
    (".git/config", "Git configuration file", Severity::Critical),
    (".git/HEAD", "Git HEAD reference", Severity::Critical),
    (
        "wp-config.php.bak",
        "WordPress config backup",
        Severity::Critical,
    ),
    ("database.sql", "Database dump", Severity::Critical),
    ("dump.sql", "Database dump", Severity::Critical),
    ("db.sql", "Database dump", Severity::Critical),
    (".htpasswd", "Apache password file", Severity::Critical),
    ("web.config", "IIS configuration file", Severity::High),
    (".htaccess", "Apache configuration file", Severity::Medium),
    ("phpinfo.php", "PHP info page", Severity::High),
    ("server-status", "Apache server status", Severity::High),
    ("server-info", "Apache server info", Severity::High),
    (".DS_Store", "macOS directory metadata", Severity::Low),
    ("Thumbs.db", "Windows thumbnail cache", Severity::Low),
    (
        "crossdomain.xml",
        "Flash cross-domain policy",
        Severity::Medium,
    ),
    (".svn/entries", "SVN metadata", Severity::High),
    ("error_log", "Error log file", Severity::Medium),
    ("access_log", "Access log file", Severity::Medium),
    ("xmlrpc.php", "XML-RPC endpoint", Severity::Medium),
    (
        "wp-json/wp/v2/users",
        "WordPress user enumeration",
        Severity::Medium,
    ),
    ("actuator", "Spring Boot actuator", Severity::High),
    (
        "actuator/env",
        "Spring Boot environment",
        Severity::Critical,
    ),
    (
        "actuator/heapdump",
        "Spring Boot heap dump",
        Severity::Critical,
    ),
];

/// Patterns in the response body that indicate a soft 404
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

/// Content indicators that confirm a sensitive file is real (not a soft 404)
fn is_plausible_sensitive_file(path: &str, body: &str) -> bool {
    let body_lower = body.to_lowercase();

    // If the body contains soft 404 patterns, it's not real
    if SOFT_404_PATTERNS
        .iter()
        .any(|pattern| body_lower.contains(pattern))
    {
        return false;
    }

    // Content-specific validation for known file types
    match path {
        ".env" => {
            // .env files contain KEY=VALUE pairs
            body.lines()
                .any(|line| line.contains('=') && !line.starts_with('<'))
        }
        ".git/config" => body.contains("[core]") || body.contains("[remote"),
        ".git/HEAD" => body.starts_with("ref: ") || body.len() == 41,
        ".htpasswd" => body.contains(':') && !body.contains('<'),
        ".htaccess" => {
            body.contains("RewriteRule")
                || body.contains("Deny from")
                || body.contains("Allow from")
                || body.contains("AuthType")
        }
        "web.config" => body.contains("<configuration") || body.contains("<system.web"),
        "phpinfo.php" => body.contains("phpinfo()") || body.contains("PHP Version"),
        "robots.txt" => body.contains("User-agent") || body.contains("Disallow"),
        "crossdomain.xml" => body.contains("<cross-domain-policy"),
        ".svn/entries" => body.contains("svn") || body.starts_with("10") || body.starts_with("12"),
        ".DS_Store" => !body.starts_with("<!") && !body.starts_with('<'),
        "Thumbs.db" => !body.starts_with("<!") && !body.starts_with('<'),
        "xmlrpc.php" => body.contains("XML-RPC") || body.contains("xmlrpc"),
        "wp-json/wp/v2/users" => body.starts_with('[') && body.contains("\"slug\""),
        "actuator" | "actuator/env" | "actuator/heapdump" => {
            body.starts_with('{') || body.contains("\"_links\"")
        }
        _ if path.ends_with(".sql") => {
            body.contains("CREATE TABLE")
                || body.contains("INSERT INTO")
                || body.contains("DROP TABLE")
        }
        _ if path.ends_with("_log") => !body.starts_with("<!") && !body.starts_with('<'),
        _ => true,
    }
}

impl DiscoveryScanner {
    fn load_wordlist(config: &ScanConfig) -> Vec<String> {
        let wordlist_path = config
            .wordlist_path
            .as_deref()
            .unwrap_or("wordlists/directories.txt");

        match std::fs::read_to_string(wordlist_path) {
            Ok(content) => content
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect(),
            Err(_) => {
                info!("Could not load wordlist from {wordlist_path}, using built-in defaults");
                vec![
                    "admin",
                    "login",
                    "dashboard",
                    "api",
                    "console",
                    "config",
                    "backup",
                    "test",
                    "staging",
                    "debug",
                    "docs",
                    "swagger",
                ]
                .into_iter()
                .map(String::from)
                .collect()
            }
        }
    }
}

#[async_trait]
impl super::Scanner for DiscoveryScanner {
    fn name(&self) -> &str {
        "discovery"
    }

    fn description(&self) -> &str {
        "Discovers hidden directories, sensitive files, and exposed endpoints"
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

        // Check robots.txt
        let robots_url = format!("{base_url}/robots.txt");
        if let Ok(response) = client.get(&robots_url).await {
            if response.status().is_success() {
                let body = response.text().await.unwrap_or_default();
                if body.contains("Disallow") {
                    let disallowed: Vec<&str> = body
                        .lines()
                        .filter(|l| l.starts_with("Disallow:"))
                        .filter_map(|l| l.strip_prefix("Disallow:").map(|p| p.trim()))
                        .filter(|p| !p.is_empty())
                        .collect();

                    if !disallowed.is_empty() {
                        findings.push(
                            Finding::new(
                                "Robots.txt Contains Disallowed Paths",
                                "The robots.txt reveals paths the site owner wants hidden from search engines.",
                                Severity::Info,
                                "Discovery",
                                &robots_url,
                            )
                            .with_evidence(format!("Disallowed paths:\n{}", disallowed.join("\n")))
                            .with_recommendation("Use proper authentication instead of relying on robots.txt for security."),
                        );
                    }
                }
            }
        }

        // Check sensitive files
        info!("Checking {} sensitive file paths", SENSITIVE_FILES.len());
        for (path, description, severity) in SENSITIVE_FILES {
            let url = format!("{base_url}/{path}");
            if let Ok(response) = client.get(&url).await {
                let status = response.status();
                if status.is_success() {
                    let body = response.text().await.unwrap_or_default();

                    // Validate that the content is actually the sensitive file, not a soft 404
                    if !is_plausible_sensitive_file(path, &body) {
                        debug!(
                            "Skipping {url}: HTTP 200 but content doesn't match expected file type"
                        );
                        continue;
                    }

                    // Also check against baseline soft 404
                    if is_soft_404(&body, &baseline_body) {
                        debug!("Skipping {url}: HTTP 200 but detected as soft 404");
                        continue;
                    }

                    findings.push(
                        Finding::new(
                            format!("Sensitive File Exposed: {path}"),
                            format!("{description} is publicly accessible."),
                            severity.clone(),
                            "Discovery",
                            &url,
                        )
                        .with_evidence(format!("GET {url} returned HTTP {status}"))
                        .with_recommendation(format!(
                            "Restrict access to '/{path}' via web server configuration."
                        ))
                        .with_cwe("CWE-538")
                        .with_owasp("A01:2021 Broken Access Control"),
                    );
                }
            }
        }

        // Directory brute-force
        let wordlist = Self::load_wordlist(config);
        info!("Running directory discovery with {} paths", wordlist.len());

        // Clone baseline for use in async closures
        let baseline_for_dirs = baseline_body.clone();

        let concurrency = config.threads;
        let discovered: Vec<Finding> = stream::iter(wordlist.into_iter())
            .map(|path| {
                let url = format!("{base_url}/{path}");
                let client_ref = client;
                let baseline_ref = &baseline_for_dirs;
                async move {
                    match client_ref.get(&url).await {
                        Ok(response) => {
                            let status = response.status();
                            match status.as_u16() {
                                200 => {
                                    let body = response.text().await.unwrap_or_default();

                                    // Filter out soft 404s
                                    if is_soft_404(&body, baseline_ref) {
                                        debug!("Skipping {url}: soft 404 detected");
                                        return None;
                                    }

                                    debug!("Found: {url} (200)");
                                    Some(
                                        Finding::new(
                                            format!("Directory/Endpoint Found: /{path}"),
                                            format!("The path '/{path}' is accessible."),
                                            Severity::Info,
                                            "Discovery",
                                            &url,
                                        )
                                        .with_evidence(format!("GET {url} returned HTTP {status}")),
                                    )
                                }
                                301 | 302 => {
                                    let location = response
                                        .headers()
                                        .get("location")
                                        .and_then(|v| v.to_str().ok())
                                        .unwrap_or("unknown");
                                    Some(
                                        Finding::new(
                                            format!("Redirect Found: /{path}"),
                                            format!("The path '/{path}' redirects."),
                                            Severity::Info,
                                            "Discovery",
                                            &url,
                                        )
                                        .with_evidence(
                                            format!("GET {url} -> {status} -> {location}"),
                                        ),
                                    )
                                }
                                403 => None,
                                _ => None,
                            }
                        }
                        Err(_) => None,
                    }
                }
            })
            .buffer_unordered(concurrency)
            .filter_map(|f| async { f })
            .collect()
            .await;

        findings.extend(discovered);
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
    if SOFT_404_PATTERNS
        .iter()
        .any(|pattern| body_lower.contains(pattern))
    {
        return true;
    }

    // Compare against baseline soft 404 body if available
    if let Some(ref baseline) = baseline_body {
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

    let len_ratio = len_a.min(len_b) as f64 / len_a.max(len_b) as f64;
    if len_ratio < 0.8 {
        return len_ratio;
    }

    let sample_a: String = a.chars().take(2000).collect();
    let sample_b: String = b.chars().take(2000).collect();

    let matching_chars = sample_a
        .chars()
        .zip(sample_b.chars())
        .filter(|(ca, cb)| ca == cb)
        .count();

    matching_chars as f64 / sample_a.len().max(sample_b.len()) as f64
}
