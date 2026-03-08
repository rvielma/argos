//! Web crawler/spider for URL discovery
//!
//! Concurrent BFS crawler with deduplication, depth limiting, and rate limiting.
//! Discovers URLs by parsing HTML, JavaScript, JSON, comments, sitemap.xml, and robots.txt.

pub mod browser;
pub mod extractor;
pub mod spa_detector;

use crate::http::HttpClient;
use crate::models::ScanConfig;
use extractor::FormInfo;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, info, warn};
use url::Url;

/// Result of a crawl including URLs, forms, and dedup info
#[derive(Debug, Clone, Default)]
pub struct CrawlResult {
    /// All discovered URLs
    pub urls: Vec<String>,
    /// Collected forms with parameters
    pub forms: Vec<FormInfo>,
    /// Normalized path patterns for dedup (e.g., /user/:id)
    pub path_patterns: HashMap<String, String>,
}

/// Concurrent BFS web crawler that discovers URLs within a target site
pub struct Crawler<'a> {
    client: &'a HttpClient,
    max_depth: u32,
    max_urls: usize,
    concurrency: usize,
    render_enabled: bool,
    include_subdomains: bool,
    #[cfg_attr(not(feature = "browser"), allow(dead_code))]
    render_wait_ms: u64,
}

impl<'a> Crawler<'a> {
    pub fn new(client: &'a HttpClient, config: &ScanConfig) -> Self {
        Self {
            client,
            max_depth: config.max_depth,
            max_urls: config.max_urls,
            concurrency: config.threads.max(1),
            render_enabled: config.render_enabled,
            include_subdomains: config.include_subdomains,
            render_wait_ms: config.render_wait_ms,
        }
    }

    /// Crawls the target URL concurrently and returns a CrawlResult with all discovered data
    pub async fn crawl(&mut self, start_url: &str) -> Vec<String> {
        let result = self.crawl_full(start_url).await;
        result.urls
    }

    /// Full crawl returning CrawlResult with URLs, forms, and path patterns
    pub async fn crawl_full(&mut self, start_url: &str) -> CrawlResult {
        let base_url = match Url::parse(start_url) {
            Ok(u) => u,
            Err(e) => {
                warn!("Invalid start URL for crawler: {e}");
                return CrawlResult {
                    urls: vec![start_url.to_string()],
                    ..Default::default()
                };
            }
        };

        let base_host = base_url.host_str().unwrap_or("").to_string();
        let base_domain = extract_base_domain(&base_host);
        let include_subdomains = self.include_subdomains;

        let visited = Arc::new(Mutex::new(HashSet::new()));
        let discovered = Arc::new(Mutex::new(Vec::new()));
        let all_forms = Arc::new(Mutex::new(Vec::new()));
        let js_fetched = Arc::new(Mutex::new(HashSet::new()));
        let path_patterns: Arc<Mutex<HashMap<String, String>>> =
            Arc::new(Mutex::new(HashMap::new()));

        {
            let mut v = visited.lock().await;
            v.insert(normalize_url(start_url));
            let mut d = discovered.lock().await;
            d.push(start_url.to_string());
        }

        // Phase 0: Seed with sitemap.xml and robots.txt
        let seed_urls = self.fetch_seed_urls(&base_url).await;
        if !seed_urls.is_empty() {
            info!("Seeded {} URLs from sitemap.xml/robots.txt", seed_urls.len());
            let mut v = visited.lock().await;
            let mut d = discovered.lock().await;
            for url in &seed_urls {
                let normalized = normalize_url(url);
                if !v.contains(&normalized) && d.len() < self.max_urls {
                    v.insert(normalized);
                    d.push(url.clone());
                }
            }
        }

        // BFS crawl
        let mut current_layer = {
            let d = discovered.lock().await;
            d.clone()
        };

        for depth in 0..self.max_depth {
            if current_layer.is_empty() {
                break;
            }

            let discovered_count = discovered.lock().await.len();
            if discovered_count >= self.max_urls {
                break;
            }

            let semaphore = Arc::new(Semaphore::new(self.concurrency));

            #[derive(Default)]
            struct PageResult {
                new_urls: Vec<String>,
                forms: Vec<FormInfo>,
                js_urls: Vec<String>,
            }

            let (tx, mut rx) =
                tokio::sync::mpsc::channel::<PageResult>(current_layer.len() + 1);

            let mut handles = Vec::new();

            for url in current_layer.drain(..) {
                let sem = Arc::clone(&semaphore);
                let client = self.client.clone();
                let base_host = base_host.clone();
                let base_domain = base_domain.clone();
                let tx = tx.clone();
                let js_fetched = Arc::clone(&js_fetched);

                let handle = tokio::spawn(async move {
                    let _permit = match sem.acquire().await {
                        Ok(p) => p,
                        Err(_) => return,
                    };

                    let (body, content_type) = match fetch_body_with_type(&client, &url).await {
                        Some(b) => b,
                        None => return,
                    };

                    let page_url = match Url::parse(&url) {
                        Ok(u) => u,
                        Err(_) => return,
                    };

                    let is_json = content_type.contains("application/json");
                    let is_js = content_type.contains("javascript");

                    let mut result = PageResult::default();

                    if is_json {
                        // Parse JSON responses for URLs
                        result.new_urls.extend(extractor::extract_from_json(&page_url, &body));
                    } else if is_js {
                        // Pure JS file
                        result.new_urls.extend(extractor::extract_from_js(&page_url, &body));
                    } else {
                        // HTML page
                        result.new_urls.extend(extractor::extract_from_html(&page_url, &body));
                        result.new_urls.extend(extractor::extract_from_js(&page_url, &body));
                        result.new_urls.extend(extractor::extract_from_comments(&page_url, &body));
                        result.forms = extractor::extract_forms(&page_url, &body);

                        // Collect JS file URLs to fetch separately
                        let js_srcs = extractor::extract_script_srcs(&page_url, &body);
                        let mut fetched = js_fetched.lock().await;
                        for js_url in js_srcs {
                            if !fetched.contains(&js_url) {
                                fetched.insert(js_url.clone());
                                result.js_urls.push(js_url);
                            }
                        }
                    }

                    // Filter to scope (same host or subdomain)
                    let host_filter = |u: &String| -> bool {
                        if let Ok(parsed) = Url::parse(u) {
                            let host = parsed.host_str().unwrap_or("");
                            if include_subdomains {
                                host == base_host || host.ends_with(&format!(".{base_domain}"))
                            } else {
                                host == base_host
                            }
                        } else {
                            false
                        }
                    };

                    result.new_urls.retain(host_filter);

                    let _ = tx.send(result).await;
                });

                handles.push(handle);
            }

            drop(tx);

            // Collect results
            let mut next_layer = Vec::new();
            let mut js_to_fetch = Vec::new();
            let mut limit_reached = false;

            while let Some(page_result) = rx.recv().await {
                let mut v = visited.lock().await;
                let mut d = discovered.lock().await;
                let mut patterns = path_patterns.lock().await;

                for url in page_result.new_urls {
                    if d.len() >= self.max_urls {
                        limit_reached = true;
                        break;
                    }
                    let normalized = normalize_url(&url);
                    if !v.contains(&normalized) {
                        // Smart path dedup
                        let pattern = normalize_path_pattern(&url);
                        if let Some(existing) = patterns.get(&pattern) {
                            debug!("Skipping duplicate pattern: {} (same as {})", url, existing);
                            continue;
                        }
                        patterns.insert(pattern, url.clone());
                        v.insert(normalized);
                        d.push(url.clone());
                        next_layer.push(url);
                    }
                }

                // Collect forms
                if !page_result.forms.is_empty() {
                    let mut forms = all_forms.lock().await;
                    forms.extend(page_result.forms);
                }

                // Collect JS files to fetch
                js_to_fetch.extend(page_result.js_urls);
            }

            // Fetch JS files discovered in this layer
            if !js_to_fetch.is_empty() && !limit_reached {
                let js_urls = self
                    .fetch_js_files(&base_url, &base_host, &base_domain, &js_to_fetch)
                    .await;
                let mut v = visited.lock().await;
                let mut d = discovered.lock().await;
                let mut patterns = path_patterns.lock().await;
                for url in js_urls {
                    if d.len() >= self.max_urls {
                        break;
                    }
                    let normalized = normalize_url(&url);
                    if !v.contains(&normalized) {
                        let pattern = normalize_path_pattern(&url);
                        if patterns.contains_key(&pattern) {
                            continue;
                        }
                        patterns.insert(pattern, url.clone());
                        v.insert(normalized);
                        d.push(url.clone());
                        next_layer.push(url);
                    }
                }
            }

            if limit_reached {
                info!("Crawler reached max URL limit ({})", self.max_urls);
                break;
            }

            // Wait for all spawned tasks
            for handle in handles {
                let _ = handle.await;
            }

            debug!(
                "Crawler depth {} complete, {} new URLs",
                depth,
                next_layer.len()
            );
            current_layer = next_layer;
        }

        let mut result_urls = discovered.lock().await.clone();

        // Browser rendering pass
        if self.render_enabled {
            result_urls = self.render_pass(result_urls, &base_url).await;
        }

        let forms = all_forms.lock().await.clone();
        let patterns = path_patterns.lock().await.clone();

        info!(
            "Crawler finished: {} URLs, {} forms discovered",
            result_urls.len(),
            forms.len()
        );

        CrawlResult {
            urls: result_urls,
            forms,
            path_patterns: patterns,
        }
    }

    /// Fetch sitemap.xml and robots.txt for seed URLs
    async fn fetch_seed_urls(&self, base_url: &Url) -> Vec<String> {
        let mut seeds = Vec::new();
        let base_host = base_url.host_str().unwrap_or("");

        // Try sitemap.xml
        let sitemap_url = format!("{}://{}/sitemap.xml", base_url.scheme(), base_url.host_str().unwrap_or(""));
        if let Some(body) = fetch_body(self.client, &sitemap_url).await {
            let sitemap_urls = parse_sitemap(&body, base_url);
            debug!("Found {} URLs in sitemap.xml", sitemap_urls.len());
            seeds.extend(sitemap_urls);
        }

        // Try robots.txt
        let robots_url = format!("{}://{}/robots.txt", base_url.scheme(), base_url.host_str().unwrap_or(""));
        if let Some(body) = fetch_body(self.client, &robots_url).await {
            let robots_urls = parse_robots_txt(&body, base_url, base_host);
            debug!("Found {} URLs/paths in robots.txt", robots_urls.len());
            seeds.extend(robots_urls);
        }

        seeds
    }

    /// Fetch JavaScript files and extract URLs from their content
    async fn fetch_js_files(
        &self,
        base_url: &Url,
        base_host: &str,
        base_domain: &str,
        js_urls: &[String],
    ) -> Vec<String> {
        let mut discovered = Vec::new();
        let include_subs = self.include_subdomains;

        for js_url in js_urls.iter().take(50) {
            if let Some(body) = fetch_body(self.client, js_url).await {
                let page_url = match Url::parse(js_url) {
                    Ok(u) => u,
                    Err(_) => base_url.clone(),
                };
                let mut urls = extractor::extract_from_js(&page_url, &body);
                urls.retain(|u| {
                    if let Ok(parsed) = Url::parse(u) {
                        let host = parsed.host_str().unwrap_or("");
                        if include_subs {
                            host == base_host || host.ends_with(&format!(".{base_domain}"))
                        } else {
                            host == base_host
                        }
                    } else {
                        false
                    }
                });
                discovered.extend(urls);
            }
        }

        debug!("Fetched {} JS files, found {} new URLs", js_urls.len().min(50), discovered.len());
        discovered
    }

    /// Renders pages with headless browser to discover additional URLs
    #[cfg(feature = "browser")]
    async fn render_pass(&self, urls: Vec<String>, base_url: &Url) -> Vec<String> {
        use browser::BrowserRenderer;

        let renderer = match BrowserRenderer::new().await {
            Ok(r) => r,
            Err(e) => {
                warn!("Browser rendering unavailable: {e}. Continuing with HTTP-only crawl.");
                return urls;
            }
        };

        let base_host = base_url.host_str().unwrap_or("").to_string();
        let mut all_urls: HashSet<String> = urls.iter().map(|u| normalize_url(u)).collect();
        let mut result = urls;

        let render_limit = 20.min(result.len());
        for url in result.iter().take(render_limit).cloned().collect::<Vec<_>>() {
            match renderer.render(&url, self.render_wait_ms).await {
                Ok(page) => {
                    for new_url in page.urls {
                        if let Ok(parsed) = Url::parse(&new_url) {
                            if parsed.host_str() == Some(&base_host) {
                                let normalized = normalize_url(&new_url);
                                if !all_urls.contains(&normalized) {
                                    all_urls.insert(normalized);
                                    result.push(new_url);
                                }
                            }
                        }
                    }

                    if let Ok(page_url) = Url::parse(&url) {
                        let html_urls = extractor::extract_from_html(&page_url, &page.html);
                        for new_url in html_urls {
                            if let Ok(parsed) = Url::parse(&new_url) {
                                if parsed.host_str() == Some(&base_host) {
                                    let normalized = normalize_url(&new_url);
                                    if !all_urls.contains(&normalized) {
                                        all_urls.insert(normalized);
                                        result.push(new_url);
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("Browser render failed for {url}: {e}");
                }
            }
        }

        info!(
            "Browser rendering discovered {} additional URLs",
            result.len().saturating_sub(render_limit)
        );
        result
    }

    /// Stub when browser feature is not enabled
    #[cfg(not(feature = "browser"))]
    async fn render_pass(&self, urls: Vec<String>, _base_url: &Url) -> Vec<String> {
        warn!("Browser rendering requested but 'browser' feature not enabled. Compile with: cargo build --features browser");
        urls
    }
}

/// Parse sitemap.xml content and extract URLs
fn parse_sitemap(xml: &str, base_url: &Url) -> Vec<String> {
    let mut urls = Vec::new();
    let loc_re = Regex::new(r"<loc>\s*(.*?)\s*</loc>").expect("valid regex");

    for cap in loc_re.captures_iter(xml) {
        if let Some(m) = cap.get(1) {
            let url = m.as_str().trim();
            if let Some(resolved) = extractor::resolve_url(base_url, url) {
                urls.push(resolved);
            }
        }
    }

    // Also check for nested sitemaps
    let sitemap_re = Regex::new(r"<sitemap>\s*<loc>\s*(.*?)\s*</loc>").expect("valid regex");
    for cap in sitemap_re.captures_iter(xml) {
        if let Some(m) = cap.get(1) {
            let url = m.as_str().trim();
            if let Some(resolved) = extractor::resolve_url(base_url, url) {
                urls.push(resolved);
            }
        }
    }

    urls
}

/// Parse robots.txt and extract Disallow/Allow/Sitemap paths
fn parse_robots_txt(content: &str, base_url: &Url, _base_host: &str) -> Vec<String> {
    let mut urls = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(path) = line
            .strip_prefix("Disallow:")
            .or_else(|| line.strip_prefix("Allow:"))
        {
            let path = path.trim();
            if !path.is_empty() && path != "/" && !path.contains('*') {
                if let Some(resolved) = extractor::resolve_url(base_url, path) {
                    urls.push(resolved);
                }
            }
        } else if let Some(sitemap_url) = line.strip_prefix("Sitemap:") {
            let url = sitemap_url.trim();
            if let Some(resolved) = extractor::resolve_url(base_url, url) {
                urls.push(resolved);
            }
        }
    }

    urls
}

/// Extracts base domain from a host (e.g., "sub.example.com" -> "example.com")
fn extract_base_domain(host: &str) -> String {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 2 {
        parts[parts.len() - 2..].join(".")
    } else {
        host.to_string()
    }
}

/// Normalizes URL path to a pattern for smart dedup
/// e.g., /users/123/posts/456 -> /users/:id/posts/:id
fn normalize_path_pattern(url: &str) -> String {
    if let Ok(parsed) = Url::parse(url) {
        let path = parsed.path();
        let id_re = Regex::new(r"/\d+(?:/|$)").expect("valid regex");
        let uuid_re = Regex::new(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:/|$)").expect("valid regex");
        let hash_re = Regex::new(r"/[0-9a-f]{24,}(?:/|$)").expect("valid regex");

        let mut pattern = path.to_string();
        pattern = uuid_re.replace_all(&pattern, "/:uuid/").to_string();
        pattern = hash_re.replace_all(&pattern, "/:hash/").to_string();
        pattern = id_re.replace_all(&pattern, "/:id/").to_string();

        // Include query parameter names (but not values) in pattern
        let mut query_keys: Vec<String> = parsed
            .query_pairs()
            .map(|(k, _)| k.to_string())
            .collect();
        query_keys.sort();

        if query_keys.is_empty() {
            format!("{}://{}{}", parsed.scheme(), parsed.host_str().unwrap_or(""), pattern)
        } else {
            format!(
                "{}://{}{}?{}",
                parsed.scheme(),
                parsed.host_str().unwrap_or(""),
                pattern,
                query_keys.join("&")
            )
        }
    } else {
        url.to_string()
    }
}

async fn fetch_body(client: &HttpClient, url: &str) -> Option<String> {
    match client.get(url).await {
        Ok(response) => {
            let content_type = response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            if content_type.contains("text/")
                || content_type.contains("application/javascript")
                || content_type.contains("application/json")
                || content_type.contains("application/xml")
                || content_type.is_empty()
            {
                response.text().await.ok()
            } else {
                None
            }
        }
        Err(e) => {
            debug!("Crawler failed to fetch {url}: {e}");
            None
        }
    }
}

async fn fetch_body_with_type(client: &HttpClient, url: &str) -> Option<(String, String)> {
    match client.get(url).await {
        Ok(response) => {
            let content_type = response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            if content_type.contains("text/")
                || content_type.contains("application/javascript")
                || content_type.contains("application/json")
                || content_type.contains("application/xml")
                || content_type.is_empty()
            {
                response.text().await.ok().map(|body| (body, content_type))
            } else {
                None
            }
        }
        Err(e) => {
            debug!("Crawler failed to fetch {url}: {e}");
            None
        }
    }
}

/// Normalizes a URL for deduplication (strips trailing slash, fragment)
fn normalize_url(url: &str) -> String {
    if let Ok(mut parsed) = Url::parse(url) {
        parsed.set_fragment(None);
        let mut result = parsed.to_string();
        if result.ends_with('/') && result.len() > 1 {
            result.pop();
        }
        result
    } else {
        url.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_url() {
        assert_eq!(
            normalize_url("https://example.com/path/"),
            "https://example.com/path"
        );
        assert_eq!(
            normalize_url("https://example.com/path#section"),
            "https://example.com/path"
        );
        assert_eq!(
            normalize_url("https://example.com/path?a=1"),
            "https://example.com/path?a=1"
        );
    }

    #[test]
    fn test_normalize_path_pattern() {
        assert_eq!(
            normalize_path_pattern("https://example.com/users/123"),
            "https://example.com/users/:id/"
        );
        assert_eq!(
            normalize_path_pattern("https://example.com/users/456"),
            "https://example.com/users/:id/"
        );
        assert_eq!(
            normalize_path_pattern("https://example.com/users/123/posts/789"),
            "https://example.com/users/:id/posts/:id/"
        );
    }

    #[test]
    fn test_extract_base_domain() {
        assert_eq!(extract_base_domain("sub.example.com"), "example.com");
        assert_eq!(extract_base_domain("example.com"), "example.com");
        assert_eq!(
            extract_base_domain("deep.sub.example.com"),
            "example.com"
        );
    }

    #[test]
    fn test_parse_robots_txt() {
        let base = Url::parse("https://example.com").expect("valid url");
        let robots = "User-agent: *\nDisallow: /admin/\nDisallow: /private/config\nAllow: /public/\nSitemap: https://example.com/sitemap.xml\n";

        let urls = parse_robots_txt(robots, &base, "example.com");
        assert!(urls.contains(&"https://example.com/admin/".to_string()));
        assert!(urls.contains(&"https://example.com/private/config".to_string()));
        assert!(urls.contains(&"https://example.com/public/".to_string()));
        assert!(urls.contains(&"https://example.com/sitemap.xml".to_string()));
    }

    #[test]
    fn test_parse_sitemap() {
        let base = Url::parse("https://example.com").expect("valid url");
        let xml = r#"<?xml version="1.0"?>
            <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                <url><loc>https://example.com/page1</loc></url>
                <url><loc>https://example.com/page2</loc></url>
            </urlset>"#;

        let urls = parse_sitemap(xml, &base);
        assert_eq!(urls.len(), 2);
        assert!(urls.contains(&"https://example.com/page1".to_string()));
        assert!(urls.contains(&"https://example.com/page2".to_string()));
    }
}
