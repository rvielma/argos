//! Web crawler/spider for URL discovery
//!
//! Concurrent BFS crawler with deduplication, depth limiting, and rate limiting.
//! Discovers URLs by parsing HTML and JavaScript content.

pub mod browser;
pub mod extractor;
pub mod spa_detector;

use crate::http::HttpClient;
use crate::models::ScanConfig;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, info, warn};
use url::Url;

/// Concurrent BFS web crawler that discovers URLs within a target site
pub struct Crawler<'a> {
    client: &'a HttpClient,
    max_depth: u32,
    max_urls: usize,
    concurrency: usize,
}

impl<'a> Crawler<'a> {
    pub fn new(client: &'a HttpClient, config: &ScanConfig) -> Self {
        Self {
            client,
            max_depth: config.max_depth,
            max_urls: 500,
            concurrency: config.threads.max(1),
        }
    }

    /// Crawls the target URL concurrently and returns all discovered URLs
    pub async fn crawl(&mut self, start_url: &str) -> Vec<String> {
        let base_url = match Url::parse(start_url) {
            Ok(u) => u,
            Err(e) => {
                warn!("Invalid start URL for crawler: {e}");
                return vec![start_url.to_string()];
            }
        };

        let visited = Arc::new(Mutex::new(HashSet::new()));
        let discovered = Arc::new(Mutex::new(Vec::new()));

        {
            let mut v = visited.lock().await;
            v.insert(normalize_url(start_url));
            let mut d = discovered.lock().await;
            d.push(start_url.to_string());
        }

        // Process depth by depth (BFS layers)
        let mut current_layer = vec![start_url.to_string()];

        for depth in 0..self.max_depth {
            if current_layer.is_empty() {
                break;
            }

            let discovered_count = discovered.lock().await.len();
            if discovered_count >= self.max_urls {
                break;
            }

            let semaphore = Arc::new(Semaphore::new(self.concurrency));
            let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<String>>(current_layer.len() + 1);

            let mut handles = Vec::new();

            for url in current_layer.drain(..) {
                let sem = Arc::clone(&semaphore);
                let client = self.client.clone();
                let base_host = base_url.host_str().unwrap_or("").to_string();
                let tx = tx.clone();

                let handle = tokio::spawn(async move {
                    let _permit = match sem.acquire().await {
                        Ok(p) => p,
                        Err(_) => return,
                    };

                    let body = match fetch_body(&client, &url).await {
                        Some(b) => b,
                        None => return,
                    };

                    let page_url = match Url::parse(&url) {
                        Ok(u) => u,
                        Err(_) => return,
                    };

                    let mut new_urls = extractor::extract_from_html(&page_url, &body);
                    new_urls.extend(extractor::extract_from_js(&page_url, &body));

                    // Filter to same-host
                    new_urls.retain(|u| {
                        if let Ok(parsed) = Url::parse(u) {
                            parsed.host_str() == Some(&base_host)
                        } else {
                            false
                        }
                    });

                    let _ = tx.send(new_urls).await;
                });

                handles.push(handle);
            }

            drop(tx);

            // Collect results from all concurrent fetches
            let mut next_layer = Vec::new();
            let mut limit_reached = false;
            while let Some(urls) = rx.recv().await {
                let mut v = visited.lock().await;
                let mut d = discovered.lock().await;

                for url in urls {
                    if d.len() >= self.max_urls {
                        limit_reached = true;
                        break;
                    }
                    let normalized = normalize_url(&url);
                    if !v.contains(&normalized) {
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

        let result = discovered.lock().await.clone();
        info!("Crawler finished: {} URLs discovered", result.len());
        result
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

            if content_type.contains("text/html")
                || content_type.contains("application/javascript")
                || content_type.contains("text/javascript")
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
}
