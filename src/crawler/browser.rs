//! Browser-based rendering for SPA crawling
//!
//! Uses headless Chromium to render JavaScript-heavy pages and extract
//! the final DOM content. Only available with the `browser` feature.

#[cfg(feature = "browser")]
use chromiumoxide::{Browser, BrowserConfig, Page};
#[cfg(feature = "browser")]
use std::sync::Arc;
#[cfg(feature = "browser")]
use tracing::{debug, info, warn};

/// Rendered page content
#[derive(Debug, Clone)]
pub struct RenderedPage {
    /// Final HTML after JavaScript execution
    pub html: String,
    /// URLs extracted from the rendered DOM
    pub urls: Vec<String>,
    /// Evidence of DOM-based XSS sinks found
    pub dom_xss_evidence: Vec<String>,
}

/// Browser-based renderer for JavaScript-heavy pages
#[cfg(feature = "browser")]
pub struct BrowserRenderer {
    browser: Arc<Browser>,
}

#[cfg(feature = "browser")]
impl BrowserRenderer {
    /// Creates a new browser renderer with headless Chromium
    pub async fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (browser, mut handler) = Browser::launch(
            BrowserConfig::builder()
                .no_sandbox()
                .window_size(1920, 1080)
                .arg("--disable-gpu")
                .arg("--disable-dev-shm-usage")
                .build()
                .map_err(|e| format!("Browser config error: {}", e))?,
        )
        .await?;

        // Spawn handler as background task
        tokio::spawn(async move {
            while let Some(event) = handler.next().await {
                // Process browser events
            }
        });

        info!("Browser renderer initialized");
        Ok(Self {
            browser: Arc::new(browser),
        })
    }

    /// Renders a URL and returns the final DOM content
    pub async fn render(
        &self,
        url: &str,
        wait_ms: u64,
    ) -> Result<RenderedPage, Box<dyn std::error::Error + Send + Sync>> {
        let page = self.browser.new_page(url).await?;

        // Wait for the page to load
        tokio::time::sleep(std::time::Duration::from_millis(wait_ms)).await;

        // Get the rendered HTML
        let html = page
            .evaluate("document.documentElement.outerHTML")
            .await?
            .into_value::<String>()
            .unwrap_or_default();

        // Extract URLs from rendered DOM
        let urls_js = r#"
            Array.from(document.querySelectorAll('a[href], form[action], script[src], link[href]'))
                .map(el => el.href || el.action || el.src)
                .filter(url => url && url.startsWith('http'))
        "#;
        let urls = page
            .evaluate(urls_js)
            .await?
            .into_value::<Vec<String>>()
            .unwrap_or_default();

        // Check for DOM XSS sinks
        let xss_check_js = r#"
            (() => {
                const sinks = [];
                // Check for dangerous DOM assignments
                const scripts = document.querySelectorAll('script');
                scripts.forEach(s => {
                    const text = s.textContent || '';
                    if (text.includes('innerHTML') || text.includes('outerHTML')) {
                        sinks.push('innerHTML/outerHTML usage in script');
                    }
                    if (text.includes('document.write')) {
                        sinks.push('document.write usage');
                    }
                    if (text.includes('eval(')) {
                        sinks.push('eval() usage');
                    }
                    if (text.includes('location.hash') || text.includes('location.search')) {
                        if (text.includes('innerHTML') || text.includes('document.write') || text.includes('eval')) {
                            sinks.push('URL input flows to dangerous sink');
                        }
                    }
                });
                return sinks;
            })()
        "#;
        let dom_xss_evidence = page
            .evaluate(xss_check_js)
            .await?
            .into_value::<Vec<String>>()
            .unwrap_or_default();

        debug!(
            "Rendered {}: {} bytes HTML, {} URLs, {} XSS sinks",
            url,
            html.len(),
            urls.len(),
            dom_xss_evidence.len()
        );

        Ok(RenderedPage {
            html,
            urls,
            dom_xss_evidence,
        })
    }
}

/// Stub implementation when browser feature is not enabled
#[cfg(not(feature = "browser"))]
pub struct BrowserRenderer;

#[cfg(not(feature = "browser"))]
impl BrowserRenderer {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Err("Browser rendering requires the 'browser' feature flag. \
             Compile with: cargo build --features browser"
            .into())
    }
}
