//! Scanner engine and trait definitions

pub mod api;
pub mod cookies;
pub mod cors;
pub mod dast;
pub mod discovery;
pub mod graphql;
pub mod headers;
pub mod info_disclosure;
pub mod injection;
pub mod oob_scanner;
pub mod secrets;
pub mod ssl;
pub mod templates;
pub mod waf;
pub mod websocket;

use crate::crawler::Crawler;
use crate::error::Result;
use crate::http::HttpClient;
use crate::models::{Finding, ScanConfig, ScanResult};
use async_trait::async_trait;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::Arc;
use tokio::task::JoinSet;
use tracing::{error, info};

/// Trait that all scanner modules must implement
#[async_trait]
pub trait Scanner: Send + Sync {
    /// Returns the module name
    fn name(&self) -> &str;

    /// Returns a description of what this module checks
    fn description(&self) -> &str;

    /// Executes the scan and returns findings
    async fn scan(
        &self,
        client: &HttpClient,
        config: &ScanConfig,
        crawled_urls: &[String],
    ) -> Result<Vec<Finding>>;
}

/// Orchestrates the execution of all registered scanner modules
pub struct ScanEngine {
    scanners: Vec<Arc<dyn Scanner>>,
}

impl ScanEngine {
    /// Creates a new ScanEngine with no registered scanners
    pub fn new() -> Self {
        Self {
            scanners: Vec::new(),
        }
    }

    /// Creates a ScanEngine with all default scanners registered
    pub fn with_defaults() -> Self {
        let mut engine = Self::new();
        engine.register(Arc::new(headers::HeadersScanner));
        engine.register(Arc::new(ssl::SslScanner));
        engine.register(Arc::new(cookies::CookiesScanner));
        engine.register(Arc::new(cors::CorsScanner));
        engine.register(Arc::new(info_disclosure::InfoDisclosureScanner));
        engine.register(Arc::new(discovery::DiscoveryScanner));
        engine.register(Arc::new(injection::InjectionScanner));
        engine.register(Arc::new(api::ApiScanner));
        engine.register(Arc::new(templates::TemplateScanner));
        engine.register(Arc::new(waf::WafScanner));
        engine.register(Arc::new(websocket::WebSocketScanner));
        engine.register(Arc::new(dast::DastScanner));
        engine.register(Arc::new(oob_scanner::OobScanner));
        engine.register(Arc::new(graphql::GraphQLScanner));
        engine.register(Arc::new(secrets::SecretsScanner));
        engine
    }

    /// Registers a new scanner module
    pub fn register(&mut self, scanner: Arc<dyn Scanner>) {
        self.scanners.push(scanner);
    }

    /// Returns information about all registered modules
    pub fn list_modules(&self) -> Vec<(&str, &str)> {
        self.scanners
            .iter()
            .map(|s| (s.name(), s.description()))
            .collect()
    }

    /// Runs all enabled scanner modules and collects results
    pub async fn run(&self, config: &ScanConfig) -> Result<ScanResult> {
        let mut result = ScanResult::new(&config.target);
        let client = HttpClient::from_config(config).await?;

        // Run crawler first to discover URLs
        info!("Starting crawler on {}", config.target);
        let mut crawler = Crawler::new(&client, config);
        let crawled_urls = crawler.crawl(&config.target).await;
        info!("Crawler discovered {} URLs", crawled_urls.len());

        let enabled_scanners: Vec<Arc<dyn Scanner>> = self
            .scanners
            .iter()
            .filter(|s| config.modules.contains(&s.name().to_string()))
            .cloned()
            .collect();

        if config.concurrent {
            self.run_concurrent(
                &enabled_scanners,
                &client,
                config,
                &crawled_urls,
                &mut result,
            )
            .await;
        } else {
            self.run_sequential(
                &enabled_scanners,
                &client,
                config,
                &crawled_urls,
                &mut result,
            )
            .await;
        }

        result.total_requests = client.request_count();
        result.finish();

        // Deduplicate findings by (title, url) - keep first occurrence (higher priority module)
        let mut seen = std::collections::HashSet::new();
        result.findings.retain(|f| {
            let key = format!("{}|{}", f.title.to_lowercase(), f.url.to_lowercase());
            seen.insert(key)
        });

        // Sort findings by severity
        result.findings.sort_by(|a, b| a.severity.cmp(&b.severity));

        Ok(result)
    }

    /// Sequential execution (original behavior)
    async fn run_sequential(
        &self,
        scanners: &[Arc<dyn Scanner>],
        client: &HttpClient,
        config: &ScanConfig,
        crawled_urls: &[String],
        result: &mut ScanResult,
    ) {
        let pb = ProgressBar::new(scanners.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("  {spinner:.cyan} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("=>-"),
        );

        for scanner in scanners {
            pb.set_message(format!("Running {}...", scanner.name()));
            info!("Executing module: {}", scanner.name());

            match scanner.scan(client, config, crawled_urls).await {
                Ok(findings) => {
                    info!(
                        "Module '{}' completed: {} findings",
                        scanner.name(),
                        findings.len()
                    );
                    result.findings.extend(findings);
                    result.modules_executed.push(scanner.name().to_string());
                }
                Err(e) => {
                    error!("Module '{}' failed: {}", scanner.name(), e);
                }
            }

            pb.inc(1);
        }

        pb.finish_with_message("Scan complete");
    }

    /// Concurrent execution using JoinSet
    async fn run_concurrent(
        &self,
        scanners: &[Arc<dyn Scanner>],
        client: &HttpClient,
        config: &ScanConfig,
        crawled_urls: &[String],
        result: &mut ScanResult,
    ) {
        let pb = ProgressBar::new(scanners.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("  {spinner:.cyan} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("=>-"),
        );
        pb.set_message("Running modules concurrently...");

        let mut set = JoinSet::new();

        for scanner in scanners {
            let scanner = Arc::clone(scanner);
            let client = client.clone();
            let config = config.clone();
            let urls: Vec<String> = crawled_urls.to_vec();
            let name = scanner.name().to_string();

            set.spawn(async move {
                info!("Executing module: {}", name);
                let scan_result = scanner.scan(&client, &config, &urls).await;
                (name, scan_result)
            });
        }

        while let Some(join_result) = set.join_next().await {
            match join_result {
                Ok((name, scan_result)) => match scan_result {
                    Ok(findings) => {
                        info!("Module '{}' completed: {} findings", name, findings.len());
                        result.findings.extend(findings);
                        result.modules_executed.push(name);
                    }
                    Err(e) => {
                        error!("Module '{}' failed: {}", name, e);
                    }
                },
                Err(e) => {
                    error!("Scanner task panicked: {}", e);
                }
            }
            pb.inc(1);
        }

        pb.finish_with_message("Scan complete");
    }
}

impl Default for ScanEngine {
    fn default() -> Self {
        Self::with_defaults()
    }
}
