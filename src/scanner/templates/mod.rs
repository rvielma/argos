//! CVE Template-based scanning
//!
//! Loads YAML templates that define HTTP requests and response matchers
//! for detecting known CVEs and vulnerabilities.
//! Supports template clustering (grouping by path) and parallel execution.

pub mod cluster;
pub mod engine;
pub mod loader;
pub mod matcher;

use crate::error::Result;
use crate::http::HttpClient;
use crate::models::{Finding, ScanConfig};
use async_trait::async_trait;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::info;

use cluster::TemplateCluster;
use loader::CveTemplate;

/// Recursively load templates from a directory and all its subdirectories
fn load_templates_recursive(dir: &Path, templates: &mut Vec<CveTemplate>) {
    if let Ok(dir_templates) = loader::load_templates(dir) {
        if !dir_templates.is_empty() {
            info!(
                "Loaded {} templates from {}",
                dir_templates.len(),
                dir.display()
            );
            templates.extend(dir_templates);
        }
    }

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                load_templates_recursive(&path, templates);
            }
        }
    }
}

/// Scanner that loads and executes CVE detection templates
pub struct TemplateScanner;

#[async_trait]
impl super::Scanner for TemplateScanner {
    fn name(&self) -> &str {
        "templates"
    }

    fn description(&self) -> &str {
        "Scans for known CVEs using YAML-based detection templates"
    }

    async fn scan(
        &self,
        client: &HttpClient,
        config: &ScanConfig,
        _crawled_urls: &[String],
    ) -> Result<Vec<Finding>> {
        let templates_dir = config.templates_dir.as_deref().unwrap_or("templates");

        let base_path = Path::new(templates_dir);
        let mut templates = Vec::new();

        load_templates_recursive(base_path, &mut templates);

        for extra_dir in &config.extra_template_dirs {
            let extra_path = Path::new(extra_dir);
            match loader::load_templates(extra_path) {
                Ok(extra_templates) => {
                    info!(
                        "Loaded {} templates from {}",
                        extra_templates.len(),
                        extra_dir
                    );
                    templates.extend(extra_templates);
                }
                Err(e) => {
                    info!("Failed to load templates from {}: {}", extra_dir, e);
                }
            }
        }

        if templates.is_empty() {
            info!("No CVE templates found");
            return Ok(Vec::new());
        }

        info!(
            "Executing {} CVE templates against {}",
            templates.len(),
            config.target
        );

        let mut findings = Vec::new();

        if config.template_clustering {
            let cluster = TemplateCluster::from_templates(templates);

            // Execute clustered templates: one request per path, evaluate all templates
            for (key, cluster_templates) in &cluster.clusters {
                let path = key.strip_prefix("GET:").unwrap_or(key);
                let url = format!(
                    "{}/{}",
                    config.target.trim_end_matches('/'),
                    path.trim_start_matches('/')
                );

                match client.get(&url).await {
                    Ok(response) => {
                        let status_code = response.status().as_u16();
                        let resp_headers: Vec<(String, String)> = response
                            .headers()
                            .iter()
                            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                            .collect();
                        let body = response.text().await.unwrap_or_default();

                        for tmpl in cluster_templates {
                            let f = engine::evaluate_template_against_response(
                                tmpl,
                                status_code,
                                &resp_headers,
                                &body,
                                &url,
                            );
                            findings.extend(f);
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Cluster request to {} failed: {}", url, e);
                    }
                }
            }

            // Execute unclustered templates in parallel
            findings.extend(
                execute_templates_parallel(
                    client,
                    &config.target,
                    &cluster.unclustered,
                    config.threads,
                )
                .await,
            );
        } else {
            // No clustering: run all templates in parallel
            findings.extend(
                execute_templates_parallel(client, &config.target, &templates, config.threads)
                    .await,
            );
        }

        Ok(findings)
    }
}

/// Execute templates concurrently with a semaphore-based concurrency limit
async fn execute_templates_parallel(
    client: &HttpClient,
    target: &str,
    templates: &[CveTemplate],
    max_concurrent: usize,
) -> Vec<Finding> {
    let semaphore = Arc::new(Semaphore::new(max_concurrent.max(1)));
    let mut set = JoinSet::new();

    for template in templates {
        let sem = Arc::clone(&semaphore);
        let client = client.clone();
        let target = target.to_string();
        let template = template.clone();

        set.spawn(async move {
            let _permit = sem.acquire().await;
            engine::execute_template(&client, &target, &template).await
        });
    }

    let mut findings = Vec::new();
    while let Some(result) = set.join_next().await {
        if let Ok(f) = result {
            findings.extend(f);
        }
    }

    findings
}
