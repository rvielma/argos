//! CVE Template-based scanning
//!
//! Loads YAML templates that define HTTP requests and response matchers
//! for detecting known CVEs and vulnerabilities.
//! Supports template clustering (grouping by path) and parallel execution.

pub mod cluster;
pub mod engine;
pub mod loader;
pub mod matcher;
pub mod nuclei;

use crate::error::Result;
use crate::http::HttpClient;
use crate::models::{Finding, ScanConfig};
use async_trait::async_trait;
use include_dir::{include_dir, Dir};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{info, warn};

use cluster::TemplateCluster;
use loader::CveTemplate;

/// Embedded templates directory (compiled into the binary)
static EMBEDDED_TEMPLATES: Dir = include_dir!("$CARGO_MANIFEST_DIR/templates");

/// Map a subdirectory name to a human-readable category
fn dir_to_category(dir_name: &str) -> &str {
    match dir_name {
        "cves" => "CVE",
        "technologies" => "Technology Detection",
        "misconfigurations" => "Misconfiguration",
        "exposures" => "Exposure",
        "default-logins" => "Default Login",
        "healthcare" => "Healthcare",
        "cloud" => "Cloud Security",
        "graphql" => "GraphQL Security",
        _ => "Template",
    }
}

/// Generate a recommendation based on the template category
fn category_recommendation(category: &str, template_id: &str) -> String {
    match category {
        "CVE" => format!("Investigate {} and apply vendor patches.", template_id),
        "Technology Detection" => "Review detected technology for known vulnerabilities and ensure it is up to date.".to_string(),
        "Misconfiguration" => "Review and fix the misconfiguration to harden the service.".to_string(),
        "Exposure" => "Restrict access to the exposed resource and ensure it is not publicly reachable.".to_string(),
        "Default Login" => "Change default credentials immediately and enforce strong password policies.".to_string(),
        "Healthcare" => "Review healthcare system exposure and restrict access per compliance requirements.".to_string(),
        "Cloud Security" => "Review cloud resource configuration and restrict public access.".to_string(),
        "GraphQL Security" => "Review GraphQL endpoint configuration and disable unnecessary features like introspection.".to_string(),
        _ => format!("Investigate {} and remediate.", template_id),
    }
}

/// Load templates embedded in the binary
fn load_embedded_templates() -> Vec<CveTemplate> {
    let mut templates = Vec::new();
    load_embedded_dir(&EMBEDDED_TEMPLATES, "templates", &mut templates);
    info!("Loaded {} embedded templates", templates.len());
    templates
}

/// Recursively load templates from an embedded directory
fn load_embedded_dir(dir: &Dir, dir_name: &str, templates: &mut Vec<CveTemplate>) {
    let category = dir_to_category(dir_name).to_string();

    for file in dir.files() {
        let path = file.path().display().to_string();
        if path.ends_with(".yaml") || path.ends_with(".yml") {
            let content = match file.contents_utf8() {
                Some(c) => c,
                None => {
                    warn!("Embedded template is not valid UTF-8: {}", path);
                    continue;
                }
            };
            match loader::load_template_from_str(content, &path) {
                Ok(mut tmpl) => {
                    tmpl.category = category.clone();
                    templates.push(tmpl);
                }
                Err(e) => {
                    warn!("Failed to load embedded template {}: {}", path, e);
                }
            }
        }
    }

    for subdir in dir.dirs() {
        let sub_name = subdir
            .path()
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("templates");
        load_embedded_dir(subdir, sub_name, templates);
    }
}

/// Recursively load templates from a directory and all its subdirectories
fn load_templates_recursive(dir: &Path, templates: &mut Vec<CveTemplate>) {
    // Determine category from the directory name
    let dir_name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("templates");
    let category = dir_to_category(dir_name).to_string();

    if let Ok(mut dir_templates) = loader::load_templates(dir) {
        if !dir_templates.is_empty() {
            info!(
                "Loaded {} templates from {}",
                dir_templates.len(),
                dir.display()
            );
            // Assign category to each loaded template
            for tmpl in &mut dir_templates {
                tmpl.category = category.clone();
            }
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
        let mut templates = if let Some(ref dir) = config.templates_dir {
            // Explicit templates dir: load from filesystem
            let base_path = Path::new(dir);
            let mut fs_templates = Vec::new();
            load_templates_recursive(base_path, &mut fs_templates);
            fs_templates
        } else {
            // No explicit dir: try filesystem "templates/" first, fallback to embedded
            let default_path = Path::new("templates");
            if default_path.exists() && default_path.is_dir() {
                let mut fs_templates = Vec::new();
                load_templates_recursive(default_path, &mut fs_templates);
                if fs_templates.is_empty() {
                    info!("Filesystem templates dir empty, using embedded templates");
                    load_embedded_templates()
                } else {
                    fs_templates
                }
            } else {
                info!("No templates directory found, using embedded templates");
                load_embedded_templates()
            }
        };

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

        // Load Nuclei-compatible templates if specified
        if let Some(ref nuclei_dir) = config.nuclei_templates_dir {
            let nuclei_path = Path::new(nuclei_dir);
            let nuclei_templates = nuclei::load_nuclei_templates(nuclei_path);
            if !nuclei_templates.is_empty() {
                info!("Loaded {} Nuclei templates from {}", nuclei_templates.len(), nuclei_dir);
                templates.extend(nuclei_templates);
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
