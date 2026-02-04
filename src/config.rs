//! Configuration management for Argos scanner

use crate::error::{ArgosError, Result};
use crate::models::ScanConfig;
use serde::Deserialize;
use std::path::Path;

/// File-based configuration structure matching default.toml
#[derive(Debug, Deserialize)]
struct FileConfig {
    scan: Option<ScanSection>,
    modules: Option<ModulesSection>,
    #[allow(dead_code)]
    output: Option<OutputSection>,
    proxy: Option<ProxySection>,
    #[allow(dead_code)]
    ai: Option<AiSection>,
}

#[derive(Debug, Deserialize)]
struct ScanSection {
    threads: Option<usize>,
    timeout_secs: Option<u64>,
    user_agent: Option<String>,
    follow_redirects: Option<bool>,
    max_depth: Option<u32>,
    rate_limit: Option<u32>,
    concurrent: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ModulesSection {
    enabled: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct OutputSection {
    pub format: Option<String>,
    pub report_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProxySection {
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AiSection {
    pub enabled: Option<bool>,
    pub ollama_endpoint: Option<String>,
    pub model: Option<String>,
}

/// Loads configuration from a TOML file and merges with defaults
pub fn load_config(path: &Path) -> Result<ScanConfig> {
    let content = std::fs::read_to_string(path).map_err(ArgosError::IoError)?;
    let file_config: FileConfig = toml::from_str(&content)?;

    let mut config = ScanConfig::default();

    if let Some(scan) = file_config.scan {
        if let Some(threads) = scan.threads {
            config.threads = threads;
        }
        if let Some(timeout) = scan.timeout_secs {
            config.timeout_secs = timeout;
        }
        if let Some(ua) = scan.user_agent {
            config.user_agent = ua;
        }
        if let Some(follow) = scan.follow_redirects {
            config.follow_redirects = follow;
        }
        if let Some(depth) = scan.max_depth {
            config.max_depth = depth;
        }
        if let Some(rate) = scan.rate_limit {
            config.rate_limit = Some(rate);
        }
        if let Some(concurrent) = scan.concurrent {
            config.concurrent = concurrent;
        }
    }

    if let Some(modules) = file_config.modules {
        if let Some(enabled) = modules.enabled {
            config.modules = enabled;
        }
    }

    if let Some(proxy) = file_config.proxy {
        config.proxy = proxy.url;
    }

    Ok(config)
}

/// Merges CLI arguments into an existing ScanConfig
#[allow(clippy::too_many_arguments)]
pub fn merge_cli_args(
    config: &mut ScanConfig,
    target: String,
    threads: Option<usize>,
    timeout: Option<u64>,
    modules: Option<Vec<String>>,
    proxy: Option<String>,
    rate_limit: Option<u32>,
    wordlist: Option<String>,
    headers: Option<Vec<String>>,
) {
    config.target = target;

    if let Some(t) = threads {
        config.threads = t;
    }
    if let Some(t) = timeout {
        config.timeout_secs = t;
    }
    if let Some(m) = modules {
        config.modules = m;
    }
    if let Some(p) = proxy {
        config.proxy = Some(p);
    }
    if let Some(r) = rate_limit {
        config.rate_limit = Some(r);
    }
    if let Some(w) = wordlist {
        config.wordlist_path = Some(w);
    }
    if let Some(h) = headers {
        for header in h {
            if let Some((key, value)) = header.split_once(':') {
                config
                    .headers
                    .insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }
}
