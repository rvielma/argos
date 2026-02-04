//! Common test utilities

use argos::http::AuthConfig;
use argos::models::ScanConfig;

/// Creates a test ScanConfig pointing to a wiremock server
pub fn test_config(target: &str) -> ScanConfig {
    ScanConfig {
        target: target.to_string(),
        threads: 2,
        timeout_secs: 10,
        user_agent: "Argos-Test/0.1.0".to_string(),
        modules: vec![
            "headers".to_string(),
            "ssl".to_string(),
            "cookies".to_string(),
            "cors".to_string(),
            "info_disclosure".to_string(),
            "discovery".to_string(),
            "injection".to_string(),
            "api".to_string(),
            "templates".to_string(),
        ],
        follow_redirects: true,
        max_depth: 1,
        wordlist_path: None,
        proxy: None,
        headers: std::collections::HashMap::new(),
        rate_limit: None,
        auth: AuthConfig::None,
        templates_dir: None,
        concurrent: false,
        extra_template_dirs: Vec::new(),
    }
}
