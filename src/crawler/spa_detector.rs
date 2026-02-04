//! SPA (Single Page Application) detection
//!
//! Detects React, Angular, Vue, Next.js and other SPA frameworks
//! from HTML content without requiring a browser.

use regex::Regex;

/// Result of SPA detection analysis
#[derive(Debug, Clone)]
pub struct SpaDetection {
    /// Whether the page appears to be a SPA
    pub is_spa: bool,
    /// Detected frameworks
    pub frameworks: Vec<String>,
    /// Whether JavaScript rendering would yield more content
    pub needs_rendering: bool,
}

/// Analyzes HTML content to detect if it's a Single Page Application
pub fn detect_spa(html: &str) -> SpaDetection {
    let mut frameworks = Vec::new();
    let lower = html.to_lowercase();

    // React indicators
    if lower.contains("__next") || lower.contains("_next/static") || lower.contains("__next_data__") {
        frameworks.push("Next.js".to_string());
    } else if lower.contains("data-reactroot")
        || lower.contains("data-reactid")
        || lower.contains("react-root")
        || lower.contains("\"react\"")
        || lower.contains("react-dom")
    {
        frameworks.push("React".to_string());
    }

    // Angular indicators
    if lower.contains("ng-app") || lower.contains("ng-version") || lower.contains("ng-controller") {
        frameworks.push("Angular".to_string());
    }

    // Vue.js indicators
    if lower.contains("data-v-")
        || lower.contains("v-app")
        || lower.contains("__vue__")
        || lower.contains("vue-router")
    {
        frameworks.push("Vue.js".to_string());
    }

    // Nuxt.js indicators
    if lower.contains("__nuxt") || lower.contains("_nuxt/") {
        frameworks.push("Nuxt.js".to_string());
    }

    // Svelte indicators
    if lower.contains("svelte") && (lower.contains("__svelte") || lower.contains("svelte-")) {
        frameworks.push("Svelte".to_string());
    }

    // Generic SPA indicators
    let has_app_root = lower.contains("id=\"app\"")
        || lower.contains("id=\"root\"")
        || lower.contains("id=\"__app\"");

    let is_spa = !frameworks.is_empty() || has_app_root;

    // If HTML body is very small but has SPA indicators, rendering would help
    let body_size = extract_body_size(html);
    let needs_rendering = is_spa && body_size < 5000;

    SpaDetection {
        is_spa,
        frameworks,
        needs_rendering,
    }
}

/// Extracts approximate body content size (between <body> tags)
fn extract_body_size(html: &str) -> usize {
    if let Ok(re) = Regex::new(r"(?is)<body[^>]*>(.*?)</body>") {
        if let Some(cap) = re.captures(html) {
            if let Some(body) = cap.get(1) {
                return body.as_str().trim().len();
            }
        }
    }
    html.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_react() {
        let html = r#"<html><head></head><body><div id="root" data-reactroot></div><script src="/static/js/main.js"></script></body></html>"#;
        let result = detect_spa(html);
        assert!(result.is_spa);
        assert!(result.frameworks.contains(&"React".to_string()));
    }

    #[test]
    fn test_detect_nextjs() {
        let html = r#"<html><head></head><body><div id="__next"></div><script src="/_next/static/chunks/main.js"></script></body></html>"#;
        let result = detect_spa(html);
        assert!(result.is_spa);
        assert!(result.frameworks.contains(&"Next.js".to_string()));
    }

    #[test]
    fn test_detect_non_spa() {
        let html = r#"<html><head><title>Hello</title></head><body><h1>Welcome</h1><p>This is a normal page with lots of content...</p></body></html>"#;
        let result = detect_spa(html);
        assert!(!result.is_spa);
        assert!(result.frameworks.is_empty());
    }
}
