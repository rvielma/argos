//! URL extraction from HTML and JavaScript content

use regex::Regex;
use scraper::{Html, Selector};
use url::Url;

/// Extracts URLs from HTML content (a[href], form[action], script[src], link[href])
pub fn extract_from_html(base_url: &Url, html: &str) -> Vec<String> {
    let document = Html::parse_document(html);
    let mut urls = Vec::new();

    let selectors = [
        ("a[href]", "href"),
        ("form[action]", "action"),
        ("script[src]", "src"),
        ("link[href]", "href"),
        ("img[src]", "src"),
        ("iframe[src]", "src"),
    ];

    for (sel_str, attr) in &selectors {
        if let Ok(selector) = Selector::parse(sel_str) {
            for element in document.select(&selector) {
                if let Some(value) = element.value().attr(attr) {
                    if let Some(resolved) = resolve_url(base_url, value) {
                        urls.push(resolved);
                    }
                }
            }
        }
    }

    urls
}

/// Extracts URLs from JavaScript content using regex patterns
pub fn extract_from_js(base_url: &Url, js_content: &str) -> Vec<String> {
    let mut urls = Vec::new();

    let patterns = [
        r#"["'](/[a-zA-Z0-9_\-/.?&=]+)["']"#,
        r#"(?:fetch|axios\.get|axios\.post|\.ajax)\s*\(\s*["']([^"']+)["']"#,
        r#"(?:href|src|action|url)\s*[=:]\s*["']([^"']+)["']"#,
        r#"window\.location\s*(?:\.\w+)?\s*=\s*["']([^"']+)["']"#,
        // React/Vue/Angular router patterns
        r#"path\s*:\s*["'](/[^"']+)["']"#,
        // Dynamic imports
        r#"import\s*\(\s*["']([^"']+)["']\s*\)"#,
        // Webpack chunk loading
        r#"__webpack_require__\s*\.e\s*\(\s*["']([^"']+)["']"#,
        // API endpoint patterns
        r#"(?:api|endpoint|baseUrl|API_URL)\s*[=:+]\s*["']([^"']+)["']"#,
    ];

    for pattern in &patterns {
        if let Ok(re) = Regex::new(pattern) {
            for cap in re.captures_iter(js_content) {
                if let Some(m) = cap.get(1) {
                    let path = m.as_str();
                    if should_include_path(path) {
                        if let Some(resolved) = resolve_url(base_url, path) {
                            urls.push(resolved);
                        }
                    }
                }
            }
        }
    }

    urls
}

/// Resolves a potentially relative URL against a base URL
fn resolve_url(base_url: &Url, raw: &str) -> Option<String> {
    let trimmed = raw.trim();

    if trimmed.is_empty()
        || trimmed.starts_with('#')
        || trimmed.starts_with("mailto:")
        || trimmed.starts_with("tel:")
        || trimmed.starts_with("javascript:")
        || trimmed.starts_with("data:")
    {
        return None;
    }

    let resolved = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        Url::parse(trimmed).ok()?
    } else {
        base_url.join(trimmed).ok()?
    };

    // Only keep URLs on the same host
    if resolved.host_str() != base_url.host_str() {
        return None;
    }

    // Strip fragment
    let mut clean = resolved;
    clean.set_fragment(None);

    Some(clean.to_string())
}

/// Filters out paths that are unlikely to be useful endpoints
fn should_include_path(path: &str) -> bool {
    let skip_extensions = [
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp3",
        ".mp4", ".avi", ".mov", ".pdf", ".zip", ".tar", ".gz",
    ];

    let lower = path.to_lowercase();
    !skip_extensions.iter().any(|ext| lower.ends_with(ext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_from_html() {
        let base = Url::parse("https://example.com").expect("valid url");
        let html = r##"
            <html>
            <body>
                <a href="/about">About</a>
                <a href="https://example.com/contact">Contact</a>
                <a href="https://external.com/page">External</a>
                <form action="/search"><input name="q"/></form>
                <script src="/js/app.js"></script>
                <a href="javascript:void(0)">Skip</a>
                <a href="#">Skip</a>
            </body>
            </html>
        "##;

        let urls = extract_from_html(&base, html);
        assert!(urls.contains(&"https://example.com/about".to_string()));
        assert!(urls.contains(&"https://example.com/contact".to_string()));
        assert!(urls.contains(&"https://example.com/search".to_string()));
        assert!(urls.contains(&"https://example.com/js/app.js".to_string()));
        // External URLs should be excluded
        assert!(!urls.iter().any(|u| u.contains("external.com")));
    }

    #[test]
    fn test_extract_from_js() {
        let base = Url::parse("https://example.com").expect("valid url");
        let js = r#"
            fetch("/api/users");
            const url = "/admin/dashboard";
            axios.get("/api/v2/data");
        "#;

        let urls = extract_from_js(&base, js);
        assert!(urls.contains(&"https://example.com/api/users".to_string()));
        assert!(urls.contains(&"https://example.com/admin/dashboard".to_string()));
        assert!(urls.contains(&"https://example.com/api/v2/data".to_string()));
    }

    #[test]
    fn test_skip_static_assets() {
        assert!(!should_include_path("/images/logo.png"));
        assert!(!should_include_path("/fonts/roboto.woff2"));
        assert!(should_include_path("/api/users"));
        assert!(should_include_path("/admin"));
    }
}
