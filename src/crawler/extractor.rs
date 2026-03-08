//! URL extraction from HTML and JavaScript content

use regex::Regex;
use scraper::{Html, Selector};
use url::Url;

/// Collected form information for injection scanning
#[derive(Debug, Clone)]
pub struct FormInfo {
    /// Form action URL
    pub action: String,
    /// HTTP method (GET/POST)
    pub method: String,
    /// Input fields: (name, type, value)
    pub inputs: Vec<(String, String, Option<String>)>,
}

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

/// Extracts URLs from HTML comments (<!-- -->)
pub fn extract_from_comments(base_url: &Url, html: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let comment_re = Regex::new(r"<!--([\s\S]*?)-->").expect("valid regex");
    let url_re = Regex::new(r#"(?:https?://[^\s"'<>]+|/[a-zA-Z0-9_\-/.?&=]+)"#).expect("valid regex");

    for cap in comment_re.captures_iter(html) {
        if let Some(content) = cap.get(1) {
            for url_match in url_re.find_iter(content.as_str()) {
                let path = url_match.as_str().trim();
                if should_include_path(path) {
                    if let Some(resolved) = resolve_url(base_url, path) {
                        urls.push(resolved);
                    }
                }
            }
        }
    }

    urls
}

/// Extracts script src URLs for fetching JS content separately
pub fn extract_script_srcs(base_url: &Url, html: &str) -> Vec<String> {
    let document = Html::parse_document(html);
    let mut urls = Vec::new();

    if let Ok(selector) = Selector::parse("script[src]") {
        for element in document.select(&selector) {
            if let Some(src) = element.value().attr("src") {
                if let Some(resolved) = resolve_url(base_url, src) {
                    urls.push(resolved);
                }
            }
        }
    }

    urls
}

/// Extracts form information (action, method, inputs) for injection scanning
pub fn extract_forms(base_url: &Url, html: &str) -> Vec<FormInfo> {
    let document = Html::parse_document(html);
    let mut forms = Vec::new();

    let form_selector = match Selector::parse("form") {
        Ok(s) => s,
        Err(_) => return forms,
    };
    let input_selector = Selector::parse("input").unwrap_or_else(|_| form_selector.clone());
    let select_selector = Selector::parse("select").unwrap_or_else(|_| form_selector.clone());
    let textarea_selector = Selector::parse("textarea").unwrap_or_else(|_| form_selector.clone());

    for form_el in document.select(&form_selector) {
        let action_raw = form_el.value().attr("action").unwrap_or("");
        let action = resolve_url(base_url, action_raw)
            .unwrap_or_else(|| base_url.to_string());
        let method = form_el
            .value()
            .attr("method")
            .unwrap_or("GET")
            .to_uppercase();

        let mut inputs = Vec::new();

        for input in form_el.select(&input_selector) {
            let name = input.value().attr("name").unwrap_or("").to_string();
            if name.is_empty() {
                continue;
            }
            let input_type = input.value().attr("type").unwrap_or("text").to_string();
            let value = input.value().attr("value").map(|v| v.to_string());
            inputs.push((name, input_type, value));
        }

        for select in form_el.select(&select_selector) {
            let name = select.value().attr("name").unwrap_or("").to_string();
            if !name.is_empty() {
                inputs.push((name, "select".to_string(), None));
            }
        }

        for textarea in form_el.select(&textarea_selector) {
            let name = textarea.value().attr("name").unwrap_or("").to_string();
            if !name.is_empty() {
                inputs.push((name, "textarea".to_string(), None));
            }
        }

        forms.push(FormInfo {
            action,
            method,
            inputs,
        });
    }

    forms
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

/// Extracts URLs from JSON responses (API endpoint discovery)
pub fn extract_from_json(base_url: &Url, json_text: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let url_re = Regex::new(r#""((?:https?://[^"]+|/[a-zA-Z0-9_\-/.?&=]+))""#).expect("valid regex");

    for cap in url_re.captures_iter(json_text) {
        if let Some(m) = cap.get(1) {
            let path = m.as_str();
            if should_include_path(path) {
                if let Some(resolved) = resolve_url(base_url, path) {
                    urls.push(resolved);
                }
            }
        }
    }

    urls
}

/// Resolves a potentially relative URL against a base URL
pub fn resolve_url(base_url: &Url, raw: &str) -> Option<String> {
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

    // Strip fragment
    let mut clean = resolved;
    clean.set_fragment(None);

    Some(clean.to_string())
}

/// Filters out paths that are unlikely to be useful endpoints
fn should_include_path(path: &str) -> bool {
    let skip_extensions = [
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp3",
        ".mp4", ".avi", ".mov", ".pdf", ".zip", ".tar", ".gz", ".css", ".map",
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
        // External URLs are now included at extraction level (host filtering happens in crawler)
        assert!(urls.iter().any(|u| u.contains("external.com")));
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
    fn test_extract_from_comments() {
        let base = Url::parse("https://example.com").expect("valid url");
        let html = r#"
            <html>
            <!-- TODO: implement /api/v2/internal -->
            <!-- Old endpoint: /admin/legacy/config -->
            <body>hello</body>
            </html>
        "#;

        let urls = extract_from_comments(&base, html);
        assert!(urls.contains(&"https://example.com/api/v2/internal".to_string()));
        assert!(urls.contains(&"https://example.com/admin/legacy/config".to_string()));
    }

    #[test]
    fn test_extract_forms() {
        let base = Url::parse("https://example.com").expect("valid url");
        let html = r#"
            <html><body>
            <form action="/login" method="POST">
                <input name="username" type="text"/>
                <input name="password" type="password"/>
                <select name="role"><option value="user">User</option></select>
                <textarea name="notes"></textarea>
                <input type="submit" value="Login"/>
            </form>
            </body></html>
        "#;

        let forms = extract_forms(&base, html);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].action, "https://example.com/login");
        assert_eq!(forms[0].method, "POST");
        assert_eq!(forms[0].inputs.len(), 4); // username, password, role, notes (submit excluded by name)
    }

    #[test]
    fn test_extract_from_json() {
        let base = Url::parse("https://example.com").expect("valid url");
        let json = r#"{"links": ["/api/v1/users", "/api/v1/products"], "next": "https://example.com/api/v1/users?page=2"}"#;

        let urls = extract_from_json(&base, json);
        assert!(urls.contains(&"https://example.com/api/v1/users".to_string()));
        assert!(urls.contains(&"https://example.com/api/v1/products".to_string()));
        assert!(urls.contains(&"https://example.com/api/v1/users?page=2".to_string()));
    }

    #[test]
    fn test_skip_static_assets() {
        assert!(!should_include_path("/images/logo.png"));
        assert!(!should_include_path("/fonts/roboto.woff2"));
        assert!(!should_include_path("/styles/main.css"));
        assert!(should_include_path("/api/users"));
        assert!(should_include_path("/admin"));
    }
}
