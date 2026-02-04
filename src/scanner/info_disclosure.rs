//! Information disclosure detection module

use crate::error::Result;
use crate::http::HttpClient;
use crate::models::{Finding, ScanConfig, Severity};
use async_trait::async_trait;
use regex::Regex;
use scraper::{Html, Selector};

/// Detects information disclosure vulnerabilities
pub struct InfoDisclosureScanner;

const ERROR_PATTERNS: &[(&str, &str)] = &[
    (r"(?i)stack\s*trace", "Stack trace detected"),
    (r"(?i)exception\s+in\s+thread", "Java exception detected"),
    (
        r"(?i)traceback\s*\(most\s+recent",
        "Python traceback detected",
    ),
    (
        r"(?i)fatal\s+error.*on\s+line\s+\d+",
        "PHP fatal error detected",
    ),
    (r"(?i)uncaught\s+exception", "Uncaught exception detected"),
    (
        r"(?i)internal\s+server\s+error",
        "Internal server error page",
    ),
    (r"(?i)syntax\s+error.*\.php", "PHP syntax error"),
    (
        r"(?i)warning:.*\bon\s+line\s+\d+",
        "PHP warning with line number",
    ),
    (r"(?i)microsoft\s+ole\s+db", "OLE DB error"),
    (r"(?i)odbc\s+.*driver", "ODBC driver error"),
    (
        r"(?i)\bat\s+\w+\.\w+\.\w+\(",
        ".NET/Java stack trace pattern",
    ),
];

const SENSITIVE_COMMENT_PATTERNS: &[(&str, &str)] = &[
    (r"(?i)password", "Password reference in comment"),
    (r"(?i)api[_\-]?key", "API key reference in comment"),
    (r"(?i)secret", "Secret reference in comment"),
    (r"(?i)todo|fixme|hack|bug", "Developer note in comment"),
    (
        r"(?i)internal|private|confidential",
        "Confidential reference",
    ),
    (r"(?i)username|user_name", "Username reference in comment"),
    (
        r"(?i)database|db_host|db_pass",
        "Database reference in comment",
    ),
    (r"(?i)token", "Token reference in comment"),
    (
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "IP address in comment",
    ),
];

#[async_trait]
impl super::Scanner for InfoDisclosureScanner {
    fn name(&self) -> &str {
        "info_disclosure"
    }

    fn description(&self) -> &str {
        "Detects information disclosure through error messages, comments, and exposed metadata"
    }

    async fn scan(
        &self,
        client: &HttpClient,
        config: &ScanConfig,
        _crawled_urls: &[String],
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let response = client.get(&config.target).await?;
        let body = response.text().await.unwrap_or_default();

        // Check for error patterns in response body
        for (pattern, description) in ERROR_PATTERNS {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(m) = re.find(&body) {
                    let context_start = m.start().saturating_sub(50);
                    let context_end = (m.end() + 50).min(body.len());
                    let context = &body[context_start..context_end];

                    findings.push(
                        Finding::new(
                            format!("Information Disclosure: {description}"),
                            "The application exposes detailed error messages revealing internal details.",
                            Severity::Medium,
                            "Information Disclosure",
                            &config.target,
                        )
                        .with_evidence(format!("Pattern: {description}\nContext: ...{context}..."))
                        .with_recommendation("Show generic error pages in production. Log details server-side only.")
                        .with_cwe("CWE-209")
                        .with_owasp("A05:2021 Security Misconfiguration"),
                    );
                    break;
                }
            }
        }

        // Check HTML comments for sensitive information
        let comment_regex = Regex::new(r"<!--([\s\S]*?)-->")
            .unwrap_or_else(|_| Regex::new(r"$^").expect("fallback regex"));

        for cap in comment_regex.captures_iter(&body) {
            if let Some(comment_content) = cap.get(1) {
                let comment = comment_content.as_str();

                for (pattern, description) in SENSITIVE_COMMENT_PATTERNS {
                    if let Ok(re) = Regex::new(pattern) {
                        if re.is_match(comment) {
                            let truncated = if comment.len() > 200 {
                                format!("{}...", &comment[..200])
                            } else {
                                comment.to_string()
                            };

                            findings.push(
                                Finding::new(
                                    format!("Sensitive HTML Comment: {description}"),
                                    "HTML comments contain potentially sensitive information visible in page source.",
                                    Severity::Low,
                                    "Information Disclosure",
                                    &config.target,
                                )
                                .with_evidence(format!("Comment: <!--{truncated}-->"))
                                .with_recommendation("Remove sensitive comments from production HTML.")
                                .with_cwe("CWE-615")
                                .with_owasp("A01:2021 Broken Access Control"),
                            );
                            break;
                        }
                    }
                }
            }
        }

        // Check for directory listing
        let dir_listing_indicators = [
            "Index of /",
            "Directory listing for",
            "<title>Directory listing",
            "Parent Directory",
        ];
        for indicator in &dir_listing_indicators {
            if body.contains(indicator) {
                findings.push(
                    Finding::new(
                        "Directory Listing Enabled",
                        "Directory listing is enabled, allowing attackers to browse and discover files.",
                        Severity::Medium,
                        "Information Disclosure",
                        &config.target,
                    )
                    .with_evidence(format!("Page contains: '{indicator}'"))
                    .with_recommendation("Disable directory listing in the web server configuration.")
                    .with_cwe("CWE-548")
                    .with_owasp("A01:2021 Broken Access Control"),
                );
                break;
            }
        }

        // Check for generator meta tag
        let document = Html::parse_document(&body);
        if let Ok(selector) = Selector::parse("meta[name='generator']") {
            for element in document.select(&selector) {
                if let Some(content) = element.value().attr("content") {
                    findings.push(
                        Finding::new(
                            "Generator Meta Tag Reveals Technology",
                            "The meta generator tag reveals the CMS or framework used.",
                            Severity::Low,
                            "Information Disclosure",
                            &config.target,
                        )
                        .with_evidence(format!("Meta generator: {content}"))
                        .with_recommendation("Remove the generator meta tag from production pages.")
                        .with_cwe("CWE-200")
                        .with_owasp("A05:2021 Security Misconfiguration"),
                    );
                }
            }
        }

        Ok(findings)
    }
}
