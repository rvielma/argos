//! Secrets and credential exposure detection module
//!
//! Scans crawled pages for exposed tokens, API keys, private keys,
//! database connection strings, and other hardcoded credentials.

use crate::error::Result;
use crate::http::HttpClient;
use crate::models::{Confidence, Finding, ScanConfig, Severity};
use crate::scanner::injection::InjectionScanner;
use async_trait::async_trait;
use regex::Regex;
use std::collections::HashMap;
use tracing::{debug, warn};

/// Maximum number of crawled URLs to inspect
const MAX_URLS: usize = 50;

/// Maximum findings per detection category per URL
const MAX_PER_CATEGORY_PER_URL: usize = 3;

/// Detects exposed secrets, tokens, and credentials in page bodies
pub struct SecretsScanner;

/// A secret match found in page content
struct SecretMatch {
    title: String,
    description: String,
    severity: Severity,
    confidence: Confidence,
    cwe: &'static str,
    evidence: String,
}

/// Truncate a secret value for evidence: show first 8 + "..." + last 4 chars
fn truncate_secret(value: &str) -> String {
    if value.len() <= 16 {
        return format!("{}...", &value[..value.len().min(8)]);
    }
    let start = &value[..8];
    let end = &value[value.len() - 4..];
    format!("{start}...{end}")
}

/// Check if a value looks like a placeholder or test value
fn is_placeholder(value: &str) -> bool {
    let lower = value.to_lowercase();

    // Common placeholder words
    if lower.contains("your_")
        || lower.contains("change_me")
        || lower.contains("changeme")
        || lower.contains("example")
        || lower.contains("sample")
        || lower.contains("placeholder")
        || lower.contains("todo")
        || lower.contains("fixme")
        || lower.contains("insert_")
        || lower.contains("replace_")
        || lower.contains("put_your")
        || lower.contains("enter_your")
        || lower.contains("add_your")
        || lower == "test"
        || lower == "testing"
        || lower == "password"
        || lower == "secret"
        || lower == "changeit"
    {
        return true;
    }

    // All x's, stars, or same repeated char
    let bytes = value.as_bytes();
    if bytes.len() >= 4 && bytes.iter().all(|&b| b == bytes[0]) {
        return true;
    }
    if lower.chars().all(|c| c == 'x' || c == '*' || c == '0') && value.len() >= 4 {
        return true;
    }

    // Sequential patterns like "1234567890" or "abcdefgh"
    if lower == "1234567890" || lower == "abcdefghijklmnop" || lower == "0000000000" {
        return true;
    }

    false
}

/// Check if the match position is inside an HTML or JS comment
fn is_in_comment(body: &str, match_start: usize) -> bool {
    // Check HTML comment: find last <!-- before match, ensure no --> between
    if let Some(html_open) = body[..match_start].rfind("<!--") {
        if !body[html_open..match_start].contains("-->") {
            return true;
        }
    }

    // Check JS block comment: find last /* before match, ensure no */ between
    if let Some(js_open) = body[..match_start].rfind("/*") {
        if !body[js_open..match_start].contains("*/") {
            return true;
        }
    }

    // Check JS line comment: find last \n before match, check if // precedes
    let line_start = body[..match_start].rfind('\n').map_or(0, |p| p + 1);
    let line_prefix = body[line_start..match_start].trim();
    if line_prefix.starts_with("//") {
        return true;
    }

    false
}

/// Detect JWT tokens
fn detect_jwt(body: &str) -> Vec<SecretMatch> {
    let mut matches = Vec::new();
    let re = match Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*") {
        Ok(r) => r,
        Err(_) => return matches,
    };

    for m in re.find_iter(body) {
        if is_in_comment(body, m.start()) {
            continue;
        }
        let token = m.as_str();
        if is_placeholder(token) {
            continue;
        }
        matches.push(SecretMatch {
            title: "Exposed JWT Token".to_string(),
            description: "A JSON Web Token (JWT) was found exposed in the page source. \
                JWTs may contain authentication claims and allow impersonation if captured."
                .to_string(),
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            cwe: "CWE-798",
            evidence: format!("JWT: {}", truncate_secret(token)),
        });
    }

    matches
}

/// Detect OAuth/Bearer tokens and related secrets
fn detect_oauth_tokens(body: &str) -> Vec<SecretMatch> {
    let mut matches = Vec::new();

    let patterns: &[(&str, &str, Severity)] = &[
        (
            r"Bearer\s+[A-Za-z0-9_\-\.]{20,}",
            "Exposed Bearer Token",
            Severity::Critical,
        ),
        (
            r#"access_token["']\s*[:=]\s*["'][A-Za-z0-9_\-\.]{20,}"#,
            "Exposed Access Token",
            Severity::Critical,
        ),
        (
            r#"refresh_token["']\s*[:=]\s*["'][A-Za-z0-9_\-\.]{20,}"#,
            "Exposed Refresh Token",
            Severity::Critical,
        ),
        (
            r#"client_secret["']\s*[:=]\s*["'][A-Za-z0-9_\-\.]{10,}"#,
            "Exposed Client Secret",
            Severity::Critical,
        ),
    ];

    for (pattern, title, severity) in patterns {
        let re = match Regex::new(pattern) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for m in re.find_iter(body) {
            if is_in_comment(body, m.start()) {
                continue;
            }
            let value = m.as_str();
            // Extract the actual token part after = or space
            let token_part = value
                .split(['=', ' ', ':', '\'', '"'])
                .rfind(|s| s.len() >= 10)
                .unwrap_or(value);
            if is_placeholder(token_part) {
                continue;
            }
            matches.push(SecretMatch {
                title: title.to_string(),
                description: "An OAuth/Bearer credential was found in the page source. \
                    Attackers can use this to authenticate as the token holder."
                    .to_string(),
                severity: severity.clone(),
                confidence: Confidence::Confirmed,
                cwe: "CWE-798",
                evidence: format!("{}: {}", title, truncate_secret(value)),
            });
        }
    }

    matches
}

/// Detect generic API keys
fn detect_api_keys(body: &str) -> Vec<SecretMatch> {
    let mut matches = Vec::new();
    let re = match Regex::new(
        r#"["']?(?:api[_\-]?key|apikey|api_secret)["']?\s*[:=]\s*["']([A-Za-z0-9_\-]{20,})["']"#,
    ) {
        Ok(r) => r,
        Err(_) => return matches,
    };

    for cap in re.captures_iter(body) {
        let full_match = cap.get(0).expect("full match exists");
        if is_in_comment(body, full_match.start()) {
            continue;
        }
        if let Some(key_val) = cap.get(1) {
            let key = key_val.as_str();
            if is_placeholder(key) {
                continue;
            }
            matches.push(SecretMatch {
                title: "Exposed API Key".to_string(),
                description: "A generic API key was found in the page source. \
                    API keys can grant unauthorized access to backend services."
                    .to_string(),
                severity: Severity::High,
                confidence: Confidence::Tentative,
                cwe: "CWE-798",
                evidence: format!("API Key: {}", truncate_secret(key)),
            });
        }
    }

    matches
}

/// Detect cloud provider keys (AWS, GCP, Azure)
fn detect_cloud_keys(body: &str) -> Vec<SecretMatch> {
    let mut matches = Vec::new();

    // AWS Access Key
    let aws_re = match Regex::new(r"AKIA[0-9A-Z]{16}") {
        Ok(r) => r,
        Err(_) => return matches,
    };
    for m in aws_re.find_iter(body) {
        if is_in_comment(body, m.start()) {
            continue;
        }
        matches.push(SecretMatch {
            title: "Exposed AWS Access Key".to_string(),
            description: "An AWS Access Key ID was found in the page source. \
                This can be used with the corresponding secret key to access AWS resources."
                .to_string(),
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            cwe: "CWE-798",
            evidence: format!("AWS Key: {}", truncate_secret(m.as_str())),
        });
    }

    // GCP API Key
    let gcp_re = match Regex::new(r"AIza[0-9A-Za-z_-]{35}") {
        Ok(r) => r,
        Err(_) => return matches,
    };
    for m in gcp_re.find_iter(body) {
        if is_in_comment(body, m.start()) {
            continue;
        }
        matches.push(SecretMatch {
            title: "Exposed GCP API Key".to_string(),
            description: "A Google Cloud Platform API key was found in the page source.".to_string(),
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            cwe: "CWE-798",
            evidence: format!("GCP Key: {}", truncate_secret(m.as_str())),
        });
    }

    // Azure connection strings
    let azure_re = match Regex::new(r"(?:DefaultEndpointsProtocol=|AccountKey=)[A-Za-z0-9+/=]{20,}")
    {
        Ok(r) => r,
        Err(_) => return matches,
    };
    for m in azure_re.find_iter(body) {
        if is_in_comment(body, m.start()) {
            continue;
        }
        matches.push(SecretMatch {
            title: "Exposed Azure Credential".to_string(),
            description: "An Azure connection string or account key was found in the page source."
                .to_string(),
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            cwe: "CWE-798",
            evidence: format!("Azure: {}", truncate_secret(m.as_str())),
        });
    }

    matches
}

/// Detect private keys (RSA, etc.)
fn detect_private_keys(body: &str) -> Vec<SecretMatch> {
    let mut matches = Vec::new();
    let re = match Regex::new(r"-----BEGIN\s(?:RSA\s)?PRIVATE\sKEY-----") {
        Ok(r) => r,
        Err(_) => return matches,
    };

    for m in re.find_iter(body) {
        if is_in_comment(body, m.start()) {
            continue;
        }
        matches.push(SecretMatch {
            title: "Exposed Private Key".to_string(),
            description: "A private key was found in the page source. \
                Private keys allow decryption and impersonation attacks."
                .to_string(),
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            cwe: "CWE-321",
            evidence: "Private key header: -----BEGIN [RSA] PRIVATE KEY-----".to_string(),
        });
    }

    matches
}

/// Detect database connection strings with embedded credentials
fn detect_db_connection_strings(body: &str) -> Vec<SecretMatch> {
    let mut matches = Vec::new();
    let re = match Regex::new(
        r#"(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^:]+:[^@]+@[^\s'"<>]{5,}"#,
    ) {
        Ok(r) => r,
        Err(_) => return matches,
    };

    for m in re.find_iter(body) {
        if is_in_comment(body, m.start()) {
            continue;
        }
        let conn_str = m.as_str();
        if is_placeholder(conn_str) {
            continue;
        }
        // Detect the DB type for the title
        let db_type = if conn_str.starts_with("mongodb") {
            "MongoDB"
        } else if conn_str.starts_with("postgres") {
            "PostgreSQL"
        } else if conn_str.starts_with("mysql") {
            "MySQL"
        } else {
            "Redis"
        };

        matches.push(SecretMatch {
            title: format!("Exposed {} Connection String", db_type),
            description: format!(
                "A {} connection string with embedded credentials was found. This allows direct database access.",
                db_type
            ),
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            cwe: "CWE-798",
            evidence: format!("DB URI: {}", truncate_secret(conn_str)),
        });
    }

    matches
}

/// Detect hardcoded passwords
fn detect_hardcoded_passwords(body: &str) -> Vec<SecretMatch> {
    let mut matches = Vec::new();
    let pattern = r#"["']?password["']?\s*[:=]\s*["']([^"']{8,})["']"#;
    let re = match Regex::new(pattern) {
        Ok(r) => r,
        Err(_) => return matches,
    };

    for cap in re.captures_iter(body) {
        let full_match = cap.get(0).expect("full match exists");
        if is_in_comment(body, full_match.start()) {
            continue;
        }
        if let Some(pass_val) = cap.get(1) {
            let pass = pass_val.as_str();
            if is_placeholder(pass) {
                continue;
            }
            matches.push(SecretMatch {
                title: "Hardcoded Password".to_string(),
                description:
                    "A hardcoded password was found in the page source. \
                    Credentials in client-side code can be extracted by any visitor."
                        .to_string(),
                severity: Severity::High,
                confidence: Confidence::Tentative,
                cwe: "CWE-798",
                evidence: format!("Password value: {}", truncate_secret(pass)),
            });
        }
    }

    matches
}

/// Detect Stripe and payment keys
fn detect_payment_keys(body: &str) -> Vec<SecretMatch> {
    let mut matches = Vec::new();

    // Stripe secret key (critical)
    let sk_re = match Regex::new(r"sk_live_[0-9a-zA-Z]{24,}") {
        Ok(r) => r,
        Err(_) => return matches,
    };
    for m in sk_re.find_iter(body) {
        if is_in_comment(body, m.start()) {
            continue;
        }
        matches.push(SecretMatch {
            title: "Exposed Stripe Secret Key".to_string(),
            description: "A Stripe live secret key was found. \
                This allows full access to the Stripe account including charges and refunds."
                .to_string(),
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            cwe: "CWE-798",
            evidence: format!("Stripe SK: {}", truncate_secret(m.as_str())),
        });
    }

    // Stripe publishable key (high, less severe)
    let pk_re = match Regex::new(r"pk_live_[0-9a-zA-Z]{24,}") {
        Ok(r) => r,
        Err(_) => return matches,
    };
    for m in pk_re.find_iter(body) {
        if is_in_comment(body, m.start()) {
            continue;
        }
        matches.push(SecretMatch {
            title: "Exposed Stripe Publishable Key (Live)".to_string(),
            description: "A Stripe live publishable key was found. While less sensitive than \
                secret keys, live publishable keys should not be exposed outside intended contexts."
                .to_string(),
            severity: Severity::High,
            confidence: Confidence::Tentative,
            cwe: "CWE-798",
            evidence: format!("Stripe PK: {}", truncate_secret(m.as_str())),
        });
    }

    matches
}

/// All detection functions to run against each page body
fn run_all_detectors(body: &str) -> HashMap<&'static str, Vec<SecretMatch>> {
    let mut results: HashMap<&'static str, Vec<SecretMatch>> = HashMap::new();

    results.insert("jwt", detect_jwt(body));
    results.insert("oauth", detect_oauth_tokens(body));
    results.insert("api_keys", detect_api_keys(body));
    results.insert("cloud", detect_cloud_keys(body));
    results.insert("private_keys", detect_private_keys(body));
    results.insert("db_conn", detect_db_connection_strings(body));
    results.insert("passwords", detect_hardcoded_passwords(body));
    results.insert("payment", detect_payment_keys(body));

    results
}

#[async_trait]
impl super::Scanner for SecretsScanner {
    fn name(&self) -> &str {
        "secrets"
    }

    fn description(&self) -> &str {
        "Detects exposed secrets, tokens, API keys, and credentials in page source"
    }

    async fn scan(
        &self,
        client: &HttpClient,
        config: &ScanConfig,
        crawled_urls: &[String],
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Always include the target URL, plus crawled URLs up to MAX_URLS
        let mut urls_to_check: Vec<&str> = vec![&config.target];
        for url in crawled_urls.iter().take(MAX_URLS) {
            if url != &config.target {
                urls_to_check.push(url);
            }
        }

        for url in &urls_to_check {
            // Skip OAuth/SSO URLs
            if InjectionScanner::is_oauth_url(url) {
                debug!("Secrets: skipping OAuth URL: {}", url);
                continue;
            }

            let body = match client.get(url).await {
                Ok(resp) => resp.text().await.unwrap_or_default(),
                Err(e) => {
                    warn!("Secrets: failed to fetch {}: {}", url, e);
                    continue;
                }
            };

            if body.is_empty() {
                continue;
            }

            let detections = run_all_detectors(&body);

            for secret_matches in detections.values() {
                for secret in secret_matches.iter().take(MAX_PER_CATEGORY_PER_URL) {
                    findings.push(
                        Finding::new(
                            &secret.title,
                            &secret.description,
                            secret.severity.clone(),
                            "Secrets Exposure",
                            *url,
                        )
                        .with_confidence(secret.confidence.clone())
                        .with_evidence(&secret.evidence)
                        .with_recommendation(
                            "Immediately rotate the exposed credential. \
                            Remove secrets from client-side code and use server-side \
                            environment variables or a secrets manager instead.",
                        )
                        .with_cwe(secret.cwe)
                        .with_owasp("A07:2021 Identification and Authentication Failures"),
                    );
                }
            }
        }

        Ok(findings)
    }
}
