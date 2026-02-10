//! Secrets and credential exposure detection module
//!
//! Scans crawled pages for exposed tokens, API keys, private keys,
//! database connection strings, and other hardcoded credentials.
//! Covers 45+ secret types across cloud providers, SaaS services,
//! AI platforms, payment processors, and more.

use crate::error::Result;
use crate::http::HttpClient;
use crate::models::{Confidence, Finding, ScanConfig, Severity};
use crate::scanner::injection::InjectionScanner;
use async_trait::async_trait;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use tracing::{debug, warn};

/// Maximum number of crawled URLs to inspect
const MAX_URLS: usize = 50;

/// Maximum findings per detection category per URL
const MAX_PER_CATEGORY_PER_URL: usize = 3;

/// Minimum Shannon entropy for generic secret patterns (API keys, passwords)
const MIN_ENTROPY_GENERIC: f64 = 3.0;

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

// ---------------------------------------------------------------------------
// Service-specific token patterns — data-driven table
// Each entry: (regex, title, severity: 0=Critical 1=High 2=Medium, cwe)
// All use Confirmed confidence since they have unique, unambiguous prefixes.
// ---------------------------------------------------------------------------
const SERVICE_TOKEN_PATTERNS: &[(&str, &str, u8, &str)] = &[
    // -- Version Control --
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token", 0, "CWE-798"),
    (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth Access Token", 0, "CWE-798"),
    (r"ghu_[a-zA-Z0-9]{36}", "GitHub User-to-Server Token", 0, "CWE-798"),
    (r"ghs_[A-Za-z0-9_]{36,}", "GitHub Server-to-Server Token", 0, "CWE-798"),
    (r"ghr_[a-zA-Z0-9]{36}", "GitHub Refresh Token", 0, "CWE-798"),
    (r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}", "GitHub Fine-Grained PAT", 0, "CWE-798"),
    (r"glpat-[0-9a-zA-Z_\-]{20,}", "GitLab Personal Access Token", 0, "CWE-798"),
    // -- Communication: Tokens --
    (r"xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9\-]*", "Slack Bot Token", 0, "CWE-798"),
    (r"xoxp-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9\-]*", "Slack User Token", 0, "CWE-798"),
    (r"xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-z0-9]+", "Slack App-Level Token", 0, "CWE-798"),
    // -- Communication: Webhooks --
    (r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}", "Slack Webhook URL", 1, "CWE-798"),
    (r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_\-]+", "Discord Webhook URL", 1, "CWE-798"),
    // -- AI / LLM Providers --
    (r"sk-proj-[A-Za-z0-9_\-]{48,}", "OpenAI API Key", 0, "CWE-798"),
    (r"sk-ant-api03-[a-zA-Z0-9_\-]{90,}", "Anthropic API Key", 0, "CWE-798"),
    (r"hf_[a-zA-Z0-9]{34,}", "HuggingFace Access Token", 1, "CWE-798"),
    // -- Email / SMS --
    (r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}", "SendGrid API Key", 0, "CWE-798"),
    // -- Package Registries --
    (r"npm_[a-zA-Z0-9]{36}", "npm Access Token", 0, "CWE-798"),
    (r"pypi-[A-Za-z0-9_\-]{50,}", "PyPI API Token", 0, "CWE-798"),
    // -- E-commerce --
    (r"shpat_[0-9a-fA-F]{32}", "Shopify Admin Access Token", 0, "CWE-798"),
    (r"shpss_[0-9a-fA-F]{32}", "Shopify Shared Secret", 0, "CWE-798"),
    (r"shpca_[0-9a-fA-F]{32}", "Shopify Custom App Token", 0, "CWE-798"),
    (r"shppa_[0-9a-fA-F]{32}", "Shopify Private App Token", 0, "CWE-798"),
    (r"sq0atp-[0-9A-Za-z_\-]{22}", "Square Access Token", 1, "CWE-798"),
    (r"sq0csp-[0-9A-Za-z_\-]{43}", "Square OAuth Secret", 0, "CWE-798"),
    // -- Cloud / Infrastructure --
    (r"dop_v1_[a-z0-9]{64}", "DigitalOcean Personal Access Token", 0, "CWE-798"),
    (r"hvs\.[a-zA-Z0-9]{24,}", "HashiCorp Vault Service Token", 0, "CWE-798"),
    (r"hvb\.[a-zA-Z0-9]{24,}", "HashiCorp Vault Batch Token", 0, "CWE-798"),
    // -- Monitoring / Observability --
    (r"NRAK-[A-Z0-9]{27}", "New Relic User API Key", 1, "CWE-798"),
    (r"glsa_[a-zA-Z0-9_]{32,}", "Grafana Service Account Token", 1, "CWE-798"),
    (r"glc_[a-zA-Z0-9+/=]{30,}", "Grafana Cloud API Token", 1, "CWE-798"),
    (r"sntrys_[a-zA-Z0-9]{60,}", "Sentry Auth Token", 0, "CWE-798"),
    // -- OAuth Tokens --
    (r"ya29\.[0-9A-Za-z_\-]{30,}", "Google OAuth Access Token", 0, "CWE-798"),
    (r"EAACEdEose0cBA[0-9A-Za-z]{20,}", "Facebook Access Token", 0, "CWE-798"),
    // -- Other Services --
    (r"lin_api_[a-zA-Z0-9]{40}", "Linear API Key", 0, "CWE-798"),
    (r"dp\.st\.[a-zA-Z0-9._\-]{40,}", "Doppler Service Token", 0, "CWE-798"),
    (r"sbp_[a-f0-9]{40}", "Supabase Service Key", 0, "CWE-798"),
    (r"cloudinary://[0-9]+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9]+", "Cloudinary Credentials URL", 0, "CWE-798"),
    (r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}", "Firebase Cloud Messaging Key", 1, "CWE-798"),
];

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Truncate a secret value for evidence: show first 8 + "..." + last 4 chars.
/// Uses char iteration to safely handle multi-byte UTF-8.
fn truncate_secret(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 16 {
        let prefix: String = chars.iter().take(8).collect();
        return format!("{prefix}...");
    }
    let prefix: String = chars.iter().take(8).collect();
    let suffix: String = chars[chars.len() - 4..].iter().collect();
    format!("{prefix}...{suffix}")
}

/// Shannon entropy of a string — measures randomness.
/// High entropy (>3.5) suggests a real secret; low entropy suggests a placeholder.
fn shannon_entropy(s: &str) -> f64 {
    let len = s.len() as f64;
    if len == 0.0 {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Check if a value looks like a placeholder, test value, or template variable
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
        || lower.contains("_here")
        || lower == "test"
        || lower == "testing"
        || lower == "password"
        || lower == "secret"
        || lower == "changeit"
        || lower == "undefined"
        || lower == "null"
        || lower == "none"
    {
        return true;
    }

    // Template variables and environment references
    if value.contains("${")
        || value.contains("#{")
        || value.contains("{{")
        || value.contains("}}")
        || lower.contains("process.env")
        || lower.contains("os.environ")
        || lower.contains("env[")
        || lower.contains("env(")
    {
        return true;
    }

    // HTML-like content (tags, entities)
    if value.starts_with('<') || value.starts_with("&lt;") {
        return true;
    }

    // All same repeated character
    let bytes = value.as_bytes();
    if bytes.len() >= 4 && bytes.iter().all(|&b| b == bytes[0]) {
        return true;
    }

    // All x's, stars, zeros
    if lower.chars().all(|c| c == 'x' || c == '*' || c == '0') && value.len() >= 4 {
        return true;
    }

    // Well-known dummy values
    if lower == "1234567890"
        || lower == "abcdefghijklmnop"
        || lower == "0000000000"
        || lower == "abcdef"
    {
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

// ---------------------------------------------------------------------------
// Detection functions — one per category
// ---------------------------------------------------------------------------

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

/// Detect generic API keys (with entropy filter to reduce FP)
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
            // Entropy filter: low-entropy strings are likely config names, not keys
            if shannon_entropy(key) < MIN_ENTROPY_GENERIC {
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

    // AWS Access Key: AKIA prefix is unique and unambiguous
    if let Ok(re) = Regex::new(r"(?:AKIA|ASIA)[0-9A-Z]{16}") {
        for m in re.find_iter(body) {
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
    }

    // GCP API Key
    if let Ok(re) = Regex::new(r"AIza[0-9A-Za-z_-]{35}") {
        for m in re.find_iter(body) {
            if is_in_comment(body, m.start()) {
                continue;
            }
            matches.push(SecretMatch {
                title: "Exposed GCP API Key".to_string(),
                description: "A Google Cloud Platform API key was found in the page source."
                    .to_string(),
                severity: Severity::Critical,
                confidence: Confidence::Confirmed,
                cwe: "CWE-798",
                evidence: format!("GCP Key: {}", truncate_secret(m.as_str())),
            });
        }
    }

    // Azure connection strings
    if let Ok(re) = Regex::new(r"(?:DefaultEndpointsProtocol=|AccountKey=)[A-Za-z0-9+/=]{20,}") {
        for m in re.find_iter(body) {
            if is_in_comment(body, m.start()) {
                continue;
            }
            matches.push(SecretMatch {
                title: "Exposed Azure Credential".to_string(),
                description:
                    "An Azure connection string or account key was found in the page source."
                        .to_string(),
                severity: Severity::Critical,
                confidence: Confidence::Confirmed,
                cwe: "CWE-798",
                evidence: format!("Azure: {}", truncate_secret(m.as_str())),
            });
        }
    }

    matches
}

/// Detect private keys (RSA, EC, DSA, OPENSSH, PGP)
fn detect_private_keys(body: &str) -> Vec<SecretMatch> {
    let mut matches = Vec::new();
    let re = match Regex::new(
        r"-----BEGIN\s+(?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE\s+KEY(?:\s+BLOCK)?-----",
    ) {
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
            evidence: format!("Key header: {}", m.as_str()),
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

    // Also detect JDBC URLs with credentials
    if let Ok(re) = Regex::new(r"jdbc:\w+://[^:]+:[^@]+@[^\s]{5,}") {
        for m in re.find_iter(body) {
            if is_in_comment(body, m.start()) {
                continue;
            }
            let conn_str = m.as_str();
            if is_placeholder(conn_str) {
                continue;
            }
            matches.push(SecretMatch {
                title: "Exposed JDBC Connection String".to_string(),
                description: "A JDBC connection string with credentials was found.".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::Confirmed,
                cwe: "CWE-798",
                evidence: format!("JDBC: {}", truncate_secret(conn_str)),
            });
        }
    }

    matches
}

/// Detect hardcoded passwords (with entropy filter and HTML exclusion)
fn detect_hardcoded_passwords(body: &str) -> Vec<SecretMatch> {
    let mut matches = Vec::new();
    // Exclude angle brackets to avoid matching HTML attributes
    let pattern = r#"["']?password["']?\s*[:=]\s*["']([^"'<>]{8,})["']"#;
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
            // Entropy filter: low-entropy strings are labels, not passwords
            if shannon_entropy(pass) < MIN_ENTROPY_GENERIC {
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
    if let Ok(re) = Regex::new(r"sk_live_[0-9a-zA-Z]{24,}") {
        for m in re.find_iter(body) {
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
    }

    // Stripe restricted key (critical)
    if let Ok(re) = Regex::new(r"rk_live_[0-9a-zA-Z]{24,}") {
        for m in re.find_iter(body) {
            if is_in_comment(body, m.start()) {
                continue;
            }
            matches.push(SecretMatch {
                title: "Exposed Stripe Restricted Key".to_string(),
                description: "A Stripe live restricted key was found.".to_string(),
                severity: Severity::Critical,
                confidence: Confidence::Confirmed,
                cwe: "CWE-798",
                evidence: format!("Stripe RK: {}", truncate_secret(m.as_str())),
            });
        }
    }

    // Stripe publishable key (high, less severe)
    if let Ok(re) = Regex::new(r"pk_live_[0-9a-zA-Z]{24,}") {
        for m in re.find_iter(body) {
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
    }

    // Square, Braintree handled in service tokens

    matches
}

/// Detect service-specific tokens using the pattern table (37 patterns)
fn detect_service_tokens(body: &str) -> Vec<SecretMatch> {
    let mut matches = Vec::new();

    for &(pattern, title, sev, cwe) in SERVICE_TOKEN_PATTERNS {
        let re = match Regex::new(pattern) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for m in re.find_iter(body) {
            if is_in_comment(body, m.start()) {
                continue;
            }
            let value = m.as_str();
            if is_placeholder(value) {
                continue;
            }
            let severity = match sev {
                0 => Severity::Critical,
                1 => Severity::High,
                _ => Severity::Medium,
            };
            matches.push(SecretMatch {
                title: title.to_string(),
                description: format!(
                    "A {} was found exposed in the page source. Rotate it immediately.",
                    title
                ),
                severity,
                confidence: Confidence::Confirmed,
                cwe,
                evidence: format!("{}: {}", title, truncate_secret(value)),
            });
        }
    }

    matches
}

/// Detect internal/private URLs and IPs exposed in page source
fn detect_internal_urls(body: &str) -> Vec<SecretMatch> {
    let mut matches = Vec::new();

    // RFC1918 private IPs with scheme
    if let Ok(re) = Regex::new(
        r"https?://(?:(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/[^\s<>]*)?",
    ) {
        for m in re.find_iter(body) {
            if is_in_comment(body, m.start()) {
                continue;
            }
            matches.push(SecretMatch {
                title: "Internal IP Address Exposed".to_string(),
                description: "A private/internal IP address was found in the page source. \
                    This reveals internal network topology to attackers."
                    .to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Confirmed,
                cwe: "CWE-200",
                evidence: format!("Internal URL: {}", truncate_secret(m.as_str())),
            });
        }
    }

    // Localhost with port (suggests backend service info)
    if let Ok(re) = Regex::new(r"https?://(?:localhost|127\.0\.0\.1):\d+(?:/[^\s<>]*)?") {
        for m in re.find_iter(body) {
            if is_in_comment(body, m.start()) {
                continue;
            }
            matches.push(SecretMatch {
                title: "Localhost URL with Port Exposed".to_string(),
                description: "A localhost URL with a specific port was found. \
                    This reveals backend service architecture."
                    .to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Confirmed,
                cwe: "CWE-200",
                evidence: format!("Localhost: {}", truncate_secret(m.as_str())),
            });
        }
    }

    // Internal hostnames (.local, .internal, .corp, .lan, .intranet)
    if let Ok(re) = Regex::new(
        r"https?://[a-zA-Z0-9_.\-]+\.(?:local|internal|corp|lan|intranet)(?::\d+)?(?:/[^\s<>]*)?",
    ) {
        for m in re.find_iter(body) {
            if is_in_comment(body, m.start()) {
                continue;
            }
            matches.push(SecretMatch {
                title: "Internal Hostname Exposed".to_string(),
                description: "An internal hostname was found in the page source. \
                    This reveals internal infrastructure details."
                    .to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Confirmed,
                cwe: "CWE-200",
                evidence: format!("Internal host: {}", truncate_secret(m.as_str())),
            });
        }
    }

    matches
}

/// Detect Sentry DSNs (semi-public but still info disclosure)
fn detect_sentry_dsn(body: &str) -> Vec<SecretMatch> {
    let mut matches = Vec::new();
    if let Ok(re) =
        Regex::new(r"https://[a-f0-9]{32}@[a-z0-9]+\.ingest(?:\.[a-z]+)?\.sentry\.io/[0-9]+")
    {
        for m in re.find_iter(body) {
            if is_in_comment(body, m.start()) {
                continue;
            }
            matches.push(SecretMatch {
                title: "Sentry DSN Exposed".to_string(),
                description: "A Sentry DSN was found. While semi-public, it allows sending \
                    arbitrary error events to the project and reveals the Sentry organization."
                    .to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Confirmed,
                cwe: "CWE-200",
                evidence: format!("Sentry DSN: {}", truncate_secret(m.as_str())),
            });
        }
    }
    matches
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

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
    results.insert("service_tokens", detect_service_tokens(body));
    results.insert("internal_urls", detect_internal_urls(body));
    results.insert("sentry", detect_sentry_dsn(body));

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
        // Dedup: track seen (title, evidence) to avoid reporting the same secret
        // found via multiple pages that reference the same JS bundle
        let mut seen_secrets: HashSet<String> = HashSet::new();

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
                    // Dedup by (title + evidence) across all URLs
                    let dedup_key = format!("{}|{}", secret.title, secret.evidence);
                    if !seen_secrets.insert(dedup_key) {
                        continue;
                    }

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
