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
use base64::Engine;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Maximum number of crawled URLs to inspect
const MAX_URLS: usize = 50;

/// Maximum findings per detection category per URL
const MAX_PER_CATEGORY_PER_URL: usize = 3;

/// Minimum Shannon entropy for generic secret patterns (API keys, passwords)
const MIN_ENTROPY_GENERIC: f64 = 3.0;

/// Maximum JS files to probe for source maps
const MAX_SOURCE_MAP_FILES: usize = 20;

/// Maximum source map file size (5 MB)
const MAX_SOURCE_MAP_SIZE: usize = 5 * 1024 * 1024;

/// Maximum git reflog size to scan (1 MB)
const MAX_GIT_REFLOG_SIZE: usize = 1024 * 1024;

/// Detects exposed secrets, tokens, and credentials in page bodies
pub struct SecretsScanner;

/// A secret match found in page content
#[derive(Clone)]
struct SecretMatch {
    title: String,
    description: String,
    severity: Severity,
    confidence: Confidence,
    cwe: &'static str,
    evidence: String,
    raw_value: Option<String>,
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
    // -- Email (Mailgun) --
    (r"key-[0-9a-f]{32}", "Mailgun API Key", 0, "CWE-798"),
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
            raw_value: Some(token.to_string()),
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
                raw_value: Some(token_part.to_string()),
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
                raw_value: Some(key.to_string()),
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
                raw_value: Some(m.as_str().to_string()),
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
                raw_value: Some(m.as_str().to_string()),
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
                raw_value: Some(m.as_str().to_string()),
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
            raw_value: None,
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
            raw_value: None,
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
                raw_value: None,
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
                raw_value: None,
            });
        }
    }

    matches
}

/// Detect credential pairs (email + password together) — no entropy filter needed
/// since the email context provides strong signal this is a real credential.
fn detect_credential_pairs(body: &str) -> Vec<SecretMatch> {
    let mut matches = Vec::new();

    // Pattern: email:"...",password:"..." or email:"...", password:"..."
    // Also handles username/user fields paired with password
    let re = match Regex::new(
        r#"["']?(?:email|user|username)["']?\s*[:=]\s*["']([^"']{3,}@[^"']{2,}\.[^"']{2,})["']\s*[,}\s]\s*["']?password["']?\s*[:=]\s*["']([^"'<>]{4,})["']"#,
    ) {
        Ok(r) => r,
        Err(_) => return matches,
    };

    for cap in re.captures_iter(body) {
        let full_match = cap.get(0).expect("full match exists");
        if is_in_comment(body, full_match.start()) {
            continue;
        }
        let email = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let password = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        if is_placeholder(password) || is_placeholder(email) {
            continue;
        }
        // Skip documentation examples with literal <password>
        if password.contains('<') || password.contains('>') {
            continue;
        }
        matches.push(SecretMatch {
            title: "Hardcoded Credentials (Email + Password)".to_string(),
            description: "An email and password pair was found hardcoded in the page source. \
                This allows direct authentication to the associated service."
                .to_string(),
            severity: Severity::Critical,
            confidence: Confidence::Confirmed,
            cwe: "CWE-798",
            evidence: format!(
                "Credentials: {} / {}",
                email,
                truncate_secret(password)
            ),
            raw_value: None,
        });
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
                raw_value: Some(m.as_str().to_string()),
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
                raw_value: Some(m.as_str().to_string()),
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
                raw_value: Some(m.as_str().to_string()),
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
                raw_value: Some(value.to_string()),
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
                raw_value: None,
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
                raw_value: None,
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
                raw_value: None,
            });
        }
    }

    matches
}

/// Detect secrets in JS runtime config objects, leaked env vars, and unresolved process.env
fn detect_js_config_secrets(body: &str) -> Vec<SecretMatch> {
    let mut matches = Vec::new();

    // 1. Window config objects — extract JSON blocks and scan them
    let config_re = match Regex::new(
        r"(?:window\.__CONFIG__|window\.__INITIAL_STATE__|window\.__ENV__|window\.__NEXT_DATA__|window\.env)\s*=\s*(\{[^;]{10,}?\});",
    ) {
        Ok(r) => r,
        Err(_) => return matches,
    };

    for cap in config_re.captures_iter(body) {
        if let Some(json_match) = cap.get(1) {
            let json_str = json_match.as_str();
            // Scan the JSON block with all detectors (avoid infinite recursion by not calling this fn)
            let inner_matches = detect_service_tokens(json_str);
            for mut m in inner_matches {
                m.evidence = format!("{} [in window config object]", m.evidence);
                matches.push(m);
            }
            let inner_cloud = detect_cloud_keys(json_str);
            for mut m in inner_cloud {
                m.evidence = format!("{} [in window config object]", m.evidence);
                matches.push(m);
            }
            let inner_api = detect_api_keys(json_str);
            for mut m in inner_api {
                m.evidence = format!("{} [in window config object]", m.evidence);
                matches.push(m);
            }
        }
    }

    // 2. Leaked env vars: REACT_APP_*, NEXT_PUBLIC_*, VUE_APP_*, VITE_*
    let env_re = match Regex::new(
        r#"["']?((?:REACT_APP|NEXT_PUBLIC|VUE_APP|VITE)_[A-Z_]+)["']?\s*[:=]\s*["']([^"']{8,})["']"#,
    ) {
        Ok(r) => r,
        Err(_) => return matches,
    };

    let sensitive_keywords = ["KEY", "SECRET", "TOKEN", "PASSWORD", "PRIVATE", "CREDENTIAL"];

    for cap in env_re.captures_iter(body) {
        let full_match = cap.get(0).expect("full match");
        if is_in_comment(body, full_match.start()) {
            continue;
        }
        let var_name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let var_value = cap.get(2).map(|m| m.as_str()).unwrap_or("");

        // Only flag if name contains a sensitive keyword
        let upper_name = var_name.to_uppercase();
        if !sensitive_keywords.iter().any(|kw| upper_name.contains(kw)) {
            continue;
        }
        if is_placeholder(var_value) {
            continue;
        }
        if shannon_entropy(var_value) < MIN_ENTROPY_GENERIC {
            continue;
        }
        matches.push(SecretMatch {
            title: "Leaked Environment Variable".to_string(),
            description: format!(
                "Sensitive environment variable {} was found exposed in client-side JavaScript. \
                 Framework env vars prefixed with REACT_APP_/NEXT_PUBLIC_/VUE_APP_/VITE_ are bundled \
                 into the client and visible to all visitors.",
                var_name
            ),
            severity: Severity::High,
            confidence: Confidence::Tentative,
            cwe: "CWE-798",
            evidence: format!("{}={}", var_name, truncate_secret(var_value)),
            raw_value: Some(var_value.to_string()),
        });
    }

    // 3. Unresolved process.env references (bundler misconfiguration)
    let process_env_re = match Regex::new(r"process\.env\.([A-Z_][A-Z0-9_]{2,})") {
        Ok(r) => r,
        Err(_) => return matches,
    };

    let safe_env_vars = [
        "NODE_ENV", "PORT", "HOST", "DEBUG", "HOSTNAME", "HOME", "PATH", "LANG", "TZ",
        "PUBLIC_URL", "BASE_URL",
    ];
    let mut seen_vars: HashSet<String> = HashSet::new();

    for cap in process_env_re.captures_iter(body) {
        let full_match = cap.get(0).expect("full match");
        if is_in_comment(body, full_match.start()) {
            continue;
        }
        let var_name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        if safe_env_vars.contains(&var_name) {
            continue;
        }
        if !seen_vars.insert(var_name.to_string()) {
            continue;
        }
        matches.push(SecretMatch {
            title: "Unresolved process.env Reference".to_string(),
            description: format!(
                "Reference to process.env.{} was found in bundled JavaScript. \
                 This means the bundler did not replace it at build time, which may \
                 cause runtime errors or expose the variable name to attackers.",
                var_name
            ),
            severity: Severity::Low,
            confidence: Confidence::Confirmed,
            cwe: "CWE-200",
            evidence: format!("process.env.{}", var_name),
            raw_value: None,
        });
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
                raw_value: None,
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
    results.insert("credential_pairs", detect_credential_pairs(body));
    results.insert("payment", detect_payment_keys(body));
    results.insert("service_tokens", detect_service_tokens(body));
    results.insert("internal_urls", detect_internal_urls(body));
    results.insert("sentry", detect_sentry_dsn(body));
    results.insert("js_config", detect_js_config_secrets(body));

    results
}

// ---------------------------------------------------------------------------
// Active secret verification
// ---------------------------------------------------------------------------

/// Result of attempting to verify a secret against its provider API
enum VerificationResult {
    /// Token is valid and active
    Valid,
    /// Token was rejected (rotated/revoked)
    Invalid,
    /// Could not determine validity
    Unknown,
    /// JWT decoded with payload details (status label + claims summary)
    JwtDecoded { status: String, details: String },
}

/// Build a minimal reqwest client for verification (no auth headers, 5s timeout)
fn build_verification_client() -> std::result::Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
}

/// Verify a secret by calling its provider's read-only API
async fn verify_secret(title: &str, raw_value: &str) -> VerificationResult {
    let http_client = match build_verification_client() {
        Ok(c) => c,
        Err(_) => return VerificationResult::Unknown,
    };

    // GitHub PAT (ghp_, github_pat_)
    if raw_value.starts_with("ghp_") || raw_value.starts_with("github_pat_") {
        return verify_http_get(
            &http_client,
            "https://api.github.com/user",
            &format!("token {raw_value}"),
            "Authorization",
        )
        .await;
    }

    // GitLab PAT (glpat-)
    if raw_value.starts_with("glpat-") {
        return verify_http_get(
            &http_client,
            "https://gitlab.com/api/v4/user",
            raw_value,
            "PRIVATE-TOKEN",
        )
        .await;
    }

    // Slack tokens (xoxb-, xoxp-)
    if raw_value.starts_with("xoxb-") || raw_value.starts_with("xoxp-") {
        return verify_slack_token(&http_client, raw_value).await;
    }

    // OpenAI (sk-proj-)
    if raw_value.starts_with("sk-proj-") {
        return verify_http_get(
            &http_client,
            "https://api.openai.com/v1/models",
            &format!("Bearer {raw_value}"),
            "Authorization",
        )
        .await;
    }

    // HuggingFace (hf_)
    if raw_value.starts_with("hf_") {
        return verify_http_get(
            &http_client,
            "https://huggingface.co/api/whoami",
            &format!("Bearer {raw_value}"),
            "Authorization",
        )
        .await;
    }

    // SendGrid (SG.)
    if raw_value.starts_with("SG.") {
        return verify_http_get(
            &http_client,
            "https://api.sendgrid.com/v3/scopes",
            &format!("Bearer {raw_value}"),
            "Authorization",
        )
        .await;
    }

    // Mailgun (key-)
    if raw_value.starts_with("key-") && raw_value.len() == 36 {
        return verify_http_basic_auth(
            &http_client,
            "https://api.mailgun.net/v3/domains",
            "api",
            raw_value,
        )
        .await;
    }

    // npm (npm_)
    if raw_value.starts_with("npm_") {
        return verify_http_get(
            &http_client,
            "https://registry.npmjs.org/-/npm/v1/user",
            &format!("Bearer {raw_value}"),
            "Authorization",
        )
        .await;
    }

    // DigitalOcean (dop_v1_)
    if raw_value.starts_with("dop_v1_") {
        return verify_http_get(
            &http_client,
            "https://api.digitalocean.com/v2/account",
            &format!("Bearer {raw_value}"),
            "Authorization",
        )
        .await;
    }

    // Anthropic (sk-ant-api03-)
    if raw_value.starts_with("sk-ant-api03-") {
        return verify_http_get(
            &http_client,
            "https://api.anthropic.com/v1/models",
            raw_value,
            "x-api-key",
        )
        .await;
    }

    // New Relic (NRAK-)
    if raw_value.starts_with("NRAK-") {
        return verify_http_get(
            &http_client,
            "https://api.newrelic.com/v2/users.json",
            raw_value,
            "Api-Key",
        )
        .await;
    }

    // Sentry (sntrys_)
    if raw_value.starts_with("sntrys_") {
        return verify_http_get(
            &http_client,
            "https://sentry.io/api/0/organizations/",
            &format!("Bearer {raw_value}"),
            "Authorization",
        )
        .await;
    }

    // Linear (lin_api_)
    if raw_value.starts_with("lin_api_") {
        return verify_http_post_json(
            &http_client,
            "https://api.linear.app/graphql",
            &format!("Bearer {raw_value}"),
            "Authorization",
            r#"{"query":"{ viewer { id } }"}"#,
        )
        .await;
    }

    // Supabase (sbp_)
    if raw_value.starts_with("sbp_") {
        return verify_http_get(
            &http_client,
            "https://api.supabase.com/v1/projects",
            &format!("Bearer {raw_value}"),
            "Authorization",
        )
        .await;
    }

    // JWT — local expiration check (no HTTP)
    if title == "Exposed JWT Token" && raw_value.starts_with("eyJ") {
        return verify_jwt_expiration(raw_value);
    }

    VerificationResult::Unknown
}

/// Generic GET verification: 200 = Valid, 401/403 = Invalid, else Unknown
async fn verify_http_get(
    client: &reqwest::Client,
    url: &str,
    header_value: &str,
    header_name: &str,
) -> VerificationResult {
    let resp = match client
        .get(url)
        .header(header_name, header_value)
        .header("User-Agent", "argos-security-scanner")
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return VerificationResult::Unknown,
    };
    match resp.status().as_u16() {
        200 => VerificationResult::Valid,
        401 | 403 => VerificationResult::Invalid,
        _ => VerificationResult::Unknown,
    }
}

/// Generic GET verification with HTTP Basic auth
async fn verify_http_basic_auth(
    client: &reqwest::Client,
    url: &str,
    username: &str,
    password: &str,
) -> VerificationResult {
    let credentials = base64::engine::general_purpose::STANDARD
        .encode(format!("{username}:{password}"));
    verify_http_get(
        client,
        url,
        &format!("Basic {credentials}"),
        "Authorization",
    )
    .await
}

/// Generic POST verification with JSON body
async fn verify_http_post_json(
    client: &reqwest::Client,
    url: &str,
    header_value: &str,
    header_name: &str,
    json_body: &str,
) -> VerificationResult {
    let resp = match client
        .post(url)
        .header(header_name, header_value)
        .header("User-Agent", "argos-security-scanner")
        .header("Content-Type", "application/json")
        .body(json_body.to_string())
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return VerificationResult::Unknown,
    };
    match resp.status().as_u16() {
        200 => VerificationResult::Valid,
        401 | 403 => VerificationResult::Invalid,
        _ => VerificationResult::Unknown,
    }
}

/// Verify Slack token via auth.test (POST, checks "ok" field in JSON response)
async fn verify_slack_token(client: &reqwest::Client, token: &str) -> VerificationResult {
    let resp = match client
        .post("https://slack.com/api/auth.test")
        .header("Authorization", format!("Bearer {token}"))
        .header("User-Agent", "argos-security-scanner")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return VerificationResult::Unknown,
    };
    let body = match resp.text().await {
        Ok(b) => b,
        Err(_) => return VerificationResult::Unknown,
    };
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
        if json.get("ok") == Some(&serde_json::Value::Bool(true)) {
            return VerificationResult::Valid;
        }
        if json.get("ok") == Some(&serde_json::Value::Bool(false)) {
            return VerificationResult::Invalid;
        }
    }
    VerificationResult::Unknown
}

/// Common weak secrets used for HS256 JWT signing
const WEAK_JWT_SECRETS: &[&str] = &[
    "secret", "password", "123456", "key", "private",
    "default", "changeme", "admin", "test", "jwt_secret",
    "your-256-bit-secret", "shhhhh", "supersecret",
    "my-secret", "mysecret", "s3cr3t", "qwerty",
];

/// Try common weak secrets against a HS256-signed JWT.
/// Returns Some(secret) if a match is found.
fn try_weak_jwt_secrets(token: &str) -> Option<&'static str> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[2])
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(parts[2]))
        .ok()?;

    for &secret in WEAK_JWT_SECRETS {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
        mac.update(signing_input.as_bytes());
        if mac.verify_slice(&signature_bytes).is_ok() {
            return Some(secret);
        }
    }
    None
}

/// Verify JWT by decoding the payload — extracts claims, expiration, algorithm analysis, and weak secret check
fn verify_jwt_expiration(token: &str) -> VerificationResult {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return VerificationResult::Unknown;
    }
    // Decode header to get algorithm
    let header_b64 = parts[0];
    let alg = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_b64)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(header_b64))
        .ok()
        .and_then(|d| std::str::from_utf8(&d).ok().map(|s| s.to_string()))
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|j| j.get("alg").and_then(|v| v.as_str()).map(|s| s.to_string()));

    // JWT payload is base64url-encoded (no padding)
    let payload = parts[1];
    let decoded = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload) {
        Ok(d) => d,
        Err(_) => {
            match base64::engine::general_purpose::STANDARD.decode(payload) {
                Ok(d) => d,
                Err(_) => return VerificationResult::Unknown,
            }
        }
    };
    let json_str = match std::str::from_utf8(&decoded) {
        Ok(s) => s,
        Err(_) => return VerificationResult::Unknown,
    };
    let json = match serde_json::from_str::<serde_json::Value>(json_str) {
        Ok(j) => j,
        Err(_) => return VerificationResult::Unknown,
    };

    // Build details from claims
    let mut details_parts: Vec<String> = Vec::new();
    if let Some(a) = &alg {
        details_parts.push(format!("alg={a}"));
    }
    if let Some(iss) = json.get("iss").and_then(|v| v.as_str()) {
        details_parts.push(format!("iss={iss}"));
    }
    if let Some(aud) = json.get("aud").and_then(|v| v.as_str()) {
        details_parts.push(format!("aud={aud}"));
    }
    if let Some(sub) = json.get("sub") {
        let sub_str = sub.as_str().map(|s| s.to_string())
            .unwrap_or_else(|| sub.to_string());
        details_parts.push(format!("sub={sub_str}"));
    }

    // Algorithm analysis
    if let Some(ref a) = alg {
        match a.to_lowercase().as_str() {
            "none" => {
                details_parts.push("CRITICAL: alg=none authentication bypass".to_string());
                return VerificationResult::JwtDecoded {
                    status: "CRITICAL: alg=none (authentication bypass)".to_string(),
                    details: details_parts.join(", "),
                };
            }
            "hs256" | "hs384" | "hs512" => {
                // Try weak secret brute-force for HS256
                if a.eq_ignore_ascii_case("HS256") {
                    if let Some(weak_secret) = try_weak_jwt_secrets(token) {
                        details_parts.push(format!(
                            "CRITICAL: signed with weak secret '{}'", weak_secret
                        ));
                        return VerificationResult::JwtDecoded {
                            status: format!("CRITICAL: weak secret '{}'", weak_secret),
                            details: details_parts.join(", "),
                        };
                    }
                }
                details_parts.push("alg=HMAC (vulnerable if weak secret)".to_string());
            }
            a if a.starts_with("rs") || a.starts_with("es") || a.starts_with("ps") => {
                details_parts.push(format!("alg={} (asymmetric, safe)", a.to_uppercase()));
            }
            _ => {}
        }
    }

    let now = chrono::Utc::now().timestamp();
    if let Some(exp) = json.get("exp").and_then(|v| v.as_i64()) {
        if exp > now {
            let hours = (exp - now) / 3600;
            let status = format!("ACTIVE (expires in {}h)", hours);
            details_parts.push(status.clone());
            return VerificationResult::JwtDecoded {
                status,
                details: details_parts.join(", "),
            };
        }
        let days = (now - exp) / 86400;
        let status = format!("EXPIRED ({}d ago)", days);
        details_parts.push(status.clone());
        return VerificationResult::JwtDecoded {
            status,
            details: details_parts.join(", "),
        };
    }

    // No exp claim — token doesn't expire
    let status = "NO EXPIRATION".to_string();
    details_parts.push(status.clone());
    VerificationResult::JwtDecoded {
        status,
        details: details_parts.join(", "),
    }
}

// ---------------------------------------------------------------------------
// Source map detection
// ---------------------------------------------------------------------------

/// Check JS source maps for exposed secrets
async fn check_source_maps(
    client: &HttpClient,
    js_urls: &[&str],
    js_bodies: &HashMap<&str, String>,
) -> Vec<(String, SecretMatch)> {
    let mut results = Vec::new();

    for &js_url in js_urls.iter().take(MAX_SOURCE_MAP_FILES) {
        // Strategy 1: try {url}.map directly
        let map_url = format!("{js_url}.map");
        let map_body = fetch_source_map(client, &map_url).await;

        // Strategy 2: look for sourceMappingURL comment in the JS body
        let map_body = if map_body.is_none() {
            if let Some(body) = js_bodies.get(js_url) {
                if let Some(map_ref) = extract_source_mapping_url(body) {
                    let resolved = resolve_map_url(js_url, &map_ref);
                    fetch_source_map(client, &resolved).await
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            map_body
        };

        let map_body = match map_body {
            Some(b) => b,
            None => continue,
        };

        // Parse source map JSON
        let json: serde_json::Value = match serde_json::from_str(&map_body) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let sources = json
            .get("sources")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let sources_content = match json.get("sourcesContent").and_then(|v| v.as_array()) {
            Some(arr) => arr,
            None => continue,
        };

        info!(
            "Secrets: found source map {} with {} source files",
            map_url,
            sources_content.len()
        );

        for (idx, content_val) in sources_content.iter().enumerate() {
            let content = match content_val.as_str() {
                Some(s) if !s.is_empty() => s,
                _ => continue,
            };

            let source_name = sources
                .get(idx)
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            let detections = run_all_detectors(content);
            for matches in detections.values() {
                for secret in matches.iter().take(MAX_PER_CATEGORY_PER_URL) {
                    let mut annotated = secret.clone();
                    annotated.evidence = format!(
                        "{} [source map: {} → {}]",
                        annotated.evidence, map_url, source_name
                    );
                    results.push((js_url.to_string(), annotated));
                }
            }
        }
    }

    results
}

/// Fetch a source map URL; returns None if not found or too large
async fn fetch_source_map(client: &HttpClient, url: &str) -> Option<String> {
    let resp = match client.get(url).await {
        Ok(r) => r,
        Err(_) => return None,
    };
    if !resp.status().is_success() {
        return None;
    }
    // Check content-length if available
    if let Some(len) = resp.content_length() {
        if len as usize > MAX_SOURCE_MAP_SIZE {
            debug!("Secrets: source map too large ({} bytes): {}", len, url);
            return None;
        }
    }
    let body = resp.text().await.unwrap_or_default();
    if body.len() > MAX_SOURCE_MAP_SIZE {
        return None;
    }
    // Must look like a source map (contains sourcesContent)
    if body.contains("\"sourcesContent\"") || body.contains("\"sources\"") {
        Some(body)
    } else {
        None
    }
}

/// Extract sourceMappingURL from a JS body
fn extract_source_mapping_url(js_body: &str) -> Option<String> {
    // Look for //# sourceMappingURL=... or //@ sourceMappingURL=...
    for line in js_body.lines().rev().take(5) {
        let trimmed = line.trim();
        if let Some(rest) = trimmed
            .strip_prefix("//# sourceMappingURL=")
            .or_else(|| trimmed.strip_prefix("//@ sourceMappingURL="))
        {
            let url = rest.trim();
            // Skip data: URIs (inline source maps)
            if url.starts_with("data:") {
                return None;
            }
            if !url.is_empty() {
                return Some(url.to_string());
            }
        }
    }
    None
}

/// Resolve a possibly-relative source map URL against the JS file URL
fn resolve_map_url(js_url: &str, map_ref: &str) -> String {
    // Already absolute
    if map_ref.starts_with("http://") || map_ref.starts_with("https://") {
        return map_ref.to_string();
    }
    // Relative: resolve against the JS URL base
    if let Some(base_end) = js_url.rfind('/') {
        format!("{}/{}", &js_url[..base_end], map_ref)
    } else {
        map_ref.to_string()
    }
}

// ---------------------------------------------------------------------------
// Git exposure deep scan
// ---------------------------------------------------------------------------

/// Scan exposed .git directory for secrets in config and reflog
async fn scan_git_exposure(
    client: &HttpClient,
    base_url: &str,
) -> Vec<(String, SecretMatch)> {
    let mut results = Vec::new();
    let base = base_url.trim_end_matches('/');

    // 1. .git/config — look for tokens embedded in remote URLs
    let config_url = format!("{base}/.git/config");
    if let Ok(resp) = client.get(&config_url).await {
        if resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("[remote") || body.contains("[core]") {
                // Look for credentials in remote URLs: https://user:token@host/repo
                if let Ok(re) = Regex::new(r"https?://[^:]+:([^@\s]{8,})@[^\s]+") {
                    for cap in re.captures_iter(&body) {
                        if let Some(token_match) = cap.get(1) {
                            let token = token_match.as_str();
                            if !is_placeholder(token) && shannon_entropy(token) >= MIN_ENTROPY_GENERIC {
                                results.push((config_url.clone(), SecretMatch {
                                    title: "Git Config: Credentials in Remote URL".to_string(),
                                    description: "The .git/config file is publicly accessible and \
                                        contains credentials embedded in a remote URL. This allows \
                                        access to the source code repository.".to_string(),
                                    severity: Severity::Critical,
                                    confidence: Confidence::Confirmed,
                                    cwe: "CWE-540",
                                    evidence: format!("Token in .git/config remote URL: {}", truncate_secret(token)),
                                    raw_value: Some(token.to_string()),
                                }));
                            }
                        }
                    }
                }

                // Also report .git/config exposure itself if it looks valid
                results.push((config_url.clone(), SecretMatch {
                    title: "Git Configuration File Exposed".to_string(),
                    description: "The .git/config file is publicly accessible. This reveals \
                        repository structure, remote URLs, and potentially credentials.".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::Confirmed,
                    cwe: "CWE-540",
                    evidence: format!(".git/config accessible at {}", config_url),
                    raw_value: None,
                }));
            }
        }
    }

    // 2. .git/logs/HEAD — reflog with commit messages that may contain secrets
    let reflog_url = format!("{base}/.git/logs/HEAD");
    if let Ok(resp) = client.get(&reflog_url).await {
        if resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            // Only scan if it looks like a real reflog and isn't too large
            if body.len() <= MAX_GIT_REFLOG_SIZE
                && (body.contains("commit:") || body.contains("0000000"))
            {
                let detections = run_all_detectors(&body);
                for matches in detections.values() {
                    for secret in matches.iter().take(MAX_PER_CATEGORY_PER_URL) {
                        let mut annotated = secret.clone();
                        annotated.evidence =
                            format!("{} [in .git/logs/HEAD reflog]", annotated.evidence);
                        results.push((reflog_url.clone(), annotated));
                    }
                }
            }
        }
    }

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
        // Always include the target URL, plus crawled URLs up to MAX_URLS
        let mut urls_to_check: Vec<&str> = vec![&config.target];
        for url in crawled_urls.iter().take(MAX_URLS) {
            if url != &config.target {
                urls_to_check.push(url);
            }
        }

        // -- Phase 1: Scan all URLs for secrets --
        let mut all_matches: Vec<(String, SecretMatch)> = Vec::new();
        let mut js_urls: Vec<&str> = Vec::new();
        let mut js_bodies: HashMap<&str, String> = HashMap::new();

        for url in &urls_to_check {
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

            // Track JS files for source map scanning
            if url.ends_with(".js") || url.contains(".js?") {
                js_urls.push(url);
                js_bodies.insert(url, body.clone());
            }

            let detections = run_all_detectors(&body);
            for matches in detections.values() {
                for secret in matches.iter().take(MAX_PER_CATEGORY_PER_URL) {
                    all_matches.push((url.to_string(), secret.clone()));
                }
            }
        }

        // -- Phase 2: Source map scanning --
        let source_map_matches = check_source_maps(client, &js_urls, &js_bodies).await;
        all_matches.extend(source_map_matches);

        // -- Phase 2.5: Git exposure deep scan --
        let git_matches = scan_git_exposure(client, &config.target).await;
        all_matches.extend(git_matches);

        // -- Phase 3: Active verification --
        for (_url, secret) in &mut all_matches {
            let raw = match &secret.raw_value {
                Some(v) => v.clone(),
                None => continue,
            };
            // Skip verification for OAuth-sourced URLs
            if InjectionScanner::is_oauth_url(_url) {
                continue;
            }
            let result = verify_secret(&secret.title, &raw).await;
            match result {
                VerificationResult::Valid => {
                    debug!("Secrets: verified VALID — {}: {}", secret.title, truncate_secret(&raw));
                    secret.confidence = Confidence::Confirmed;
                    secret.evidence = format!("{} [verified: active]", secret.evidence);
                }
                VerificationResult::Invalid => {
                    debug!("Secrets: verified INVALID (rotated) — {}: {}", secret.title, truncate_secret(&raw));
                    // Mark for removal by setting a sentinel title
                    secret.title = String::new();
                }
                VerificationResult::JwtDecoded { status, details } => {
                    debug!("Secrets: JWT decoded — {}", details);
                    if status.starts_with("ACTIVE") {
                        secret.confidence = Confidence::Confirmed;
                    }
                    secret.evidence = format!("{} [{}]", secret.evidence, details);
                }
                VerificationResult::Unknown => {
                    // Keep original confidence
                }
            }
        }

        // Remove invalidated secrets
        all_matches.retain(|(_, secret)| !secret.title.is_empty());

        // -- Phase 4: Create findings with dedup --
        let mut findings = Vec::new();
        let mut seen_secrets: HashSet<String> = HashSet::new();

        for (url, secret) in &all_matches {
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
                    url,
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

        Ok(findings)
    }
}
