//! Core data models for Argos scanner

use crate::http::AuthConfig;
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Severity level for security findings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

impl Severity {
    /// Returns the color name for terminal output
    pub fn color(&self) -> &str {
        match self {
            Severity::Critical => "red",
            Severity::High => "bright red",
            Severity::Medium => "yellow",
            Severity::Low => "blue",
            Severity::Info => "white",
        }
    }

    /// Returns the HTML color code for reports
    pub fn html_color(&self) -> &str {
        match self {
            Severity::Critical => "#dc2626",
            Severity::High => "#ea580c",
            Severity::Medium => "#ca8a04",
            Severity::Low => "#2563eb",
            Severity::Info => "#6b7280",
        }
    }
}

/// Confidence level for a finding
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    /// Vulnerability was actively confirmed (exploit worked, data leaked, etc.)
    Confirmed,
    /// Strong indicators but not directly exploited (fingerprint + vuln endpoint exists)
    Tentative,
    /// Informational detection (technology identified, header missing, etc.)
    Informational,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Confidence::Confirmed => write!(f, "confirmed"),
            Confidence::Tentative => write!(f, "tentative"),
            Confidence::Informational => write!(f, "informational"),
        }
    }
}

/// A security finding discovered during scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier
    pub id: String,
    /// Name of the finding
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Severity level
    pub severity: Severity,
    /// Confidence level
    pub confidence: Confidence,
    /// Category (Headers, SSL, Injection, etc.)
    pub category: String,
    /// Technical evidence
    pub evidence: String,
    /// Remediation recommendation
    pub recommendation: String,
    /// CWE reference (e.g., CWE-79)
    pub cwe_id: Option<String>,
    /// OWASP Top 10 reference
    pub owasp_category: Option<String>,
    /// Affected URL
    pub url: String,
    /// HTTP request that demonstrates the issue
    pub request: Option<String>,
    /// Relevant HTTP response
    pub response: Option<String>,
}

impl Finding {
    /// Creates a new Finding with a generated UUID
    pub fn new(
        title: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
        category: impl Into<String>,
        url: impl Into<String>,
    ) -> Self {
        let cat: String = category.into();
        let confidence = Self::default_confidence(&cat);
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            title: title.into(),
            description: description.into(),
            severity,
            confidence,
            category: cat,
            evidence: String::new(),
            recommendation: String::new(),
            cwe_id: None,
            owasp_category: None,
            url: url.into(),
            request: None,
            response: None,
        }
    }

    /// Sets the confidence level for this finding
    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// Determines default confidence based on category
    fn default_confidence(category: &str) -> Confidence {
        match category {
            "SQL Injection" | "XSS" | "Command Injection" | "SSTI" | "Path Traversal" => {
                Confidence::Confirmed
            }
            "Security Headers" | "SSL/TLS" | "Cookies" | "CORS" | "Information Disclosure"
            | "WAF Detection" | "WebSocket" | "API Security" => Confidence::Informational,
            _ => Confidence::Tentative,
        }
    }

    /// Sets the evidence for this finding
    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = evidence.into();
        self
    }

    /// Sets the recommendation for this finding
    pub fn with_recommendation(mut self, rec: impl Into<String>) -> Self {
        self.recommendation = rec.into();
        self
    }

    /// Sets the CWE ID for this finding
    pub fn with_cwe(mut self, cwe: impl Into<String>) -> Self {
        self.cwe_id = Some(cwe.into());
        self
    }

    /// Sets the OWASP category for this finding
    pub fn with_owasp(mut self, owasp: impl Into<String>) -> Self {
        self.owasp_category = Some(owasp.into());
        self
    }

    /// Sets the request evidence
    pub fn with_request(mut self, request: impl Into<String>) -> Self {
        self.request = Some(request.into());
        self
    }

    /// Sets the response evidence
    pub fn with_response(mut self, response: impl Into<String>) -> Self {
        self.response = Some(response.into());
        self
    }
}

/// Result of a complete scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Target URL
    pub target: String,
    /// Unique scan identifier
    pub scan_id: String,
    /// Scan start time (local timezone)
    pub started_at: DateTime<Local>,
    /// Scan end time (local timezone)
    pub finished_at: Option<DateTime<Local>>,
    /// All findings discovered
    pub findings: Vec<Finding>,
    /// Names of modules that were executed
    pub modules_executed: Vec<String>,
    /// Total HTTP requests made
    pub total_requests: u64,
}

impl ScanResult {
    /// Creates a new ScanResult
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            scan_id: uuid::Uuid::new_v4().to_string(),
            started_at: Local::now(),
            finished_at: None,
            findings: Vec::new(),
            modules_executed: Vec::new(),
            total_requests: 0,
        }
    }

    /// Returns count of findings by severity
    pub fn count_by_severity(&self, severity: &Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| &f.severity == severity)
            .count()
    }

    /// Marks the scan as finished
    pub fn finish(&mut self) {
        self.finished_at = Some(Local::now());
    }
}

/// Configuration for a scan session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Target URL to scan
    pub target: String,
    /// Number of concurrent threads
    pub threads: usize,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// User-Agent header value
    pub user_agent: String,
    /// List of modules to execute
    pub modules: Vec<String>,
    /// Whether to follow HTTP redirects
    pub follow_redirects: bool,
    /// Maximum crawl depth
    pub max_depth: u32,
    /// Path to custom wordlist
    pub wordlist_path: Option<String>,
    /// HTTP/HTTPS proxy URL
    pub proxy: Option<String>,
    /// Custom HTTP headers
    pub headers: HashMap<String, String>,
    /// Maximum requests per second (0 = unlimited)
    pub rate_limit: Option<u32>,
    /// Authentication configuration
    #[serde(skip)]
    pub auth: AuthConfig,
    /// Directory for CVE templates
    pub templates_dir: Option<String>,
    /// Run scanner modules concurrently
    #[serde(default)]
    pub concurrent: bool,
    /// Additional directories for templates
    #[serde(default)]
    pub extra_template_dirs: Vec<String>,
    /// Group templates by path to reduce HTTP requests
    #[serde(default = "default_template_clustering")]
    pub template_clustering: bool,
    /// Enable Out-of-Band testing
    #[serde(default)]
    pub oob_enabled: bool,
    /// OOB callback host (IP or hostname reachable from target)
    #[serde(default)]
    pub oob_host: Option<String>,
    /// OOB HTTP callback port
    #[serde(default = "default_oob_http_port")]
    pub oob_http_port: u16,
    /// OOB DNS listener port
    #[serde(default = "default_oob_dns_port")]
    pub oob_dns_port: u16,
    /// OOB interaction wait timeout in seconds
    #[serde(default = "default_oob_timeout")]
    pub oob_timeout_secs: u64,
    /// Enable JavaScript rendering for SPA crawling
    #[serde(default)]
    pub render_enabled: bool,
    /// Wait time in ms after page load for JS rendering
    #[serde(default = "default_render_wait")]
    pub render_wait_ms: u64,
}

fn default_template_clustering() -> bool {
    true
}

fn default_oob_http_port() -> u16 {
    8888
}

fn default_oob_dns_port() -> u16 {
    5353
}

fn default_oob_timeout() -> u64 {
    10
}

fn default_render_wait() -> u64 {
    3000
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            threads: 10,
            timeout_secs: 30,
            user_agent: "Argos-Scanner/0.1.0".to_string(),
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
                "waf".to_string(),
                "websocket".to_string(),
                "dast".to_string(),
                "graphql".to_string(),
            ],
            follow_redirects: true,
            max_depth: 3,
            wordlist_path: None,
            proxy: None,
            headers: HashMap::new(),
            rate_limit: Some(50),
            auth: AuthConfig::None,
            templates_dir: None,
            concurrent: false,
            extra_template_dirs: Vec::new(),
            template_clustering: true,
            oob_enabled: false,
            oob_host: None,
            oob_http_port: 8888,
            oob_dns_port: 5353,
            oob_timeout_secs: 10,
            render_enabled: false,
            render_wait_ms: 3000,
        }
    }
}
