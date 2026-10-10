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
    /// CVSS v3.1 base score (0.0-10.0), computed from `cvss_vector`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f64>,
    /// CVSS v3.1 base vector string the score was computed from
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss_vector: Option<String>,
    /// Compliance controls this finding is relevant to (HIPAA/ISO/PCI)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compliance: Vec<crate::compliance::ComplianceRef>,
    /// Suggested reproduction steps for this finding
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repro_steps: Vec<String>,
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
            cvss_score: None,
            cvss_vector: None,
            compliance: Vec::new(),
            repro_steps: Vec::new(),
            url: url.into(),
            request: None,
            response: None,
        }
    }

    /// Sets the CVSS v3.1 vector and computes the base score from it.
    /// Invalid vectors leave the score unset.
    pub fn with_cvss(mut self, vector: impl Into<String>) -> Self {
        let vector = vector.into();
        self.cvss_score = crate::cvss::base_score(&vector);
        self.cvss_vector = Some(vector);
        self
    }

    /// Fills in a representative CVSS vector/score derived from the finding's
    /// CWE (when known) or severity, but only if one was not already set.
    pub fn ensure_cvss(&mut self) {
        if self.cvss_vector.is_some() {
            return;
        }
        let vector = crate::cvss::representative_vector(self.cwe_id.as_deref(), &self.severity);
        self.cvss_score = crate::cvss::base_score(vector);
        self.cvss_vector = Some(vector.to_string());
    }

    /// Enriches the finding with CVSS, compliance mapping and reproduction steps.
    /// Idempotent: existing values are preserved.
    pub fn enrich(&mut self) {
        self.ensure_cvss();
        if self.compliance.is_empty() {
            self.compliance = crate::compliance::controls_for(self.cwe_id.as_deref());
        }
        if self.repro_steps.is_empty() {
            self.repro_steps = self.build_repro_steps();
        }
    }

    /// Builds category-aware reproduction steps from the finding's data.
    fn build_repro_steps(&self) -> Vec<String> {
        let mut steps = vec![format!(
            "Establish a benign baseline request to {} and record the normal response.",
            self.url
        )];

        let has_request = self.request.is_some();
        let cat = self.category.as_str();
        match cat {
            "SQL Injection" => {
                steps.push("Resend the request injecting the SQL payload shown in the Evidence into the affected parameter.".into());
                steps.push("Confirm injection: an SQL error, or a reproducible boolean/time difference versus the baseline, is observed.".into());
            }
            "XSS" => {
                steps.push("Inject the XSS payload from the Evidence into the affected parameter and load the response.".into());
                steps.push("Confirm the payload is reflected unencoded and executes in the browser (DOM or reflected context).".into());
            }
            "Command Injection" | "SSTI" => {
                steps.push(
                    "Inject the payload from the Evidence into the affected parameter.".into(),
                );
                steps.push("Confirm server-side evaluation in the response (e.g., command output or template arithmetic result).".into());
            }
            "Path Traversal" => {
                steps.push("Request the traversal path shown in the Evidence.".into());
                steps.push("Confirm the contents of an out-of-webroot file are returned.".into());
            }
            "Open Redirect" => {
                steps.push("Set the affected redirect parameter to an external, attacker-controlled domain and send the request.".into());
                steps.push("Confirm a 3xx redirect to that external domain is issued.".into());
            }
            "Security Headers" => {
                steps.push(format!(
                    "Inspect the HTTP response headers for {}.",
                    self.url
                ));
                steps.push(
                    "Confirm the security header named in the finding is missing or misconfigured."
                        .into(),
                );
            }
            "SSL/TLS" => {
                steps.push(
                    "Inspect the TLS configuration (e.g., `openssl s_client -connect host:443`)."
                        .into(),
                );
                steps.push("Confirm the weak protocol, cipher or certificate issue described in the Evidence.".into());
            }
            "Cookies" => {
                steps.push("Inspect the Set-Cookie response headers.".into());
                steps.push(
                    "Confirm the missing Secure/HttpOnly/SameSite attribute noted in the finding."
                        .into(),
                );
            }
            "CORS" => {
                steps.push(
                    "Send a request with an Origin header set to an untrusted domain.".into(),
                );
                steps.push("Confirm the response reflects that origin in Access-Control-Allow-Origin (with credentials where applicable).".into());
            }
            "Information Disclosure" => {
                steps.push("Inspect the response body and headers.".into());
                steps.push(
                    "Confirm the disclosed information described in the Evidence is present."
                        .into(),
                );
            }
            _ => {
                if has_request {
                    steps.push(
                        "Replay the request shown in the Request section against the target."
                            .into(),
                    );
                }
                steps.push(
                    "Confirm the condition described in the finding and Evidence is met.".into(),
                );
            }
        }
        steps
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
            "Security Headers"
            | "SSL/TLS"
            | "Cookies"
            | "CORS"
            | "Information Disclosure"
            | "WAF Detection"
            | "WebSocket"
            | "API Security" => Confidence::Informational,
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
    /// Differential report (when --baseline is used)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<DiffReport>,
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
            diff: None,
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

/// Differential report comparing current scan against a baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    /// Findings present in current scan but not in baseline
    pub new_findings: Vec<Finding>,
    /// Findings present in baseline but not in current scan (fixed)
    pub resolved_findings: Vec<Finding>,
    /// Findings present in both scans
    pub persisting_findings: Vec<Finding>,
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
    /// OOB SMTP listener port
    #[serde(default = "default_oob_smtp_port")]
    pub oob_smtp_port: u16,
    /// OOB FTP listener port
    #[serde(default = "default_oob_ftp_port")]
    pub oob_ftp_port: u16,
    /// OOB interaction wait timeout in seconds
    #[serde(default = "default_oob_timeout")]
    pub oob_timeout_secs: u64,
    /// Enable JavaScript rendering for SPA crawling
    #[serde(default)]
    pub render_enabled: bool,
    /// Wait time in ms after page load for JS rendering
    #[serde(default = "default_render_wait")]
    pub render_wait_ms: u64,
    /// Directory for Nuclei-compatible templates
    #[serde(default)]
    pub nuclei_templates_dir: Option<String>,
    /// Maximum number of URLs to crawl
    #[serde(default = "default_max_urls")]
    pub max_urls: usize,
    /// Include subdomains in crawl scope
    #[serde(default)]
    pub include_subdomains: bool,
    /// Pre-collected forms from crawler (not serialized)
    #[serde(skip)]
    pub crawled_forms: Vec<crate::crawler::extractor::FormInfo>,
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

fn default_oob_smtp_port() -> u16 {
    2525
}

fn default_oob_ftp_port() -> u16 {
    2121
}

fn default_oob_timeout() -> u64 {
    10
}

fn default_render_wait() -> u64 {
    3000
}

fn default_max_urls() -> usize {
    500
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
                "secrets".to_string(),
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
            oob_smtp_port: 2525,
            oob_ftp_port: 2121,
            oob_timeout_secs: 10,
            render_enabled: false,
            render_wait_ms: 3000,
            nuclei_templates_dir: None,
            max_urls: 500,
            include_subdomains: false,
            crawled_forms: Vec::new(),
        }
    }
}
