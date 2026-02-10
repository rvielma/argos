//! XSS detection (reflected, DOM-based, attribute injection)

use crate::http::HttpClient;
use crate::models::{Finding, Severity};
use regex::Regex;
use std::collections::HashMap;
use tracing::debug;

use super::BaselineResponse;
use super::InjectionPoint;
use super::InjectionScanner;

/// Scans for Cross-Site Scripting vulnerabilities
pub async fn scan(
    client: &HttpClient,
    points: &[InjectionPoint],
    crawled_urls: &[String],
    baselines: &HashMap<(String, String), BaselineResponse>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let payloads = InjectionScanner::load_payloads(
        "wordlists/payloads/xss.txt",
        vec![
            "<script>alert(1)</script>".to_string(),
            "'\"><img src=x onerror=alert(1)>".to_string(),
            "<svg onload=alert(1)>".to_string(),
            "javascript:alert(1)".to_string(),
            "'-alert(1)-'".to_string(),
        ],
    );

    // Reflected XSS
    for point in points.iter().take(10) {
        for param in &point.params {
            let baseline = baselines.get(&(point.url.clone(), param.clone()));

            'xss: for payload in payloads.iter().take(5) {
                if let Some(test_url) = InjectionScanner::build_test_url(&point.url, param, payload)
                {
                    if let Ok(resp) = client.get(&test_url).await {
                        let resp_body = resp.text().await.unwrap_or_default();
                        if resp_body.contains(payload.as_str()) {
                            // Verify the payload doesn't already exist in the baseline
                            let in_baseline = baseline
                                .map(|bl| bl.body.contains(payload.as_str()))
                                .unwrap_or(false);

                            if in_baseline {
                                continue;
                            }

                            findings.push(
                                Finding::new(
                                    format!("Reflected XSS in '{param}'"),
                                    format!(
                                        "Parameter '{param}' reflects input without sanitization."
                                    ),
                                    Severity::High,
                                    "Injection",
                                    &point.url,
                                )
                                .with_evidence(format!("Param: {param}\nPayload: {payload}"))
                                .with_request(format!("GET {test_url}"))
                                .with_recommendation(
                                    "Implement output encoding and Content-Security-Policy headers.",
                                )
                                .with_cwe("CWE-79")
                                .with_owasp("A03:2021 Injection"),
                            );
                            break 'xss;
                        }
                    }
                }
            }

            // Attribute injection check — use a unique marker to avoid matching
            // existing page content that naturally contains "onfocus" or "autofocus"
            let marker = "argosxsstest";
            let attr_payload = format!("\" onfocus=\"{marker}\" autofocus=\"");
            if let Some(test_url) =
                InjectionScanner::build_test_url(&point.url, param, &attr_payload)
            {
                if let Ok(resp) = client.get(&test_url).await {
                    let resp_body = resp.text().await.unwrap_or_default();
                    // Check for the EXACT unique marker within an event handler context
                    let marker_in_attr = format!("onfocus=\"{marker}\"");
                    if resp_body.contains(&marker_in_attr) {
                        findings.push(
                            Finding::new(
                                format!("XSS via Attribute Injection in '{param}'"),
                                format!("Parameter '{param}' allows HTML attribute injection."),
                                Severity::High,
                                "Injection",
                                &point.url,
                            )
                            .with_evidence(format!("Param: {param}\nPayload: {attr_payload}"))
                            .with_request(format!("GET {test_url}"))
                            .with_recommendation(
                                "Encode all user input in HTML attributes. Use CSP headers.",
                            )
                            .with_cwe("CWE-79")
                            .with_owasp("A03:2021 Injection"),
                        );
                    }
                }
            }
        }
    }

    // DOM-based XSS detection (analyze JS for dangerous sinks)
    // Skip known libraries — their internal use of innerHTML/eval is not a real vulnerability
    let known_libraries: &[&str] = &[
        "jquery", "angular", "react", "vue", "bootstrap", "lodash",
        "moment", "backbone", "ember", "mootools", "prototype",
        "dojo", "ext-all", "yui", "d3.", "chart.", "highcharts",
        "popper", "select2", "datatables", "sweetalert", "toastr",
        "handlebars", "mustache", "underscore", "zepto", "modernizr",
        "vendor.", "vendors.", "vendor-", "vendors-",
        "chunk-vendors", "bundle.",
    ];

    let dom_sinks: &[(&str, &str)] = &[
        (r"\.innerHTML\s*=", "innerHTML assignment"),
        (r"\beval\s*\(", "eval() usage"),
        (r"document\.write\s*\(", "document.write() usage"),
        (r"document\.writeln\s*\(", "document.writeln() usage"),
        (r"\.outerHTML\s*=", "outerHTML assignment"),
        (
            r#"setTimeout\s*\(\s*["']"#,
            "setTimeout with string argument",
        ),
        (
            r#"setInterval\s*\(\s*["']"#,
            "setInterval with string argument",
        ),
    ];

    let urls_to_check: Vec<&str> = if crawled_urls.is_empty() {
        vec![]
    } else {
        crawled_urls.iter().map(|s| s.as_str()).take(30).collect()
    };

    for &url in &urls_to_check {
        // Skip known JS libraries — their internal DOM manipulation is safe
        let url_lower = url.to_lowercase();
        let is_library = known_libraries
            .iter()
            .any(|lib| url_lower.contains(lib));
        if is_library {
            debug!("Skipping DOM XSS check for known library: {url}");
            continue;
        }

        if let Ok(resp) = client.get(url).await {
            let body = resp.text().await.unwrap_or_default();

            for (pattern, sink_name) in dom_sinks {
                if let Ok(re) = Regex::new(pattern) {
                    if let Some(m) = re.find(&body) {
                        let context_start = m.start().saturating_sub(40);
                        let context_end = (m.end() + 40).min(body.len());
                        let context = &body[context_start..context_end];

                        // Check if user-controlled sources feed into this sink
                        let has_source = body.contains("location.hash")
                            || body.contains("location.search")
                            || body.contains("document.URL")
                            || body.contains("document.referrer")
                            || body.contains("window.name");

                        if has_source {
                            findings.push(
                                Finding::new(
                                    format!("Potential DOM-Based XSS: {sink_name}"),
                                    format!(
                                        "JavaScript uses dangerous sink ({sink_name}) with user-controlled sources."
                                    ),
                                    Severity::Medium,
                                    "Injection",
                                    url,
                                )
                                .with_evidence(format!(
                                    "Sink: {sink_name}\nContext: ...{context}..."
                                ))
                                .with_recommendation(
                                    "Avoid using dangerous DOM sinks with user-controlled data. Use textContent instead of innerHTML.",
                                )
                                .with_cwe("CWE-79")
                                .with_owasp("A03:2021 Injection"),
                            );
                            break;
                        } else {
                            debug!("Found sink {sink_name} at {url} but no user-controlled source");
                        }
                    }
                }
            }
        }
    }

    findings
}
