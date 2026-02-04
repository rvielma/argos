//! CSRF (Cross-Site Request Forgery) detection

use crate::http::HttpClient;
use crate::models::{Confidence, Finding, Severity};
use scraper::{Html, Selector};
use tracing::debug;

/// Known CSRF token field names
const CSRF_FIELD_NAMES: &[&str] = &[
    "csrf",
    "csrf_token",
    "_csrf",
    "_token",
    "csrfmiddlewaretoken",
    "authenticity_token",
    "nonce",
    "__requestverificationtoken",
    "antiforgerytoken",
    "x-csrf-token",
    "xsrf",
    "_xsrf",
];

/// Extracted form data (Send-safe, no references to scraper DOM)
struct FormData {
    method: String,
    action: String,
    form_url: String,
    has_csrf_token: bool,
    /// Non-CSRF field names and values for enforcement testing
    fields: Vec<(String, String)>,
}

/// Checks a page for CSRF vulnerabilities
pub async fn check_csrf(client: &HttpClient, url: &str, html: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Extract form data synchronously (no await while holding ElementRef)
    let forms = extract_forms(url, html);

    for form in forms {
        if !form.has_csrf_token {
            let finding = Finding::new(
                "Missing CSRF Token",
                format!(
                    "POST form at {} does not contain a CSRF protection token. \
                     This may allow cross-site request forgery attacks.",
                    form.form_url
                ),
                Severity::Medium,
                "CSRF",
                &form.form_url,
            )
            .with_confidence(Confidence::Tentative)
            .with_evidence(format!(
                "Form method={} action={} has no CSRF token field",
                form.method, form.action
            ))
            .with_recommendation(
                "Add a CSRF token to all state-changing forms. Use framework-provided \
                 CSRF protection (e.g., Django csrf_token, Rails authenticity_token).",
            )
            .with_cwe("CWE-352")
            .with_owasp("A01:2021 Broken Access Control");

            findings.push(finding);
        } else {
            // Has token — try submitting without it to see if server validates
            let validated = check_csrf_enforcement(client, &form).await;
            if !validated {
                let finding = Finding::new(
                    "CSRF Token Not Enforced",
                    format!(
                        "The form at {} has a CSRF token field but the server accepts \
                         submissions without it, making the protection ineffective.",
                        form.form_url
                    ),
                    Severity::High,
                    "CSRF",
                    &form.form_url,
                )
                .with_confidence(Confidence::Confirmed)
                .with_evidence("Form submitted successfully without CSRF token")
                .with_recommendation(
                    "Ensure the server validates the CSRF token on every state-changing request. \
                     Reject requests with missing or invalid tokens.",
                )
                .with_cwe("CWE-352")
                .with_owasp("A01:2021 Broken Access Control");

                findings.push(finding);
            }
        }
    }

    findings
}

/// Extracts form data from HTML (synchronous, no async)
fn extract_forms(base_url: &str, html: &str) -> Vec<FormData> {
    let document = Html::parse_document(html);
    let mut forms = Vec::new();

    let form_selector = match Selector::parse("form") {
        Ok(s) => s,
        Err(_) => return forms,
    };

    for form in document.select(&form_selector) {
        let method = form
            .value()
            .attr("method")
            .unwrap_or("get")
            .to_lowercase();

        // Only check POST/PUT/DELETE forms
        if method != "post" && method != "put" && method != "delete" {
            continue;
        }

        let action = form.value().attr("action").unwrap_or("").to_string();
        let form_url = if action.is_empty() || action == "#" {
            base_url.to_string()
        } else if action.starts_with("http") {
            action.clone()
        } else {
            format!(
                "{}/{}",
                base_url.trim_end_matches('/'),
                action.trim_start_matches('/')
            )
        };

        let mut has_csrf_token = false;
        let mut fields = Vec::new();

        if let Ok(input_sel) = Selector::parse("input") {
            for input in form.select(&input_sel) {
                if let Some(name) = input.value().attr("name") {
                    let lower = name.to_lowercase();
                    let is_csrf =
                        CSRF_FIELD_NAMES.iter().any(|&csrf_name| lower.contains(csrf_name));

                    if is_csrf {
                        // Check hidden inputs for CSRF tokens
                        let input_type = input
                            .value()
                            .attr("type")
                            .unwrap_or("")
                            .to_lowercase();
                        if input_type == "hidden" {
                            has_csrf_token = true;
                        }
                    } else {
                        let value = input.value().attr("value").unwrap_or("test").to_string();
                        fields.push((name.to_string(), value));
                    }
                }
            }
        }

        forms.push(FormData {
            method,
            action,
            form_url,
            has_csrf_token,
            fields,
        });
    }

    forms
}

/// Tries to submit a form without the CSRF token to check if server enforces it
async fn check_csrf_enforcement(client: &HttpClient, form: &FormData) -> bool {
    let body: String = form
        .fields
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&");

    match client.post(&form.form_url, &body).await {
        Ok(response) => {
            let status = response.status().as_u16();
            // If the server returns 200 or 302 (redirect), it likely accepted the request
            // 403/419/422 would indicate the token is being validated
            if status == 200 || status == 302 || status == 301 {
                debug!(
                    "CSRF not enforced at {}: status {}",
                    form.form_url, status
                );
                return false; // Not enforced
            }
            true // Token is enforced (4xx response)
        }
        Err(_) => true, // Can't determine, assume enforced
    }
}
