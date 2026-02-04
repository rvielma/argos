//! Session management security checks
//!
//! Verifies session cookie entropy, predictability, and fixation vulnerabilities.

use crate::http::HttpClient;
use crate::models::{Confidence, Finding, Severity};
use tracing::debug;

/// Common session cookie names
const SESSION_COOKIE_NAMES: &[&str] = &[
    "session",
    "sessionid",
    "session_id",
    "sid",
    "phpsessid",
    "jsessionid",
    "asp.net_sessionid",
    "aspsessionid",
    "connect.sid",
    "_session",
    "token",
    "auth_token",
];

/// Checks session management security
pub async fn check_session(client: &HttpClient, target: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Make 3 requests to collect session cookies
    let mut session_values: Vec<String> = Vec::new();

    for i in 0..3 {
        match client.get(target).await {
            Ok(response) => {
                for cookie_header in response.headers().get_all("set-cookie") {
                    if let Ok(cookie_str) = cookie_header.to_str() {
                        let lower = cookie_str.to_lowercase();
                        for &name in SESSION_COOKIE_NAMES {
                            if lower.starts_with(&format!("{}=", name)) {
                                if let Some(value) = extract_cookie_value(cookie_str) {
                                    session_values.push(value);
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                debug!("Session check request {} failed: {}", i, e);
            }
        }
    }

    if session_values.is_empty() {
        debug!("No session cookies found");
        return findings;
    }

    // Check entropy (length)
    for value in &session_values {
        if value.len() < 16 {
            let finding = Finding::new(
                "Weak Session ID Entropy",
                format!(
                    "Session cookie value has only {} characters. \
                     Short session IDs are easier to brute-force.",
                    value.len()
                ),
                Severity::Medium,
                "Session Management",
                target,
            )
            .with_confidence(Confidence::Confirmed)
            .with_evidence(format!(
                "Session ID length: {} (recommended minimum: 16)",
                value.len()
            ))
            .with_recommendation(
                "Use session IDs with at least 128 bits of entropy (32+ hex characters). \
                 Use a cryptographically secure random number generator.",
            )
            .with_cwe("CWE-331")
            .with_owasp("A07:2021 Identification and Authentication Failures");

            findings.push(finding);
            break;
        }
    }

    // Check predictability (compare similarity between session IDs)
    if session_values.len() >= 2 {
        let similar = check_predictability(&session_values);
        if similar {
            let finding = Finding::new(
                "Predictable Session IDs",
                "Multiple session IDs show high similarity, suggesting they may be \
                 predictable or sequentially generated.",
                Severity::High,
                "Session Management",
                target,
            )
            .with_confidence(Confidence::Tentative)
            .with_evidence(format!(
                "Session IDs collected: {:?}",
                session_values.iter().take(3).collect::<Vec<_>>()
            ))
            .with_recommendation(
                "Use a cryptographically secure random number generator for session IDs. \
                 Avoid sequential or time-based generation patterns.",
            )
            .with_cwe("CWE-330")
            .with_owasp("A07:2021 Identification and Authentication Failures");

            findings.push(finding);
        }
    }

    // Session fixation check: send a pre-defined session ID and see if accepted
    let fixation = check_session_fixation(client, target).await;
    if fixation {
        let finding = Finding::new(
            "Session Fixation",
            "The server accepts externally provided session IDs, allowing an attacker \
             to set a victim's session ID before authentication.",
            Severity::High,
            "Session Management",
            target,
        )
        .with_confidence(Confidence::Confirmed)
        .with_evidence("Server accepted a pre-set session ID without regeneration")
        .with_recommendation(
            "Regenerate the session ID after authentication. Never accept \
             session IDs provided by the client before login.",
        )
        .with_cwe("CWE-384")
        .with_owasp("A07:2021 Identification and Authentication Failures");

        findings.push(finding);
    }

    findings
}

/// Extracts the value from a Set-Cookie header
fn extract_cookie_value(cookie_str: &str) -> Option<String> {
    let parts: Vec<&str> = cookie_str.splitn(2, '=').collect();
    if parts.len() != 2 {
        return None;
    }
    let value_parts: Vec<&str> = parts[1].splitn(2, ';').collect();
    let value = value_parts[0].trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Checks if session IDs show predictable patterns
fn check_predictability(values: &[String]) -> bool {
    if values.len() < 2 {
        return false;
    }

    // Compare common prefix length between consecutive IDs
    for i in 0..values.len() - 1 {
        let a = &values[i];
        let b = &values[i + 1];

        let common_prefix = a
            .chars()
            .zip(b.chars())
            .take_while(|(ca, cb)| ca == cb)
            .count();

        let min_len = a.len().min(b.len());
        if min_len > 0 && common_prefix as f64 / min_len as f64 > 0.8 {
            return true;
        }
    }

    false
}

/// Checks for session fixation vulnerability
async fn check_session_fixation(client: &HttpClient, target: &str) -> bool {
    let fixed_session = "argos_fixation_test_session_12345";

    for &name in &["PHPSESSID", "JSESSIONID", "session_id", "sid"] {
        let headers = vec![(
            "Cookie".to_string(),
            format!("{}={}", name, fixed_session),
        )];

        match client.get_with_headers(target, &headers).await {
            Ok(response) => {
                // Check if the response sets a NEW session cookie (regeneration = good)
                let mut regenerated = false;
                for cookie_header in response.headers().get_all("set-cookie") {
                    if let Ok(cookie_str) = cookie_header.to_str() {
                        let lower = cookie_str.to_lowercase();
                        if lower.starts_with(&format!("{}=", name.to_lowercase())) {
                            if let Some(value) = extract_cookie_value(cookie_str) {
                                if value != fixed_session {
                                    regenerated = true;
                                }
                            }
                        }
                    }
                }

                // If no new session cookie was set, the server accepted the fixed one
                if !regenerated {
                    // Verify by checking a second request with the same fixed session
                    if let Ok(r2) = client.get_with_headers(target, &headers).await {
                        if r2.status().as_u16() == 200 {
                            debug!("Session fixation: server accepted fixed {} cookie", name);
                            return true;
                        }
                    }
                }
            }
            Err(_) => continue,
        }
    }

    false
}
