//! CVSS v3.1 base-score calculator.
//!
//! Scores are computed from a CVSS vector string (CVSS:3.1/AV:.../...), never
//! guessed, so every number in a report is auditable from its vector. Implements
//! the Base metric group per the official CVSS v3.1 specification.

use crate::models::Severity;

/// Computes the CVSS v3.1 base score from a vector string.
///
/// Returns `None` if the vector is missing required base metrics or has invalid
/// values. The returned score is in the range 0.0..=10.0, rounded up to one
/// decimal place as the specification requires.
pub fn base_score(vector: &str) -> Option<f64> {
    let mut av = None; // Attack Vector
    let mut ac = None; // Attack Complexity
    let mut pr = None; // Privileges Required (raw char, resolved with scope)
    let mut ui = None; // User Interaction
    let mut scope_changed = None;
    let mut c = None; // Confidentiality
    let mut i = None; // Integrity
    let mut a = None; // Availability

    for part in vector.split('/') {
        let (key, val) = match part.split_once(':') {
            Some(kv) => kv,
            None => continue, // skips the "CVSS:3.1" prefix token
        };
        match key {
            "AV" => {
                av = Some(match val {
                    "N" => 0.85,
                    "A" => 0.62,
                    "L" => 0.55,
                    "P" => 0.2,
                    _ => return None,
                })
            }
            "AC" => {
                ac = Some(match val {
                    "L" => 0.77,
                    "H" => 0.44,
                    _ => return None,
                })
            }
            "PR" => {
                pr = Some(match val {
                    "N" | "L" | "H" => val.to_string(),
                    _ => return None,
                })
            }
            "UI" => {
                ui = Some(match val {
                    "N" => 0.85,
                    "R" => 0.62,
                    _ => return None,
                })
            }
            "S" => {
                scope_changed = Some(match val {
                    "U" => false,
                    "C" => true,
                    _ => return None,
                })
            }
            "C" => c = Some(impact_metric(val)?),
            "I" => i = Some(impact_metric(val)?),
            "A" => a = Some(impact_metric(val)?),
            _ => {} // ignore temporal/environmental metrics
        }
    }

    let av = av?;
    let ac = ac?;
    let pr_raw = pr?;
    let ui = ui?;
    let scope_changed = scope_changed?;
    let c = c?;
    let i = i?;
    let a = a?;

    // Privileges Required weight depends on Scope.
    let pr = match (pr_raw.as_str(), scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };

    let iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };

    if impact <= 0.0 {
        return Some(0.0);
    }

    let exploitability = 8.22 * av * ac * pr * ui;
    let raw = if scope_changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };

    Some(roundup(raw))
}

fn impact_metric(val: &str) -> Option<f64> {
    match val {
        "H" => Some(0.56),
        "L" => Some(0.22),
        "N" => Some(0.0),
        _ => None,
    }
}

/// CVSS v3.1 roundup: the smallest number to one decimal place that is >= input.
fn roundup(input: f64) -> f64 {
    let int_input = (input * 100_000.0).round() as i64;
    if int_input % 10_000 == 0 {
        int_input as f64 / 100_000.0
    } else {
        ((int_input as f64 / 10_000.0).floor() + 1.0) / 10.0
    }
}

/// Qualitative rating for a CVSS v3.1 base score.
pub fn rating(score: f64) -> &'static str {
    if score == 0.0 {
        "None"
    } else if score < 4.0 {
        "Low"
    } else if score < 7.0 {
        "Medium"
    } else if score < 9.0 {
        "High"
    } else {
        "Critical"
    }
}

/// Returns a representative CVSS v3.1 base vector for a finding, chosen from its
/// CWE when known and otherwise from its qualitative severity. The score is then
/// computed from this vector, so the report shows exactly how it was derived.
pub fn representative_vector(cwe: Option<&str>, severity: &Severity) -> &'static str {
    if let Some(cwe) = cwe {
        // Normalize "CWE-89" / "89" to the numeric id.
        let id = cwe.trim_start_matches("CWE-").trim_start_matches("cwe-");
        match id {
            // SQL injection
            "89" => return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            // OS command injection / code injection / SSTI (RCE)
            "78" | "77" | "94" | "95" | "1336" => {
                return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            }
            // Reflected/DOM XSS
            "79" => return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            // Path traversal / LFI
            "22" | "98" => return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            // Open redirect
            "601" => return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            // CRLF / HTTP response splitting
            "93" | "113" => return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            // CSRF
            "352" => return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
            // CORS misconfiguration
            "942" => return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            // Information disclosure / sensitive data exposure
            "200" | "209" | "538" => return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            // Hard-coded / exposed credentials and secrets
            "798" | "522" | "312" => return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            // Weak transport / crypto (requires MitM -> high complexity)
            "319" | "326" | "327" | "295" => return "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
            // Missing cookie security flags
            "614" | "1004" | "1275" => return "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
            _ => {}
        }
    }

    // Fallback: representative vector per qualitative severity.
    match severity {
        Severity::Critical => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        Severity::High => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        Severity::Medium => "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        Severity::Low => "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        Severity::Info => "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors_match_spec() {
        // Canonical examples with their documented v3.1 base scores.
        assert_eq!(
            base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Some(9.8)
        );
        assert_eq!(
            base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
            Some(7.5)
        );
        assert_eq!(
            base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
            Some(6.1)
        );
        // Scope-changed example: FIRST.org calculator yields 9.1 for this vector.
        assert_eq!(
            base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:L"),
            Some(9.1)
        );
    }

    #[test]
    fn invalid_or_incomplete_vectors_return_none() {
        assert_eq!(base_score("not a vector"), None);
        assert_eq!(base_score("CVSS:3.1/AV:N/AC:L"), None); // missing metrics
        assert_eq!(
            base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            None
        );
    }

    #[test]
    fn ratings_follow_bands() {
        assert_eq!(rating(0.0), "None");
        assert_eq!(rating(3.9), "Low");
        assert_eq!(rating(4.0), "Medium");
        assert_eq!(rating(7.0), "High");
        assert_eq!(rating(9.8), "Critical");
    }

    #[test]
    fn representative_vectors_are_computable() {
        // Every representative vector must produce a valid score.
        for cwe in [
            "CWE-89", "CWE-79", "CWE-22", "CWE-200", "CWE-319", "CWE-614",
        ] {
            let v = representative_vector(Some(cwe), &Severity::Medium);
            assert!(base_score(v).is_some(), "vector not computable: {v}");
        }
        for sev in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            let v = representative_vector(None, &sev);
            assert!(base_score(v).is_some(), "vector not computable: {v}");
        }
    }
}
