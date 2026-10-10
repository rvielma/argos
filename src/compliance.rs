//! Compliance mapping: relates a finding's CWE to the controls it touches in
//! common frameworks (HIPAA Security Rule, ISO/IEC 27001:2022 Annex A, PCI DSS
//! v4.0). The mapping is deterministic from the CWE so a report can show which
//! regulatory controls each finding is relevant to.

use serde::{Deserialize, Serialize};

/// A single compliance control a finding is relevant to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComplianceRef {
    /// Framework name, e.g. "HIPAA", "ISO 27001", "PCI DSS".
    pub framework: String,
    /// Control reference and short description.
    pub control: String,
}

fn r(framework: &str, control: &str) -> ComplianceRef {
    ComplianceRef {
        framework: framework.to_string(),
        control: control.to_string(),
    }
}

/// Returns the compliance controls relevant to a finding given its CWE.
///
/// Findings without a recognized CWE get a general secure-development mapping
/// rather than nothing, since every finding is still relevant to risk
/// management and secure configuration.
pub fn controls_for(cwe: Option<&str>) -> Vec<ComplianceRef> {
    let id = cwe
        .map(|c| c.trim_start_matches("CWE-").trim_start_matches("cwe-"))
        .unwrap_or("");

    match id {
        // Injection, XSS, SSTI, RCE, traversal, open redirect, CRLF (integrity / secure coding)
        "89" | "78" | "77" | "94" | "95" | "1336" | "79" | "22" | "98" | "601" | "93" | "113" => {
            vec![
                r("HIPAA", "§164.312(c)(1) Integrity"),
                r("ISO 27001", "A.8.28 Secure coding"),
                r("ISO 27001", "A.8.26 Application security requirements"),
                r(
                    "PCI DSS",
                    "Req 6.2.4 / 6.3 Address injection & software vulns",
                ),
                r("OWASP", "A03:2021 Injection"),
            ]
        }
        // Weak transport / cryptography / cert validation (transmission security)
        "319" | "326" | "327" | "295" => vec![
            r("HIPAA", "§164.312(e)(1) Transmission security"),
            r("ISO 27001", "A.8.24 Use of cryptography"),
            r("PCI DSS", "Req 4.2 Encrypt transmission of data"),
            r("OWASP", "A02:2021 Cryptographic Failures"),
        ],
        // Credentials, secrets, auth, CSRF (access control / authentication)
        "798" | "522" | "312" | "287" | "352" | "384" => vec![
            r("HIPAA", "§164.312(d) Person or entity authentication"),
            r("HIPAA", "§164.312(a)(1) Access control"),
            r("ISO 27001", "A.8.5 Secure authentication"),
            r("PCI DSS", "Req 8 Identify & authenticate access"),
            r("OWASP", "A07:2021 Identification & Auth Failures"),
        ],
        // Information disclosure / sensitive data exposure
        "200" | "209" | "538" => vec![
            r("HIPAA", "§164.312(a)(1) Access control"),
            r("HIPAA", "§164.308(a)(1) Security management process"),
            r("ISO 27001", "A.8.9 Configuration management"),
            r("PCI DSS", "Req 6.3 Identify & address vulnerabilities"),
            r("OWASP", "A01:2021 Broken Access Control"),
        ],
        // Cookie / session security flags
        "614" | "1004" | "1275" => vec![
            r("HIPAA", "§164.312(a)(1) Access control"),
            r("ISO 27001", "A.8.5 Secure authentication"),
            r("PCI DSS", "Req 6.2 Secure software development"),
            r("OWASP", "A05:2021 Security Misconfiguration"),
        ],
        // CORS and other misconfigurations
        "942" | "16" | "693" => vec![
            r("HIPAA", "§164.312(a)(1) Access control"),
            r("ISO 27001", "A.8.9 Configuration management"),
            r("PCI DSS", "Req 6.3 Identify & address vulnerabilities"),
            r("OWASP", "A05:2021 Security Misconfiguration"),
        ],
        // General mapping for anything without a recognized CWE
        _ => vec![
            r(
                "HIPAA",
                "§164.308(a)(1) Security management & risk analysis",
            ),
            r("ISO 27001", "A.8.26 Application security requirements"),
            r("PCI DSS", "Req 6.3 Identify & address vulnerabilities"),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injection_maps_to_integrity_and_secure_coding() {
        let refs = controls_for(Some("CWE-89"));
        assert!(refs.iter().any(|c| c.framework == "HIPAA"));
        assert!(refs
            .iter()
            .any(|c| c.framework == "ISO 27001" && c.control.contains("Secure coding")));
    }

    #[test]
    fn crypto_maps_to_transmission_security() {
        let refs = controls_for(Some("319"));
        assert!(refs
            .iter()
            .any(|c| c.control.contains("Transmission security")));
    }

    #[test]
    fn unknown_cwe_still_maps_to_general_controls() {
        let refs = controls_for(None);
        assert!(!refs.is_empty());
        assert!(refs.iter().any(|c| c.framework == "HIPAA"));
    }
}
