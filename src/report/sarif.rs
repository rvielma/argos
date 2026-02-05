//! SARIF v2.1.0 report export
//!
//! Generates Static Analysis Results Interchange Format (SARIF) reports
//! compatible with GitHub Code Scanning and other CI/CD tools.

use crate::error::Result;
use crate::models::{ScanResult, Severity};
use serde_json::{json, Value};
use std::path::Path;
use tracing::info;

/// Maps Argos severity to SARIF level
fn severity_to_sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// Maps Argos severity to SARIF security-severity score (CVSS-like 0.0-10.0)
fn severity_to_score(severity: &Severity) -> f64 {
    match severity {
        Severity::Critical => 9.5,
        Severity::High => 7.5,
        Severity::Medium => 5.5,
        Severity::Low => 3.0,
        Severity::Info => 1.0,
    }
}

/// Generates a SARIF rule object from a finding
fn build_rules(result: &ScanResult) -> Vec<Value> {
    let mut rules = Vec::new();
    let mut seen_ids = std::collections::HashSet::new();

    for finding in &result.findings {
        let rule_id = finding
            .cwe_id
            .clone()
            .unwrap_or_else(|| finding.category.replace(' ', "-").to_lowercase());

        if !seen_ids.insert(rule_id.clone()) {
            continue;
        }

        let mut rule = json!({
            "id": rule_id,
            "shortDescription": {
                "text": finding.title.clone()
            },
            "properties": {
                "security-severity": severity_to_score(&finding.severity).to_string(),
                "tags": ["security"]
            }
        });

        if !finding.recommendation.is_empty() {
            rule["help"] = json!({
                "text": finding.recommendation,
                "markdown": finding.recommendation
            });
        }

        if let Some(ref cwe) = finding.cwe_id {
            rule["properties"]["tags"] = json!(["security", cwe]);
        }

        rules.push(rule);
    }

    rules
}

/// Exports scan results in SARIF v2.1.0 format
pub fn export(result: &ScanResult, output_path: &Path) -> Result<()> {
    let rules = build_rules(result);

    let results: Vec<Value> = result
        .findings
        .iter()
        .map(|f| {
            let rule_id = f
                .cwe_id
                .clone()
                .unwrap_or_else(|| f.category.replace(' ', "-").to_lowercase());

            let mut sarif_result = json!({
                "ruleId": rule_id,
                "level": severity_to_sarif_level(&f.severity),
                "message": {
                    "text": f.description
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.url
                        }
                    }
                }],
                "fingerprints": {
                    "argos/v1": f.id
                },
                "properties": {
                    "severity": f.severity.to_string(),
                    "confidence": f.confidence.to_string(),
                    "category": f.category
                }
            });

            if !f.evidence.is_empty() {
                sarif_result["message"]["text"] =
                    json!(format!("{}\n\nEvidence:\n{}", f.description, f.evidence));
            }

            sarif_result
        })
        .collect();

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Argos Panoptes",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/argos-panoptes/argos",
                    "rules": rules
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": true,
                "startTimeUtc": result.started_at.to_rfc3339(),
                "endTimeUtc": result.finished_at.map(|t| t.to_rfc3339()).unwrap_or_default()
            }]
        }]
    });

    let json_str = serde_json::to_string_pretty(&sarif)?;
    std::fs::write(output_path, json_str)?;
    info!("SARIF report saved to {}", output_path.display());
    Ok(())
}
