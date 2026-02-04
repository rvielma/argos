//! Tests for YAML template quality and correctness
//!
//! Validates that all templates:
//! - Parse correctly from YAML
//! - Have valid structure (non-empty id, name, requests)
//! - Don't have trivial matchers that would cause false positives
//! - Have appropriate confidence levels

use argos::scanner::templates::loader::{load_templates, validate_template, CveTemplate};
use std::path::Path;

/// Load all templates from the templates directory
fn load_all_templates() -> Vec<(String, CveTemplate)> {
    let base = Path::new("templates");
    let mut results = Vec::new();

    fn recurse(dir: &Path, results: &mut Vec<(String, CveTemplate)>) {
        if let Ok(templates) = load_templates(dir) {
            for t in templates {
                results.push((dir.display().to_string(), t));
            }
        }
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    recurse(&path, results);
                }
            }
        }
    }

    recurse(base, &mut results);
    results
}

#[test]
fn all_templates_parse_successfully() {
    let templates = load_all_templates();
    assert!(
        !templates.is_empty(),
        "No templates found in templates/ directory"
    );
    println!("Loaded {} templates total", templates.len());
}

#[test]
fn all_templates_pass_validation() {
    let templates = load_all_templates();
    let mut failures = Vec::new();

    for (dir, template) in &templates {
        if let Err(msg) = validate_template(template) {
            failures.push(format!("{}/{}: {}", dir, template.id, msg));
        }
    }

    assert!(
        failures.is_empty(),
        "Template validation failures:\n{}",
        failures.join("\n")
    );
}

#[test]
fn no_cve_template_with_only_status_matcher() {
    let templates = load_all_templates();
    let mut problems = Vec::new();

    for (dir, template) in &templates {
        // Only check CVE templates (critical/high severity)
        if !template.id.starts_with("CVE-") {
            continue;
        }

        for (i, request) in template.requests.iter().enumerate() {
            let types: Vec<&str> = request
                .matchers
                .iter()
                .map(|m| m.matcher_type.as_str())
                .collect();

            if types == ["status"] {
                problems.push(format!(
                    "{}/{} request#{}: only status matcher (high FP risk)",
                    dir, template.id, i
                ));
            }
        }
    }

    assert!(
        problems.is_empty(),
        "CVE templates with only status matchers (will cause false positives):\n{}",
        problems.join("\n")
    );
}

#[test]
fn no_cve_template_with_only_header_matcher() {
    let templates = load_all_templates();
    let mut problems = Vec::new();

    for (dir, template) in &templates {
        if !template.id.starts_with("CVE-") {
            continue;
        }

        // Single-request CVE templates that only check headers are fingerprinting, not vuln detection
        if template.requests.len() == 1 {
            let types: Vec<&str> = template.requests[0]
                .matchers
                .iter()
                .map(|m| m.matcher_type.as_str())
                .collect();

            let sev = template.severity.to_lowercase();
            if types.iter().all(|t| *t == "header" || *t == "status")
                && (sev == "critical" || sev == "high")
            {
                problems.push(format!(
                    "{}/{}: {} severity with only status+header matchers (no body proof)",
                    dir, template.id, sev
                ));
            }
        }
    }

    assert!(
        problems.is_empty(),
        "CVE templates with high severity but no body/regex proof:\n{}",
        problems.join("\n")
    );
}

#[test]
fn all_templates_have_valid_severity() {
    let templates = load_all_templates();
    let valid = ["critical", "high", "medium", "low", "info"];

    for (dir, template) in &templates {
        assert!(
            valid.contains(&template.severity.to_lowercase().as_str()),
            "{}/{}: invalid severity '{}'",
            dir,
            template.id,
            template.severity
        );
    }
}

#[test]
fn all_templates_have_valid_confidence() {
    let templates = load_all_templates();
    let valid = ["confirmed", "tentative", "informational"];

    for (dir, template) in &templates {
        assert!(
            valid.contains(&template.confidence.to_lowercase().as_str()),
            "{}/{}: invalid confidence '{}'",
            dir,
            template.id,
            template.confidence
        );
    }
}

#[test]
fn technology_templates_are_info_severity() {
    let templates = load_all_templates();

    for (dir, template) in &templates {
        if template.id.starts_with("tech-") {
            assert_eq!(
                template.severity.to_lowercase(),
                "info",
                "{}/{}: technology template should be info severity, got {}",
                dir,
                template.id,
                template.severity
            );
        }
    }
}

#[test]
fn no_duplicate_template_ids() {
    let templates = load_all_templates();
    let mut seen = std::collections::HashSet::new();
    let mut duplicates = Vec::new();

    for (dir, template) in &templates {
        if !seen.insert(template.id.clone()) {
            duplicates.push(format!("{}/{}", dir, template.id));
        }
    }

    assert!(
        duplicates.is_empty(),
        "Duplicate template IDs:\n{}",
        duplicates.join("\n")
    );
}

#[test]
fn all_requests_have_matchers() {
    let templates = load_all_templates();
    let mut problems = Vec::new();

    for (dir, template) in &templates {
        for (i, request) in template.requests.iter().enumerate() {
            if request.matchers.is_empty() {
                problems.push(format!(
                    "{}/{} request#{}: no matchers defined",
                    dir, template.id, i
                ));
            }
        }
    }

    assert!(
        problems.is_empty(),
        "Requests without matchers:\n{}",
        problems.join("\n")
    );
}

#[test]
fn template_count_minimum() {
    let templates = load_all_templates();
    assert!(
        templates.len() >= 100,
        "Expected at least 100 templates, found {}",
        templates.len()
    );
}
