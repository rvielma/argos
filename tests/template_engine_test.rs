use argos::scanner::templates::cluster::TemplateCluster;
use argos::scanner::templates::engine;
use argos::scanner::templates::loader::{CveTemplate, TemplateExtractor, TemplateMatcher, TemplateRequest};
use argos::scanner::templates::matcher;
use std::collections::HashMap;

// ── Helper builders ──────────────────────────────────────────────────

fn status_matcher(statuses: Vec<u16>) -> TemplateMatcher {
    TemplateMatcher {
        matcher_type: "status".to_string(),
        status: Some(statuses),
        words: None,
        regex: None,
        header: None,
        duration: None,
        variable: None,
        version_range: None,
    }
}

fn body_matcher(words: Vec<&str>) -> TemplateMatcher {
    TemplateMatcher {
        matcher_type: "body".to_string(),
        status: None,
        words: Some(words.into_iter().map(String::from).collect()),
        regex: None,
        header: None,
        duration: None,
        variable: None,
        version_range: None,
    }
}

fn regex_matcher(patterns: Vec<&str>) -> TemplateMatcher {
    TemplateMatcher {
        matcher_type: "regex".to_string(),
        status: None,
        words: None,
        regex: Some(patterns.into_iter().map(String::from).collect()),
        header: None,
        duration: None,
        variable: None,
        version_range: None,
    }
}

fn header_matcher(header: &str, words: Vec<&str>) -> TemplateMatcher {
    TemplateMatcher {
        matcher_type: "header".to_string(),
        status: None,
        words: Some(words.into_iter().map(String::from).collect()),
        regex: None,
        header: Some(header.to_string()),
        duration: None,
        variable: None,
        version_range: None,
    }
}

fn time_matcher(duration: f64) -> TemplateMatcher {
    TemplateMatcher {
        matcher_type: "time".to_string(),
        status: None,
        words: None,
        regex: None,
        header: None,
        duration: Some(duration),
        variable: None,
        version_range: None,
    }
}

fn version_matcher(variable: &str, range: &str) -> TemplateMatcher {
    TemplateMatcher {
        matcher_type: "version".to_string(),
        status: None,
        words: None,
        regex: None,
        header: None,
        duration: None,
        variable: Some(variable.to_string()),
        version_range: Some(range.to_string()),
    }
}

fn simple_template(id: &str, method: &str, path: &str, matchers: Vec<TemplateMatcher>) -> CveTemplate {
    CveTemplate {
        id: id.to_string(),
        name: format!("Test {}", id),
        severity: "medium".to_string(),
        confidence: "tentative".to_string(),
        description: None,
        reference: None,
        requests: vec![TemplateRequest {
            method: method.to_string(),
            path: path.to_string(),
            headers: HashMap::new(),
            body: None,
            matchers,
            condition: "and".to_string(),
            extractors: vec![],
            stop_at_first_match: false,
        }],
        tags: vec![],
        variables: HashMap::new(),
    }
}

fn empty_headers() -> Vec<(String, String)> {
    vec![]
}

// ── Matcher tests ────────────────────────────────────────────────────

#[test]
fn test_status_matcher_match() {
    let m = status_matcher(vec![200, 301]);
    let result = matcher::evaluate_matcher(&m, 200, "", &empty_headers(), 0.0);
    assert!(result.matched, "Status 200 should match [200, 301]");
}

#[test]
fn test_status_matcher_no_match() {
    let m = status_matcher(vec![200]);
    let result = matcher::evaluate_matcher(&m, 404, "", &empty_headers(), 0.0);
    assert!(!result.matched, "Status 404 should not match [200]");
}

#[test]
fn test_body_words_all_match() {
    let m = body_matcher(vec!["admin", "panel"]);
    let body = "Welcome to the admin control panel page";
    let result = matcher::evaluate_matcher(&m, 200, body, &empty_headers(), 0.0);
    assert!(result.matched, "Body containing both 'admin' and 'panel' should match");
}

#[test]
fn test_body_words_partial_match() {
    let m = body_matcher(vec!["admin", "panel"]);
    let body = "Welcome admin user";
    let result = matcher::evaluate_matcher(&m, 200, body, &empty_headers(), 0.0);
    assert!(!result.matched, "Body with only 'admin' should not match when both words required");
}

#[test]
fn test_regex_matcher() {
    let m = regex_matcher(vec![r"version\s+\d+\.\d+"]);
    let body = "Server version 2.4 running";
    let result = matcher::evaluate_matcher(&m, 200, body, &empty_headers(), 0.0);
    assert!(result.matched, "Regex should match 'version 2.4'");
}

#[test]
fn test_regex_no_match() {
    let m = regex_matcher(vec![r"version\s+\d+"]);
    let body = "hello world";
    let result = matcher::evaluate_matcher(&m, 200, body, &empty_headers(), 0.0);
    assert!(!result.matched, "Regex should not match 'hello world'");
}

#[test]
fn test_header_matcher() {
    let m = header_matcher("server", vec!["nginx"]);
    let headers = vec![("server".to_string(), "nginx/1.18.0".to_string())];
    let result = matcher::evaluate_matcher(&m, 200, "", &headers, 0.0);
    assert!(result.matched, "Header 'server' containing 'nginx' should match");
}

#[test]
fn test_header_matcher_no_match() {
    let m = header_matcher("x-custom", vec!["special"]);
    let headers = vec![("server".to_string(), "apache".to_string())];
    let result = matcher::evaluate_matcher(&m, 200, "", &headers, 0.0);
    assert!(!result.matched, "Header 'x-custom' not present should not match");
}

#[test]
fn test_time_matcher() {
    let m = time_matcher(2.0);
    let result = matcher::evaluate_matcher(&m, 200, "", &empty_headers(), 3.0);
    assert!(result.matched, "Response time 3.0s should match duration threshold 2.0s");
}

#[test]
fn test_time_matcher_no_match() {
    let m = time_matcher(5.0);
    let result = matcher::evaluate_matcher(&m, 200, "", &empty_headers(), 1.0);
    assert!(!result.matched, "Response time 1.0s should not match duration threshold 5.0s");
}

#[test]
fn test_matchers_and_condition() {
    let matchers = vec![
        status_matcher(vec![200]),
        body_matcher(vec!["admin"]),
    ];
    let body = "Welcome admin";
    let result = matcher::evaluate_matchers(&matchers, "and", 200, body, &empty_headers(), 0.0);
    assert!(result.matched, "Both matchers match, AND condition should succeed");
}

#[test]
fn test_matchers_and_one_fails() {
    let matchers = vec![
        status_matcher(vec![200]),
        body_matcher(vec!["admin"]),
    ];
    let body = "Welcome user";
    let result = matcher::evaluate_matchers(&matchers, "and", 200, body, &empty_headers(), 0.0);
    assert!(!result.matched, "Body matcher fails, AND condition should fail");
}

#[test]
fn test_matchers_or_condition() {
    let matchers = vec![
        status_matcher(vec![404]),
        body_matcher(vec!["admin"]),
    ];
    let body = "Welcome admin";
    let result = matcher::evaluate_matchers(&matchers, "or", 200, body, &empty_headers(), 0.0);
    assert!(result.matched, "Body matcher matches, OR condition should succeed");
}

#[test]
fn test_version_matcher_less_than() {
    let m = version_matcher("version", "< 2.4.51");
    let mut vars = HashMap::new();
    vars.insert("version".to_string(), "2.4.50".to_string());
    let result = matcher::evaluate_version_matcher(&m, &vars);
    assert!(result.matched, "Version 2.4.50 should be < 2.4.51");
}

#[test]
fn test_version_matcher_outside_range() {
    let m = version_matcher("version", "< 2.4.51");
    let mut vars = HashMap::new();
    vars.insert("version".to_string(), "3.0.0".to_string());
    let result = matcher::evaluate_version_matcher(&m, &vars);
    assert!(!result.matched, "Version 3.0.0 should not be < 2.4.51");
}

#[test]
fn test_version_compound_range() {
    let m = version_matcher("version", ">= 8.0 < 8.5.78");
    let mut vars = HashMap::new();
    vars.insert("version".to_string(), "8.5.50".to_string());
    let result = matcher::evaluate_version_matcher(&m, &vars);
    assert!(result.matched, "Version 8.5.50 should match >= 8.0 < 8.5.78");
}

// ── Cluster tests ────────────────────────────────────────────────────

#[test]
fn test_cluster_groups_get_templates() {
    let templates = vec![
        simple_template("T-001", "GET", "/robots.txt", vec![status_matcher(vec![200])]),
        simple_template("T-002", "GET", "/robots.txt", vec![body_matcher(vec!["Disallow"])]),
        simple_template("T-003", "GET", "/robots.txt", vec![body_matcher(vec!["admin"])]),
    ];
    let cluster = TemplateCluster::from_templates(templates);
    assert_eq!(cluster.clusters.len(), 1, "3 GET templates with same path should form 1 cluster");
    let group = cluster.clusters.values().next().expect("Should have one cluster group");
    assert_eq!(group.len(), 3, "Cluster should contain all 3 templates");
    assert!(cluster.unclustered.is_empty(), "No templates should be unclustered");
}

#[test]
fn test_cluster_separates_post() {
    let templates = vec![
        simple_template("T-001", "GET", "/login", vec![status_matcher(vec![200])]),
        simple_template("T-002", "POST", "/login", vec![status_matcher(vec![200])]),
    ];
    let cluster = TemplateCluster::from_templates(templates);
    assert_eq!(cluster.unclustered.len(), 1, "POST template should be unclustered");
    assert_eq!(cluster.unclustered[0].id, "T-002");
}

#[test]
fn test_cluster_separates_multi_request() {
    let multi_req_template = CveTemplate {
        id: "T-MULTI".to_string(),
        name: "Multi request".to_string(),
        severity: "medium".to_string(),
        confidence: "tentative".to_string(),
        description: None,
        reference: None,
        requests: vec![
            TemplateRequest {
                method: "GET".to_string(),
                path: "/step1".to_string(),
                headers: HashMap::new(),
                body: None,
                matchers: vec![status_matcher(vec![200])],
                condition: "and".to_string(),
                extractors: vec![],
                stop_at_first_match: false,
            },
            TemplateRequest {
                method: "GET".to_string(),
                path: "/step2".to_string(),
                headers: HashMap::new(),
                body: None,
                matchers: vec![status_matcher(vec![200])],
                condition: "and".to_string(),
                extractors: vec![],
                stop_at_first_match: false,
            },
        ],
        tags: vec![],
        variables: HashMap::new(),
    };
    let templates = vec![multi_req_template];
    let cluster = TemplateCluster::from_templates(templates);
    assert!(cluster.clusters.is_empty(), "Multi-request template should not be clustered");
    assert_eq!(cluster.unclustered.len(), 1, "Multi-request template should be unclustered");
}

#[test]
fn test_cluster_separates_extractors() {
    let template_with_extractor = CveTemplate {
        id: "T-EXT".to_string(),
        name: "With extractor".to_string(),
        severity: "medium".to_string(),
        confidence: "tentative".to_string(),
        description: None,
        reference: None,
        requests: vec![TemplateRequest {
            method: "GET".to_string(),
            path: "/version".to_string(),
            headers: HashMap::new(),
            body: None,
            matchers: vec![status_matcher(vec![200])],
            condition: "and".to_string(),
            extractors: vec![TemplateExtractor {
                extractor_type: "regex".to_string(),
                name: "version".to_string(),
                regex: Some(r"(\d+\.\d+)".to_string()),
                group: Some(1),
                header: None,
                json_path: None,
            }],
            stop_at_first_match: false,
        }],
        tags: vec![],
        variables: HashMap::new(),
    };
    let templates = vec![template_with_extractor];
    let cluster = TemplateCluster::from_templates(templates);
    assert!(cluster.clusters.is_empty(), "Template with extractor should not be clustered");
    assert_eq!(cluster.unclustered.len(), 1);
}

// ── Engine tests ─────────────────────────────────────────────────────

#[test]
fn test_evaluate_template_against_response_match() {
    let template = simple_template(
        "CVE-2024-0001",
        "GET",
        "/admin",
        vec![
            status_matcher(vec![200]),
            body_matcher(vec!["admin", "dashboard"]),
        ],
    );
    let headers = vec![("content-type".to_string(), "text/html".to_string())];
    let body = "Welcome to the admin dashboard";
    let findings = engine::evaluate_template_against_response(&template, 200, &headers, body, "https://example.com/admin");
    assert_eq!(findings.len(), 1, "Should produce one finding for matching template");
    assert!(findings[0].title.contains("CVE-2024-0001"));
}

#[test]
fn test_evaluate_template_against_response_no_match() {
    let template = simple_template(
        "CVE-2024-0002",
        "GET",
        "/admin",
        vec![
            status_matcher(vec![200]),
            body_matcher(vec!["secret_token"]),
        ],
    );
    let headers = vec![("content-type".to_string(), "text/html".to_string())];
    let body = "Nothing interesting here";
    let findings = engine::evaluate_template_against_response(&template, 200, &headers, body, "https://example.com/admin");
    assert!(findings.is_empty(), "Should produce no findings for non-matching template");
}
