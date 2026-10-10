use argos::models::ScanResult;
use argos::report::html::{generate_with_meta, ReportMeta};
use std::path::PathBuf;

fn tmp_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("argos_test_{}_{}.html", std::process::id(), name));
    p
}

#[test]
fn report_includes_scope_methodology_and_disclaimer() {
    let mut result = ScanResult::new("https://target.example.com");
    result.modules_executed = vec!["headers".into(), "ssl".into()];
    result.finished_at = Some(result.started_at);

    let meta = ReportMeta {
        client: Some("ACME Health".into()),
        assessor: Some("Red Team".into()),
        test_type: Some("Automated grey-box".into()),
        authorization: Some("Ticket SEC-2026-014".into()),
        scope_note: Some("Public endpoints only.".into()),
    };

    let out = tmp_path("scope");
    generate_with_meta(&result, &out, "en", &meta).expect("report generation failed");
    let html = std::fs::read_to_string(&out).expect("report not written");
    let _ = std::fs::remove_file(&out);

    // Formal ethical-hacking sections must be present.
    assert!(html.contains("Scope &amp; Authorization"));
    assert!(html.contains("Methodology"));
    assert!(html.contains("Disclaimer &amp; Limitations"));
    assert!(html.contains("Confidentiality Notice"));
    // Engagement metadata must be rendered.
    assert!(html.contains("ACME Health"));
    assert!(html.contains("Ticket SEC-2026-014"));
    assert!(html.contains("Public endpoints only."));
}

#[test]
fn report_without_meta_falls_back_to_not_specified() {
    let mut result = ScanResult::new("https://target.example.com");
    result.finished_at = Some(result.started_at);

    let out = tmp_path("nometa");
    generate_with_meta(&result, &out, "en", &ReportMeta::default())
        .expect("report generation failed");
    let html = std::fs::read_to_string(&out).expect("report not written");
    let _ = std::fs::remove_file(&out);

    // Section still renders, with unset fields marked as not specified.
    assert!(html.contains("Scope &amp; Authorization"));
    assert!(html.contains("Not specified"));
}
