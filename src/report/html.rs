//! HTML report generation using Tera templates

use crate::error::Result;
use crate::models::{ScanResult, Severity};
use std::path::Path;
use tera::{Context, Tera};
use tracing::info;

/// Generates an HTML report from scan results
pub fn generate(result: &ScanResult, output_path: &Path) -> Result<()> {
    let template_path = "templates/report.html";
    let template_content =
        std::fs::read_to_string(template_path).unwrap_or_else(|_| default_template().to_string());

    let mut tera = Tera::default();
    tera.add_raw_template("report.html", &template_content)?;

    let mut context = Context::new();
    context.insert("target", &result.target);
    context.insert("scan_id", &result.scan_id);
    context.insert("started_at", &result.started_at.to_rfc3339());
    context.insert(
        "finished_at",
        &result
            .finished_at
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| "N/A".to_string()),
    );
    context.insert("findings", &result.findings);
    context.insert("total_requests", &result.total_requests);
    context.insert("modules_executed", &result.modules_executed);
    context.insert(
        "critical_count",
        &result.count_by_severity(&Severity::Critical),
    );
    context.insert("high_count", &result.count_by_severity(&Severity::High));
    context.insert("medium_count", &result.count_by_severity(&Severity::Medium));
    context.insert("low_count", &result.count_by_severity(&Severity::Low));
    context.insert("info_count", &result.count_by_severity(&Severity::Info));
    context.insert("total_findings", &result.findings.len());
    context.insert("version", env!("CARGO_PKG_VERSION"));

    let rendered = tera.render("report.html", &context)?;
    std::fs::write(output_path, rendered)?;
    info!("HTML report saved to {}", output_path.display());
    Ok(())
}

fn default_template() -> &'static str {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Argos Panoptes - Security Report</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f1f5f9; color: #1e293b; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #334155 100%); color: white; padding: 40px 30px; border-radius: 12px; margin-bottom: 30px; text-align: center; }
        .header h1 { font-size: 2.2em; margin-bottom: 5px; letter-spacing: 2px; }
        .header .subtitle { opacity: 0.8; font-size: 1.1em; }
        .header .meta { opacity: 0.6; margin-top: 15px; font-size: 0.9em; }
        .summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 30px; }
        @media (max-width: 768px) { .summary { grid-template-columns: repeat(2, 1fr); } }
        .card { background: white; padding: 25px 15px; border-radius: 10px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-top: 4px solid #e2e8f0; }
        .card .count { font-size: 2.5em; font-weight: 800; }
        .card .label { font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; margin-top: 5px; opacity: 0.7; }
        .card.critical { border-top-color: #dc2626; } .card.critical .count { color: #dc2626; }
        .card.high { border-top-color: #ea580c; } .card.high .count { color: #ea580c; }
        .card.medium { border-top-color: #ca8a04; } .card.medium .count { color: #ca8a04; }
        .card.low { border-top-color: #2563eb; } .card.low .count { color: #2563eb; }
        .card.info { border-top-color: #6b7280; } .card.info .count { color: #6b7280; }
        .section-title { font-size: 1.4em; font-weight: 700; margin: 30px 0 15px; padding-bottom: 10px; border-bottom: 2px solid #e2e8f0; }
        .finding { background: white; padding: 25px; border-radius: 10px; margin-bottom: 15px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-left: 4px solid #e2e8f0; }
        .finding.sev-Critical { border-left-color: #dc2626; }
        .finding.sev-High { border-left-color: #ea580c; }
        .finding.sev-Medium { border-left-color: #ca8a04; }
        .finding.sev-Low { border-left-color: #2563eb; }
        .finding.sev-Info { border-left-color: #6b7280; }
        .finding h3 { margin-bottom: 10px; font-size: 1.1em; }
        .badge { display: inline-block; padding: 2px 10px; border-radius: 20px; color: white; font-size: 0.75em; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; vertical-align: middle; margin-right: 8px; }
        .badge-Critical { background: #dc2626; }
        .badge-High { background: #ea580c; }
        .badge-Medium { background: #ca8a04; }
        .badge-Low { background: #2563eb; }
        .badge-Info { background: #6b7280; }
        .finding p { margin: 8px 0; color: #475569; }
        .finding .label { font-weight: 600; color: #1e293b; }
        pre { background: #f8fafc; border: 1px solid #e2e8f0; padding: 15px; border-radius: 6px; overflow-x: auto; font-size: 0.85em; margin: 8px 0; white-space: pre-wrap; word-wrap: break-word; }
        .meta-info { display: flex; flex-wrap: wrap; gap: 15px; margin-top: 12px; padding-top: 12px; border-top: 1px solid #f1f5f9; font-size: 0.85em; color: #64748b; }
        .footer { text-align: center; padding: 30px; color: #94a3b8; font-size: 0.85em; margin-top: 30px; }
        .info-bar { background: white; padding: 15px 25px; border-radius: 10px; margin-bottom: 20px; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); font-size: 0.9em; color: #64748b; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>&#128305; ARGOS PANOPTES</h1>
            <div class="subtitle">Web Security Scan Report</div>
            <div class="meta">Target: {{ target }} | Scan ID: {{ scan_id }}</div>
        </div>
        <div class="info-bar">
            <span><strong>Started:</strong> {{ started_at }}</span>
            <span><strong>Finished:</strong> {{ finished_at }}</span>
            <span><strong>Requests:</strong> {{ total_requests }}</span>
            <span><strong>Modules:</strong> {{ modules_executed | join(sep=", ") }}</span>
        </div>
        <div class="summary">
            <div class="card critical"><div class="count">{{ critical_count }}</div><div class="label">Critical</div></div>
            <div class="card high"><div class="count">{{ high_count }}</div><div class="label">High</div></div>
            <div class="card medium"><div class="count">{{ medium_count }}</div><div class="label">Medium</div></div>
            <div class="card low"><div class="count">{{ low_count }}</div><div class="label">Low</div></div>
            <div class="card info"><div class="count">{{ info_count }}</div><div class="label">Info</div></div>
        </div>
        <div class="section-title">Findings ({{ total_findings }})</div>
        {% for finding in findings %}
        <div class="finding sev-{{ finding.severity }}">
            <h3><span class="badge badge-{{ finding.severity }}">{{ finding.severity }}</span>{{ finding.title }}</h3>
            <p>{{ finding.description }}</p>
            {% if finding.evidence %}<p><span class="label">Evidence:</span></p><pre>{{ finding.evidence }}</pre>{% endif %}
            {% if finding.recommendation %}<p><span class="label">Recommendation:</span> {{ finding.recommendation }}</p>{% endif %}
            <div class="meta-info">
                {% if finding.cwe_id %}<span>{{ finding.cwe_id }}</span>{% endif %}
                {% if finding.owasp_category %}<span>{{ finding.owasp_category }}</span>{% endif %}
                <span>{{ finding.url }}</span>
            </div>
        </div>
        {% endfor %}
        {% if total_findings == 0 %}
        <div class="finding"><h3>No findings detected</h3><p>The scan completed without identifying security issues.</p></div>
        {% endif %}
        <div class="footer">Generated by Argos Panoptes v{{ version }} | {{ started_at }}</div>
    </div>
</body>
</html>"#
}
