//! HTML report generation using Tera templates

use crate::error::Result;
use crate::models::{Finding, ScanResult, Severity};
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;
use tera::{Context, Tera};
use tracing::info;

/// An attack scenario generated from findings
#[derive(Serialize, Clone)]
struct AttackScenario {
    title: String,
    description: String,
    impact: String,
    likelihood: String,
    severity_class: String,
}

/// A remediation step generated from findings
#[derive(Serialize, Clone)]
struct RemediationStep {
    priority: String,
    finding: String,
    action: String,
    effort: String,
    severity_class: String,
}

/// Generates attack scenarios from findings based on CWE patterns
fn generate_attack_scenarios(findings: &[Finding]) -> Vec<AttackScenario> {
    let mut scenarios = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Collect CWEs present
    let cwes: Vec<String> = findings
        .iter()
        .filter_map(|f| f.cwe_id.as_ref())
        .cloned()
        .collect();

    // CWE-319: Missing HSTS / Cleartext transmission
    if cwes.iter().any(|c| c == "CWE-319") && !seen.contains("mitm") {
        seen.insert("mitm");
        scenarios.push(AttackScenario {
            title: "Man-in-the-Middle Attack (Network Interception)".into(),
            description: "Without HSTS, the first connection from a user's browser can be intercepted. An attacker on the same network (WiFi, corporate LAN) can use tools like sslstrip to downgrade HTTPS to HTTP, capturing credentials and session tokens in plaintext.".into(),
            impact: "Complete credential theft. Attacker gains authenticated access to the application with the victim's permissions. All data transmitted during the session is exposed.".into(),
            likelihood: "Medium — Requires network proximity (same WiFi, ARP spoofing). Common in shared networks.".into(),
            severity_class: "High".into(),
        });
    }

    // CWE-1021: Missing X-Frame-Options (Clickjacking)
    if cwes.iter().any(|c| c == "CWE-1021") && !seen.contains("clickjacking") {
        seen.insert("clickjacking");
        scenarios.push(AttackScenario {
            title: "Clickjacking (UI Redress Attack)".into(),
            description: "The application can be embedded in an invisible iframe on an attacker-controlled page. Users interact with what they think is a legitimate site, but their clicks are actually performed on the embedded application — submitting forms, changing settings, or authorizing actions.".into(),
            impact: "Unauthorized actions performed under the victim's session. Credential harvesting through overlaid login forms.".into(),
            likelihood: "Medium — Requires social engineering to lure victims to the attacker's page.".into(),
            severity_class: "Medium".into(),
        });
    }

    // CWE-693: Missing CSP
    if cwes.iter().any(|c| c == "CWE-693") && !seen.contains("xss-csp") {
        seen.insert("xss-csp");
        scenarios.push(AttackScenario {
            title: "Cross-Site Scripting Amplification (No CSP)".into(),
            description: "Without Content-Security-Policy, any XSS vulnerability becomes significantly more dangerous. Injected scripts can load external resources, exfiltrate data to attacker-controlled servers, keylog input fields, and hijack sessions without any browser restriction.".into(),
            impact: "If an XSS vector is found (stored or reflected), the attacker has unrestricted script execution. Data exfiltration, session hijacking, and full account takeover become trivial.".into(),
            likelihood: "Low-Medium — Requires an XSS vector, but the lack of CSP removes all mitigation.".into(),
            severity_class: "Medium".into(),
        });
    }

    // CWE-352: CSRF
    if cwes.iter().any(|c| c == "CWE-352") && !seen.contains("csrf") {
        seen.insert("csrf");
        scenarios.push(AttackScenario {
            title: "Cross-Site Request Forgery (Unauthorized Actions)".into(),
            description: "Forms without CSRF protection allow an attacker to craft a malicious page that automatically submits requests on behalf of an authenticated user. Visiting the attacker's page while logged in triggers actions the user never intended.".into(),
            impact: "Unauthorized state changes: password resets, data modifications, privilege escalation. Login CSRF can force authentication with attacker-controlled credentials for session monitoring.".into(),
            likelihood: "Medium — Requires victim to visit attacker's page while authenticated.".into(),
            severity_class: "Medium".into(),
        });
    }

    // CWE-89: SQL Injection
    if cwes.iter().any(|c| c == "CWE-89") && !seen.contains("sqli") {
        seen.insert("sqli");
        scenarios.push(AttackScenario {
            title: "Database Compromise via SQL Injection".into(),
            description: "SQL injection allows an attacker to execute arbitrary database queries. This can bypass authentication, extract entire database contents, modify or delete records, and in some cases execute operating system commands on the database server.".into(),
            impact: "Complete database compromise. Mass data exfiltration (user records, credentials, business data). Data manipulation or destruction. Potential lateral movement to internal systems.".into(),
            likelihood: "High — Automated tools can exploit SQL injection with minimal effort.".into(),
            severity_class: "Critical".into(),
        });
    }

    // CWE-79: XSS
    if cwes.iter().any(|c| c == "CWE-79") && !seen.contains("xss") {
        seen.insert("xss");
        scenarios.push(AttackScenario {
            title: "Account Takeover via Cross-Site Scripting".into(),
            description: "Reflected or stored XSS allows an attacker to execute JavaScript in the context of other users' sessions. This enables session cookie theft, keylogging of credentials, defacement, and redirection to phishing pages.".into(),
            impact: "Session hijacking and account takeover. Stored XSS affects every user who views the infected page. Credential theft through fake login forms injected into the page.".into(),
            likelihood: "High — Reflected XSS requires a crafted link; Stored XSS affects all visitors automatically.".into(),
            severity_class: "High".into(),
        });
    }

    // CWE-1336: SSTI
    if cwes.iter().any(|c| c == "CWE-1336") && !seen.contains("ssti") {
        seen.insert("ssti");
        scenarios.push(AttackScenario {
            title: "Remote Code Execution via Template Injection".into(),
            description: "Server-Side Template Injection allows an attacker to inject template expressions that are evaluated on the server. Depending on the template engine, this can escalate from information disclosure to full remote code execution on the server.".into(),
            impact: "Remote code execution on the server. Full system compromise. Access to internal databases, file systems, and network resources. Data exfiltration at scale.".into(),
            likelihood: "High — Once identified, SSTI exploitation is well-documented for all major template engines.".into(),
            severity_class: "Critical".into(),
        });
    }

    // CWE-78: Command Injection
    if cwes.iter().any(|c| c == "CWE-78") && !seen.contains("cmdi") {
        seen.insert("cmdi");
        scenarios.push(AttackScenario {
            title: "Server Compromise via OS Command Injection".into(),
            description: "Command injection allows an attacker to execute arbitrary operating system commands on the server. This provides direct access to the underlying system, bypassing all application-level controls.".into(),
            impact: "Complete server compromise. File system access, credential harvesting, lateral movement to other systems, installation of backdoors or malware.".into(),
            likelihood: "High — Exploitation is straightforward once the injection point is identified.".into(),
            severity_class: "Critical".into(),
        });
    }

    // CWE-200: Information Disclosure (server version)
    if cwes.iter().any(|c| c == "CWE-200") && !seen.contains("info-disc") {
        seen.insert("info-disc");
        scenarios.push(AttackScenario {
            title: "Targeted Exploitation via Information Disclosure".into(),
            description: "Server version headers and technology fingerprints allow attackers to identify exact software versions running on the server. This enables targeted searches for known CVEs and public exploits specific to the detected versions.".into(),
            impact: "Reduces attacker effort significantly. Instead of blind testing, the attacker can use known exploits for the specific version detected.".into(),
            likelihood: "High — Automated scanners routinely collect this information. This is often the first step in a targeted attack.".into(),
            severity_class: "Low".into(),
        });
    }

    // Combined scenarios: Missing HSTS + CSRF = session attack chain
    if cwes.iter().any(|c| c == "CWE-319") && cwes.iter().any(|c| c == "CWE-352") && !seen.contains("chain-session") {
        seen.insert("chain-session");
        scenarios.push(AttackScenario {
            title: "Attack Chain: Network Interception + CSRF".into(),
            description: "The combination of missing HSTS and CSRF vulnerabilities creates an attack chain. An attacker on the network intercepts the initial HTTP connection (no HSTS), injects a CSRF payload into the response, and the victim's browser executes unauthorized actions with their authenticated session.".into(),
            impact: "Combined impact: credential theft AND unauthorized actions. The attacker both steals the session and uses it to perform actions the victim never intended.".into(),
            likelihood: "Medium — Requires network proximity but the chain is well-established.".into(),
            severity_class: "High".into(),
        });
    }

    // Sort by severity
    scenarios.sort_by(|a, b| {
        let ord = |s: &str| match s { "Critical" => 0, "High" => 1, "Medium" => 2, _ => 3 };
        ord(&a.severity_class).cmp(&ord(&b.severity_class))
    });

    scenarios
}

/// Generates a prioritized remediation plan from findings
fn generate_remediation_plan(findings: &[Finding]) -> Vec<RemediationStep> {
    let mut steps = Vec::new();
    let mut seen_cwes = std::collections::HashSet::new();

    // Sort findings by severity first
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by(|a, b| a.severity.cmp(&b.severity));

    for f in &sorted {
        let cwe = f.cwe_id.as_deref().unwrap_or("");
        if cwe.is_empty() || seen_cwes.contains(cwe) {
            continue;
        }
        seen_cwes.insert(cwe.to_string());

        let (priority, action, effort) = match cwe {
            "CWE-89" => ("P0 — Blocker", "Use parameterized queries/prepared statements. Review all database queries for string concatenation with user input.", "Medium"),
            "CWE-79" => ("P0 — Blocker", "Implement context-aware output encoding. Deploy Content-Security-Policy header to restrict script execution.", "Medium"),
            "CWE-1336" => ("P0 — Blocker", "Never pass user input to template engines. Use sandboxed/logic-less templates. Validate and sanitize all dynamic content.", "Medium"),
            "CWE-78" => ("P0 — Blocker", "Eliminate OS command construction from user input. Use language-native APIs instead of shell commands.", "Medium"),
            "CWE-319" => ("P1 — Pre-launch", "Add Strict-Transport-Security header: max-age=31536000; includeSubDomains. Configure HTTPS redirect at load balancer/proxy level.", "Low"),
            "CWE-1021" => ("P1 — Pre-launch", "Add X-Frame-Options: DENY header. Also add frame-ancestors 'none' in CSP for defense in depth.", "Low"),
            "CWE-352" => ("P1 — Pre-launch", "Implement anti-CSRF tokens in all state-changing forms. Use SameSite=Strict or Lax on session cookies.", "Medium"),
            "CWE-693" => ("P2 — Next sprint", "Deploy Content-Security-Policy, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy headers.", "Low"),
            "CWE-200" => ("P2 — Next sprint", "Remove or obfuscate Server header. Disable version disclosure in application server configuration.", "Low"),
            "CWE-93" => ("P1 — Pre-launch", "Strip CRLF characters (\\r\\n) from all user input reflected in HTTP headers.", "Low"),
            _ => ("P3 — Backlog", &*f.recommendation, "Varies"),
        };

        let sev_class = format!("{:?}", f.severity);

        steps.push(RemediationStep {
            priority: priority.into(),
            finding: f.title.clone(),
            action: action.into(),
            effort: effort.into(),
            severity_class: sev_class,
        });
    }

    steps
}

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

    // Executive summary: risk score
    let critical = result.count_by_severity(&Severity::Critical);
    let high = result.count_by_severity(&Severity::High);
    let medium = result.count_by_severity(&Severity::Medium);
    let low = result.count_by_severity(&Severity::Low);
    let info_count = result.count_by_severity(&Severity::Info);
    let risk_score = critical * 10 + high * 5 + medium * 2 + low;
    context.insert("risk_score", &risk_score);

    let risk_level = if critical > 0 {
        "Critical"
    } else if high > 0 {
        "High"
    } else if medium > 0 {
        "Medium"
    } else if low > 0 {
        "Low"
    } else {
        "None"
    };
    context.insert("risk_level", risk_level);

    // Severity distribution for chart bars
    let total = result.findings.len().max(1);
    context.insert("critical_pct", &((critical * 100) / total));
    context.insert("high_pct", &((high * 100) / total));
    context.insert("medium_pct", &((medium * 100) / total));
    context.insert("low_pct", &((low * 100) / total));
    context.insert("info_pct", &((info_count * 100) / total));

    // Findings grouped by category
    let mut by_category: HashMap<String, Vec<&crate::models::Finding>> = HashMap::new();
    for f in &result.findings {
        by_category.entry(f.category.clone()).or_default().push(f);
    }
    let mut categories: Vec<(String, usize)> = by_category
        .iter()
        .map(|(k, v)| (k.clone(), v.len()))
        .collect();
    categories.sort_by(|a, b| b.1.cmp(&a.1));
    context.insert("categories", &categories);

    // Scan duration
    if let Some(finished) = result.finished_at {
        let duration = finished.signed_duration_since(result.started_at);
        let secs = duration.num_seconds();
        let duration_str = if secs >= 60 {
            format!("{}m {}s", secs / 60, secs % 60)
        } else {
            format!("{secs}s")
        };
        context.insert("duration", &duration_str);
    } else {
        context.insert("duration", "N/A");
    }

    // Attack scenarios & remediation plan
    let scenarios = generate_attack_scenarios(&result.findings);
    let remediation = generate_remediation_plan(&result.findings);
    context.insert("attack_scenarios", &scenarios);
    context.insert("has_scenarios", &!scenarios.is_empty());
    context.insert("remediation_plan", &remediation);
    context.insert("has_remediation", &!remediation.is_empty());

    // Diff report
    let has_diff = result.diff.is_some();
    context.insert("has_diff", &has_diff);
    if let Some(ref diff) = result.diff {
        context.insert("new_findings", &diff.new_findings);
        context.insert("resolved_findings", &diff.resolved_findings);
        context.insert("persisting_findings", &diff.persisting_findings);
        context.insert("new_count", &diff.new_findings.len());
        context.insert("resolved_count", &diff.resolved_findings.len());
        context.insert("persisting_count", &diff.persisting_findings.len());
    }

    let rendered = tera.render("report.html", &context)?;
    std::fs::write(output_path, rendered)?;
    info!("HTML report saved to {}", output_path.display());
    Ok(())
}

fn default_template() -> &'static str {
    r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Argos Panoptes - Security Report</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f1f5f9; color: #1e293b; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }

        /* Header */
        .header { background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #334155 100%); color: white; padding: 40px 30px; border-radius: 12px; margin-bottom: 24px; text-align: center; }
        .header h1 { font-size: 2.2em; margin-bottom: 5px; letter-spacing: 2px; }
        .header .subtitle { opacity: 0.8; font-size: 1.1em; }
        .header .meta { opacity: 0.6; margin-top: 15px; font-size: 0.9em; }

        /* Info bar */
        .info-bar { background: white; padding: 15px 25px; border-radius: 10px; margin-bottom: 20px; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); font-size: 0.9em; color: #64748b; }

        /* Executive Summary */
        .exec-summary { background: white; padding: 25px; border-radius: 10px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .exec-summary h2 { font-size: 1.3em; margin-bottom: 15px; color: #1e293b; }
        .risk-badge { display: inline-block; padding: 6px 20px; border-radius: 25px; color: white; font-weight: 700; font-size: 1em; letter-spacing: 0.5px; }
        .risk-badge.Critical { background: #dc2626; }
        .risk-badge.High { background: #ea580c; }
        .risk-badge.Medium { background: #ca8a04; }
        .risk-badge.Low { background: #2563eb; }
        .risk-badge.None { background: #22c55e; }
        .risk-score { font-size: 2.5em; font-weight: 800; color: #1e293b; margin-right: 15px; vertical-align: middle; }
        .risk-row { display: flex; align-items: center; gap: 15px; margin-bottom: 20px; }

        /* Severity chart */
        .chart-container { margin-top: 15px; }
        .chart-bar-row { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
        .chart-label { width: 70px; font-size: 0.85em; font-weight: 600; text-align: right; }
        .chart-bar-bg { flex: 1; background: #f1f5f9; border-radius: 6px; height: 24px; overflow: hidden; }
        .chart-bar { height: 100%; border-radius: 6px; min-width: 2px; transition: width 0.3s; display: flex; align-items: center; padding-left: 8px; color: white; font-size: 0.75em; font-weight: 600; }
        .chart-bar.critical { background: #dc2626; }
        .chart-bar.high { background: #ea580c; }
        .chart-bar.medium { background: #ca8a04; }
        .chart-bar.low { background: #2563eb; }
        .chart-bar.info { background: #6b7280; }
        .chart-count { width: 30px; font-size: 0.85em; color: #64748b; }

        /* Summary cards */
        .summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 24px; }
        @media (max-width: 768px) { .summary { grid-template-columns: repeat(2, 1fr); } }
        .card { background: white; padding: 25px 15px; border-radius: 10px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-top: 4px solid #e2e8f0; }
        .card .count { font-size: 2.5em; font-weight: 800; }
        .card .label { font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; margin-top: 5px; opacity: 0.7; }
        .card.critical { border-top-color: #dc2626; } .card.critical .count { color: #dc2626; }
        .card.high { border-top-color: #ea580c; } .card.high .count { color: #ea580c; }
        .card.medium { border-top-color: #ca8a04; } .card.medium .count { color: #ca8a04; }
        .card.low { border-top-color: #2563eb; } .card.low .count { color: #2563eb; }
        .card.info { border-top-color: #6b7280; } .card.info .count { color: #6b7280; }

        /* Categories */
        .categories { background: white; padding: 20px 25px; border-radius: 10px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .categories h3 { font-size: 1.1em; margin-bottom: 12px; }
        .cat-tag { display: inline-block; background: #f1f5f9; padding: 4px 12px; border-radius: 20px; margin: 3px; font-size: 0.85em; color: #475569; }

        /* Section titles */
        .section-title { font-size: 1.4em; font-weight: 700; margin: 24px 0 15px; padding-bottom: 10px; border-bottom: 2px solid #e2e8f0; }

        /* Findings */
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
        .confidence-badge { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 0.7em; font-weight: 600; text-transform: uppercase; vertical-align: middle; margin-left: 5px; }
        .conf-Confirmed { background: #dcfce7; color: #166534; }
        .conf-Tentative { background: #fef9c3; color: #854d0e; }
        .conf-Informational { background: #f1f5f9; color: #64748b; }
        .finding p { margin: 8px 0; color: #475569; }
        .finding .label { font-weight: 600; color: #1e293b; }

        /* Collapsible evidence */
        details { margin: 8px 0; }
        details summary { cursor: pointer; font-weight: 600; color: #1e293b; font-size: 0.9em; padding: 5px 0; }
        details summary:hover { color: #3b82f6; }
        pre { background: #f8fafc; border: 1px solid #e2e8f0; padding: 15px; border-radius: 6px; overflow-x: auto; font-size: 0.85em; margin: 8px 0; white-space: pre-wrap; word-wrap: break-word; }
        .meta-info { display: flex; flex-wrap: wrap; gap: 15px; margin-top: 12px; padding-top: 12px; border-top: 1px solid #f1f5f9; font-size: 0.85em; color: #64748b; }

        /* Diff section */
        .diff-section { background: white; padding: 25px; border-radius: 10px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .diff-section h2 { font-size: 1.3em; margin-bottom: 15px; }
        .diff-stats { display: flex; gap: 20px; margin-bottom: 15px; }
        .diff-stat { padding: 8px 16px; border-radius: 8px; font-weight: 600; font-size: 0.9em; }
        .diff-new { background: #fef2f2; color: #dc2626; }
        .diff-resolved { background: #f0fdf4; color: #16a34a; }
        .diff-persisting { background: #fffbeb; color: #ca8a04; }
        .diff-item { padding: 8px 12px; margin: 4px 0; border-radius: 6px; font-size: 0.9em; display: flex; align-items: center; gap: 8px; }
        .diff-item.new { background: #fef2f2; }
        .diff-item.resolved { background: #f0fdf4; }

        /* Attack Scenarios */
        .scenarios-section, .remediation-section { background: white; padding: 25px; border-radius: 10px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .scenarios-section h2, .remediation-section h2 { font-size: 1.3em; margin-bottom: 8px; color: #1e293b; }
        .scenarios-intro, .remediation-intro { color: #64748b; font-size: 0.9em; margin-bottom: 18px; }
        .scenario { border-left: 4px solid #e2e8f0; padding: 15px 20px; margin-bottom: 12px; border-radius: 0 8px 8px 0; background: #f8fafc; }
        .scenario.sev-Critical { border-left-color: #dc2626; background: #fef2f2; }
        .scenario.sev-High { border-left-color: #ea580c; background: #fff7ed; }
        .scenario.sev-Medium { border-left-color: #ca8a04; background: #fffbeb; }
        .scenario.sev-Low { border-left-color: #2563eb; background: #eff6ff; }
        .scenario-header { margin-bottom: 10px; font-size: 1.05em; }
        .scenario-body p { color: #475569; margin-bottom: 10px; font-size: 0.92em; }
        .scenario-detail { display: flex; gap: 8px; margin-top: 6px; font-size: 0.88em; color: #64748b; }
        .scenario-detail .label { font-weight: 600; color: #1e293b; min-width: 85px; }

        /* Remediation Table */
        .remediation-table { width: 100%; border-collapse: collapse; font-size: 0.9em; margin-top: 10px; }
        .remediation-table th { background: #f1f5f9; padding: 10px 12px; text-align: left; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px; color: #64748b; border-bottom: 2px solid #e2e8f0; }
        .remediation-table td { padding: 10px 12px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
        .rem-row.rem-Critical td { background: #fef2f2; }
        .rem-row.rem-High td { background: #fff7ed; }
        .rem-row.rem-Medium td { background: #fffbeb; }
        .priority-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: 600; white-space: nowrap; }
        .priority-P0 { background: #dc2626; color: white; }
        .priority-P1 { background: #ea580c; color: white; }
        .priority-P2 { background: #ca8a04; color: white; }
        .priority-P3 { background: #6b7280; color: white; }

        /* Footer */
        .footer { text-align: center; padding: 30px; color: #94a3b8; font-size: 0.85em; margin-top: 30px; }

        /* Print styles */
        @media print {
            body { background: white; }
            .container { max-width: 100%; padding: 10px; }
            .header { background: #1e293b !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
            .card, .finding, .exec-summary, .diff-section, .categories, .info-bar { box-shadow: none; border: 1px solid #e2e8f0; }
            .chart-bar { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
            .badge, .risk-badge, .confidence-badge { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
            details { open; }
            details[open] summary { display: none; }
        }
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
            <span><strong>Duration:</strong> {{ duration }}</span>
            <span><strong>Requests:</strong> {{ total_requests }}</span>
            <span><strong>Modules:</strong> {{ modules_executed | join(sep=", ") }}</span>
        </div>

        <!-- Executive Summary -->
        <div class="exec-summary">
            <h2>Executive Summary</h2>
            <div class="risk-row">
                <span class="risk-score">{{ risk_score }}</span>
                <span class="risk-badge {{ risk_level }}">{{ risk_level }} Risk</span>
            </div>
            <div class="chart-container">
                <div class="chart-bar-row">
                    <span class="chart-label">Critical</span>
                    <div class="chart-bar-bg"><div class="chart-bar critical" style="width: {{ critical_pct }}%">{% if critical_count > 0 %}{{ critical_count }}{% endif %}</div></div>
                    <span class="chart-count">{{ critical_count }}</span>
                </div>
                <div class="chart-bar-row">
                    <span class="chart-label">High</span>
                    <div class="chart-bar-bg"><div class="chart-bar high" style="width: {{ high_pct }}%">{% if high_count > 0 %}{{ high_count }}{% endif %}</div></div>
                    <span class="chart-count">{{ high_count }}</span>
                </div>
                <div class="chart-bar-row">
                    <span class="chart-label">Medium</span>
                    <div class="chart-bar-bg"><div class="chart-bar medium" style="width: {{ medium_pct }}%">{% if medium_count > 0 %}{{ medium_count }}{% endif %}</div></div>
                    <span class="chart-count">{{ medium_count }}</span>
                </div>
                <div class="chart-bar-row">
                    <span class="chart-label">Low</span>
                    <div class="chart-bar-bg"><div class="chart-bar low" style="width: {{ low_pct }}%">{% if low_count > 0 %}{{ low_count }}{% endif %}</div></div>
                    <span class="chart-count">{{ low_count }}</span>
                </div>
                <div class="chart-bar-row">
                    <span class="chart-label">Info</span>
                    <div class="chart-bar-bg"><div class="chart-bar info" style="width: {{ info_pct }}%">{% if info_count > 0 %}{{ info_count }}{% endif %}</div></div>
                    <span class="chart-count">{{ info_count }}</span>
                </div>
            </div>
        </div>

        <div class="summary">
            <div class="card critical"><div class="count">{{ critical_count }}</div><div class="label">Critical</div></div>
            <div class="card high"><div class="count">{{ high_count }}</div><div class="label">High</div></div>
            <div class="card medium"><div class="count">{{ medium_count }}</div><div class="label">Medium</div></div>
            <div class="card low"><div class="count">{{ low_count }}</div><div class="label">Low</div></div>
            <div class="card info"><div class="count">{{ info_count }}</div><div class="label">Info</div></div>
        </div>

        {% if categories | length > 0 %}
        <div class="categories">
            <h3>Findings by Category</h3>
            {% for cat in categories %}
            <span class="cat-tag">{{ cat.0 }} ({{ cat.1 }})</span>
            {% endfor %}
        </div>
        {% endif %}

        {% if has_scenarios %}
        <div class="scenarios-section">
            <h2>Attack Scenarios</h2>
            <p class="scenarios-intro">Based on the findings detected, the following attack scenarios are possible against this application:</p>
            {% for scenario in attack_scenarios %}
            <div class="scenario sev-{{ scenario.severity_class }}">
                <div class="scenario-header">
                    <span class="badge badge-{{ scenario.severity_class }}">{{ scenario.severity_class }}</span>
                    <strong>{{ scenario.title }}</strong>
                </div>
                <div class="scenario-body">
                    <p>{{ scenario.description }}</p>
                    <div class="scenario-detail">
                        <span class="label">Impact:</span>
                        <span>{{ scenario.impact }}</span>
                    </div>
                    <div class="scenario-detail">
                        <span class="label">Likelihood:</span>
                        <span>{{ scenario.likelihood }}</span>
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>
        {% endif %}

        {% if has_remediation %}
        <div class="remediation-section">
            <h2>Remediation Plan</h2>
            <p class="remediation-intro">Prioritized actions to address the findings. P0 items should be resolved before production deployment.</p>
            <table class="remediation-table">
                <thead>
                    <tr>
                        <th>Priority</th>
                        <th>Finding</th>
                        <th>Action Required</th>
                        <th>Effort</th>
                    </tr>
                </thead>
                <tbody>
                {% for step in remediation_plan %}
                    <tr class="rem-row rem-{{ step.severity_class }}">
                        <td><span class="priority-badge priority-{{ step.priority | truncate(length=2, end="") | trim }}">{{ step.priority }}</span></td>
                        <td>{{ step.finding }}</td>
                        <td>{{ step.action }}</td>
                        <td>{{ step.effort }}</td>
                    </tr>
                {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        {% if has_diff %}
        <div class="diff-section">
            <h2>Differential Analysis</h2>
            <div class="diff-stats">
                <span class="diff-stat diff-new">+{{ new_count }} New</span>
                <span class="diff-stat diff-resolved">-{{ resolved_count }} Resolved</span>
                <span class="diff-stat diff-persisting">={{ persisting_count }} Persisting</span>
            </div>
            {% if new_count > 0 %}
            <h4 style="color: #dc2626; margin: 10px 0 5px;">New Findings (Regressions)</h4>
            {% for f in new_findings %}
            <div class="diff-item new">
                <span class="badge badge-{{ f.severity }}">{{ f.severity }}</span>
                <span>{{ f.title }}</span>
                <span style="color: #94a3b8; margin-left: auto; font-size: 0.85em;">{{ f.url }}</span>
            </div>
            {% endfor %}
            {% endif %}
            {% if resolved_count > 0 %}
            <h4 style="color: #16a34a; margin: 10px 0 5px;">Resolved Findings (Fixed)</h4>
            {% for f in resolved_findings %}
            <div class="diff-item resolved">
                <span class="badge badge-{{ f.severity }}">{{ f.severity }}</span>
                <span>{{ f.title }}</span>
                <span style="color: #94a3b8; margin-left: auto; font-size: 0.85em;">{{ f.url }}</span>
            </div>
            {% endfor %}
            {% endif %}
        </div>
        {% endif %}

        <div class="section-title">Findings ({{ total_findings }})</div>
        {% for finding in findings %}
        <div class="finding sev-{{ finding.severity }}">
            <h3>
                <span class="badge badge-{{ finding.severity }}">{{ finding.severity }}</span>
                {{ finding.title }}
                <span class="confidence-badge conf-{{ finding.confidence }}">{{ finding.confidence }}</span>
            </h3>
            <p>{{ finding.description }}</p>
            {% if finding.evidence %}
            <details>
                <summary>Evidence</summary>
                <pre>{{ finding.evidence }}</pre>
            </details>
            {% endif %}
            {% if finding.request %}
            <details>
                <summary>Request</summary>
                <pre>{{ finding.request }}</pre>
            </details>
            {% endif %}
            {% if finding.response %}
            <details>
                <summary>Response</summary>
                <pre>{{ finding.response }}</pre>
            </details>
            {% endif %}
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
</html>"##
}
