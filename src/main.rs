//! Argos Panoptes - Web Security Scanner CLI

use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::{Path, PathBuf};
use tabled::builder::Builder;
use tabled::settings::Style;
use tracing_subscriber::EnvFilter;
use url::Url;

use argos::config;
use argos::http::AuthConfig;
use argos::models::{ScanConfig, Severity};
use argos::proxy::InterceptProxy;
use argos::report;
use argos::scanner::ScanEngine;

/// Argos Panoptes - Web Security Scanner for Healthcare Environments
#[derive(Parser)]
#[command(name = "argos", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Run a security scan against a target
    Scan {
        /// Target URL to scan
        #[arg(short, long)]
        target: String,

        /// Modules to run (comma-separated)
        #[arg(short, long, value_delimiter = ',')]
        modules: Option<Vec<String>>,

        /// Number of concurrent threads
        #[arg(long, default_value_t = 10)]
        threads: usize,

        /// Request timeout in seconds
        #[arg(long, default_value_t = 30)]
        timeout: u64,

        /// Output file path (default: argos_{hostname}.html)
        #[arg(short, long)]
        output: Option<String>,

        /// Output format (html, json, or sarif)
        #[arg(short, long, default_value = "html")]
        format: String,

        /// Exit with code 1 if findings at or above this severity are found (critical, high, medium, low, info)
        #[arg(long)]
        fail_on: Option<String>,

        /// Path to configuration file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// HTTP/HTTPS proxy URL
        #[arg(long)]
        proxy: Option<String>,

        /// Max requests per second
        #[arg(long)]
        rate_limit: Option<u32>,

        /// Custom wordlist path
        #[arg(short, long)]
        wordlist: Option<String>,

        /// Custom headers (format: "Key: Value")
        #[arg(short = 'H', long)]
        header: Option<Vec<String>>,

        /// Authentication type (none, form, bearer, cookie)
        #[arg(long, default_value = "none")]
        auth_type: String,

        /// Authentication URL (for form-based auth)
        #[arg(long)]
        auth_url: Option<String>,

        /// Authentication username (for form-based auth)
        #[arg(long)]
        auth_user: Option<String>,

        /// Authentication password (for form-based auth)
        #[arg(long)]
        auth_pass: Option<String>,

        /// Bearer token (for bearer auth)
        #[arg(long)]
        auth_token: Option<String>,

        /// Cookie string (for cookie-based auth)
        #[arg(long)]
        auth_cookie: Option<String>,

        /// Directory containing CVE template YAML files
        #[arg(long)]
        templates_dir: Option<String>,

        /// Additional template directories (comma-separated)
        #[arg(long, value_delimiter = ',')]
        extra_template_dirs: Option<Vec<String>>,

        /// Run scanner modules concurrently
        #[arg(long)]
        concurrent: bool,

        /// Enable Out-of-Band testing
        #[arg(long)]
        oob: bool,

        /// OOB callback host (IP or hostname reachable from target)
        #[arg(long)]
        oob_host: Option<String>,

        /// OOB HTTP callback port
        #[arg(long, default_value_t = 8888)]
        oob_http_port: u16,

        /// OOB DNS callback port
        #[arg(long, default_value_t = 5353)]
        oob_dns_port: u16,

        /// OOB interaction timeout in seconds
        #[arg(long, default_value_t = 10)]
        oob_timeout: u64,

        /// Enable JavaScript rendering for SPA crawling (requires browser feature)
        #[arg(long)]
        render: bool,

        /// Wait time in ms after page load for JS rendering
        #[arg(long, default_value_t = 3000)]
        render_wait: u64,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },

    /// List available scanner modules
    Modules,

    /// Start an intercept proxy to capture HTTP traffic
    Proxy {
        /// Port to listen on
        #[arg(short, long, default_value_t = 8080)]
        port: u16,

        /// Output file path for HAR export
        #[arg(short, long, default_value = "traffic.har")]
        output: String,

        /// Filter traffic for a specific target domain
        #[arg(long)]
        target: Option<String>,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },

    /// Generate a report from a previous scan's JSON output
    Report {
        /// Path to the JSON results file
        #[arg(short, long)]
        input: PathBuf,

        /// Output format (html or json)
        #[arg(short, long, default_value = "html")]
        format: String,

        /// Output file path
        #[arg(short, long, default_value = "argos_report.html")]
        output: String,
    },
}

fn output_name_from_target(target: &str, ext: &str) -> String {
    if let Ok(url) = Url::parse(target) {
        let host = url.host_str().unwrap_or("unknown");
        let sanitized: String = host
            .chars()
            .map(|c| if c == '.' { '_' } else { c })
            .collect();
        format!("argos_{sanitized}.{ext}")
    } else {
        format!("argos_report.{ext}")
    }
}

fn print_banner() {
    let banner = r#"
    ╔═══════════════════════════════════════╗
    ║  🔱 ARGOS PANOPTES v0.1.0            ║
    ║  Web Security Scanner                ║
    ║  "El que todo lo ve"                 ║
    ╚═══════════════════════════════════════╝
    "#;
    println!("{}", banner.cyan());
}

fn print_summary(findings: &[argos::models::Finding]) {
    let severities = [
        (Severity::Critical, "Critical"),
        (Severity::High, "High"),
        (Severity::Medium, "Medium"),
        (Severity::Low, "Low"),
        (Severity::Info, "Info"),
    ];

    println!("\n{}", "  Scan Summary".bold());
    println!("  {}", "─".repeat(35));

    let mut builder = Builder::default();
    builder.push_record(["Severity", "Count"]);

    for (severity, label) in &severities {
        let count = findings.iter().filter(|f| &f.severity == severity).count();
        builder.push_record([label.to_string(), count.to_string()]);
    }

    builder.push_record(["Total".to_string(), findings.len().to_string()]);

    let mut table = builder.build();
    table.with(Style::rounded());
    println!("{table}");

    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low = findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();
    let info_count = findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();

    println!(
        "\n  {} {} {} {} {}",
        format!("{critical} Critical").red().bold(),
        format!("{high} High").bright_red(),
        format!("{medium} Medium").yellow(),
        format!("{low} Low").blue(),
        format!("{info_count} Info").white(),
    );
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            target,
            modules,
            threads,
            timeout,
            output,
            format,
            fail_on,
            config: config_path,
            proxy,
            rate_limit,
            wordlist,
            header,
            auth_type,
            auth_url,
            auth_user,
            auth_pass,
            auth_token,
            auth_cookie,
            templates_dir,
            extra_template_dirs,
            concurrent,
            oob,
            oob_host,
            oob_http_port,
            oob_dns_port,
            oob_timeout,
            render,
            render_wait,
            verbose,
        } => {
            let filter = if verbose { "argos=debug" } else { "argos=info" };
            tracing_subscriber::fmt()
                .with_env_filter(
                    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
                )
                .with_target(false)
                .init();

            print_banner();

            let mut scan_config = if let Some(ref path) = config_path {
                config::load_config(path)?
            } else {
                let default_path = Path::new("config/default.toml");
                if default_path.exists() {
                    config::load_config(default_path)?
                } else {
                    ScanConfig::default()
                }
            };

            config::merge_cli_args(
                &mut scan_config,
                target,
                Some(threads),
                Some(timeout),
                modules,
                proxy,
                rate_limit,
                wordlist,
                header,
            );

            // Configure authentication
            scan_config.auth = match auth_type.as_str() {
                "form" => {
                    let login_url = auth_url.unwrap_or_else(|| {
                        eprintln!("Error: --auth-url is required for form-based auth");
                        std::process::exit(1);
                    });
                    let username = auth_user.unwrap_or_else(|| {
                        eprintln!("Error: --auth-user is required for form-based auth");
                        std::process::exit(1);
                    });
                    let password = auth_pass.unwrap_or_else(|| {
                        eprintln!("Error: --auth-pass is required for form-based auth");
                        std::process::exit(1);
                    });
                    AuthConfig::FormBased {
                        login_url,
                        username,
                        password,
                    }
                }
                "bearer" => {
                    let token = auth_token.unwrap_or_else(|| {
                        eprintln!("Error: --auth-token is required for bearer auth");
                        std::process::exit(1);
                    });
                    AuthConfig::BearerToken { token }
                }
                "cookie" => {
                    let cookies = auth_cookie.unwrap_or_else(|| {
                        eprintln!("Error: --auth-cookie is required for cookie-based auth");
                        std::process::exit(1);
                    });
                    AuthConfig::CookieBased { cookies }
                }
                _ => AuthConfig::None,
            };

            scan_config.templates_dir = templates_dir;
            if let Some(dirs) = extra_template_dirs {
                scan_config.extra_template_dirs = dirs;
            }
            if concurrent {
                scan_config.concurrent = true;
            }
            if oob {
                scan_config.oob_enabled = true;
                scan_config.oob_host = oob_host;
                scan_config.oob_http_port = oob_http_port;
                scan_config.oob_dns_port = oob_dns_port;
                scan_config.oob_timeout_secs = oob_timeout;
                // Auto-add oob module if not present
                if !scan_config.modules.contains(&"oob".to_string()) {
                    scan_config.modules.push("oob".to_string());
                }
            }
            if render {
                scan_config.render_enabled = true;
                scan_config.render_wait_ms = render_wait;
            }

            println!("  {} {}", "Target:".bold(), scan_config.target.green());
            println!(
                "  {} {}",
                "Modules:".bold(),
                scan_config.modules.join(", ").cyan()
            );
            println!(
                "  {} {}\n",
                "Threads:".bold(),
                scan_config.threads.to_string().cyan()
            );

            let engine = ScanEngine::with_defaults();
            let result = engine.run(&scan_config).await?;

            print_summary(&result.findings);

            let output_file = output.unwrap_or_else(|| {
                let ext = match format.as_str() {
                    "json" => "json",
                    "sarif" => "sarif.json",
                    _ => "html",
                };
                output_name_from_target(&scan_config.target, ext)
            });
            let output_path = Path::new(&output_file);
            match format.as_str() {
                "json" => {
                    report::json::export(&result, output_path)?;
                }
                "sarif" => {
                    report::sarif::export(&result, output_path)?;
                }
                _ => {
                    report::html::generate(&result, output_path)?;
                    let json_path = output_path.with_extension("json");
                    report::json::export(&result, &json_path)?;
                }
            }

            println!("\n  {} {}", "Report saved to:".bold(), output_file.green());

            // Exit code based on --fail-on threshold
            if let Some(ref threshold) = fail_on {
                let fail_severity = match threshold.to_lowercase().as_str() {
                    "critical" => Some(Severity::Critical),
                    "high" => Some(Severity::High),
                    "medium" => Some(Severity::Medium),
                    "low" => Some(Severity::Low),
                    "info" => Some(Severity::Info),
                    _ => {
                        eprintln!(
                            "  {} Invalid --fail-on value: '{}'. Use: critical, high, medium, low, info",
                            "Error:".red().bold(),
                            threshold
                        );
                        None
                    }
                };

                if let Some(threshold_sev) = fail_severity {
                    let has_findings_at_or_above = result
                        .findings
                        .iter()
                        .any(|f| f.severity <= threshold_sev);

                    if has_findings_at_or_above {
                        println!(
                            "\n  {} Findings at or above {} severity detected.",
                            "FAIL:".red().bold(),
                            threshold.to_uppercase().red()
                        );
                        std::process::exit(1);
                    }
                }
            }
        }

        Commands::Proxy {
            port,
            output,
            target,
            verbose,
        } => {
            let filter = if verbose { "argos=debug" } else { "argos=info" };
            tracing_subscriber::fmt()
                .with_env_filter(
                    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
                )
                .with_target(false)
                .init();

            print_banner();

            println!("  {} {}", "Proxy mode:".bold(), "Intercept Proxy".cyan());
            println!("  {} {}", "Port:".bold(), port.to_string().green());
            println!("  {} {}", "Output:".bold(), output.green());
            if let Some(ref t) = target {
                println!("  {} {}", "Target filter:".bold(), t.cyan());
            }
            println!(
                "\n  {}",
                "Press Ctrl+C to stop and export captured traffic.".yellow()
            );
            println!();

            let proxy = InterceptProxy::new(port, output, target);
            proxy.start().await?;
        }

        Commands::Modules => {
            print_banner();
            let engine = ScanEngine::with_defaults();
            let modules = engine.list_modules();

            println!("  {}\n", "Available Scanner Modules:".bold());
            for (name, description) in modules {
                println!("    {} {}", format!("{name:20}").cyan().bold(), description);
            }
            println!();
        }

        Commands::Report {
            input,
            format,
            output,
        } => {
            tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::new("argos=info"))
                .with_target(false)
                .init();

            print_banner();

            let result = report::json::load(&input)?;
            let output_path = Path::new(&output);

            match format.as_str() {
                "json" => {
                    report::json::export(&result, output_path)?;
                }
                _ => {
                    report::html::generate(&result, output_path)?;
                }
            }

            print_summary(&result.findings);
            println!("\n  {} {}", "Report saved to:".bold(), output.green());
        }
    }

    Ok(())
}
