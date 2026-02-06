# Argos Panoptes

Web Security Scanner with 800+ detection templates, 14 scanner modules, and healthcare-specific checks.

Built in Rust. Single binary. No dependencies.

*"El que todo lo ve"*

## Installation

### Homebrew (macOS/Linux)

```bash
brew install rvielma/argos/argos
```

### Script

```bash
curl -sSL https://raw.githubusercontent.com/rvielma/argos/master/install.sh | bash
```

### From source

```bash
git clone https://github.com/rvielma/argos.git
cd argos
cargo build --release
```

The binary will be at `target/release/argos`.

## Quick Start

```bash
# Scan a target with default modules
argos scan -t https://target.com

# Scan with specific modules
argos scan -t https://target.com -m headers,ssl,injection,templates

# Scan with all modules
argos scan -t https://target.com -m all

# List available modules
argos modules
```

## Features

- **14 scanner modules**: headers, SSL/TLS, cookies, CORS, info disclosure, discovery, injection, API security, templates, WAF detection, WebSocket, DAST, OOB testing, GraphQL
- **7 injection sub-modules**: SQLi (boolean + time-based), XSS (reflected + DOM), command injection, SSTI, path traversal, open redirect, CRLF
- **800+ YAML detection templates** across 8 categories, embedded in the binary
- **SARIF v2.1.0 output** for GitHub Code Scanning integration
- **CI/CD ready** with `--fail-on` exit codes
- Concurrent BFS crawler with deduplication
- Intercept proxy with HAR export
- Authentication support (form, bearer, cookie)
- Out-of-Band (OOB) testing via HTTP/DNS callbacks
- Healthcare-specific checks (FHIR, DICOM, HL7)

## Scanner Modules

| Module | Description |
|--------|-------------|
| `headers` | HTTP security headers analysis (HSTS, CSP, X-Frame-Options, etc.) |
| `ssl` | SSL/TLS configuration, certificate validity, protocol versions |
| `cookies` | Cookie security flags (Secure, HttpOnly, SameSite) |
| `cors` | CORS misconfiguration detection |
| `info_disclosure` | Information disclosure via error messages, comments, metadata |
| `discovery` | Hidden directories, sensitive files, exposed endpoints |
| `injection` | SQLi, XSS, Command Injection, SSTI, Path Traversal, Open Redirect, CRLF |
| `api` | API security: authentication, rate limiting, error handling |
| `templates` | 800+ YAML templates for CVE detection and fingerprinting |
| `waf` | Web Application Firewall detection |
| `websocket` | WebSocket endpoint security |
| `dast` | CSRF, broken access control, session management, IDOR |
| `oob` | Blind SSRF, XXE, blind SQLi via out-of-band callbacks |
| `graphql` | GraphQL introspection, misconfigurations |

## Detection Templates

800+ YAML templates organized by category:

| Category | Count | Description |
|----------|-------|-------------|
| CVEs | 160+ | Known vulnerabilities (Log4Shell, Spring4Shell, ProxyShell, etc.) |
| Technologies | 100+ | Framework and server fingerprinting |
| Misconfigurations | 90+ | Debug modes, exposed configs, directory listings |
| Exposures | 100+ | Admin panels, dashboards, management interfaces |
| Default Logins | 50+ | Default credential detection |
| Healthcare | 50+ | FHIR, DICOM, HL7, EHR system checks |
| Cloud | 15 | AWS, Azure, GCP misconfigurations |
| GraphQL | 10 | GraphQL introspection and security |

Templates are embedded in the binary. Override with `--templates-dir` or extend with `--extra-template-dirs`.

### Template format

```yaml
id: CVE-2024-1234
name: "Example Vulnerability"
severity: high
confidence: tentative
description: "Description of the vulnerability."
reference: CWE-79
requests:
  - method: GET
    path: "/vulnerable/path"
    matchers:
      - type: body
        words:
          - "specific_indicator"
          - "proof_of_vuln"
      - type: status
        status: [200]
    condition: and
```

## Output Formats

```bash
# HTML report (default)
argos scan -t https://target.com

# JSON
argos scan -t https://target.com -f json

# SARIF (GitHub Code Scanning)
argos scan -t https://target.com -f sarif
```

## Authentication

```bash
# Bearer token
argos scan -t https://target.com --auth-type bearer --auth-token "eyJhbG..."

# Cookie-based
argos scan -t https://target.com --auth-type cookie --auth-cookie "session=abc123"

# Form-based login
argos scan -t https://target.com --auth-type form \
  --auth-url https://target.com/login \
  --auth-user admin --auth-pass secret
```

## CI/CD Integration

```bash
# Exit code 1 if high or critical findings detected
argos scan -t https://target.com --fail-on high -f sarif -o results.sarif
```

### GitHub Actions

```yaml
- name: Security Scan
  run: |
    argos scan -t ${{ env.TARGET_URL }} \
      --fail-on high \
      -f sarif -o results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Options

```
  -t, --target <URL>              Target URL
  -m, --modules <LIST>            Modules to run (comma-separated)
  -o, --output <FILE>             Output file path
  -f, --format <FORMAT>           Output format: html, json, sarif
  -H, --header <HEADER>           Custom headers ("Key: Value")
  -w, --wordlist <FILE>           Custom wordlist for discovery
  -v, --verbose                   Verbose output
      --threads <N>               Concurrent threads (default: 10)
      --timeout <SECS>            Request timeout (default: 30)
      --proxy <URL>               HTTP/HTTPS proxy
      --rate-limit <N>            Max requests per second
      --templates-dir <DIR>       Custom templates directory
      --extra-template-dirs <DIR> Additional template directories
      --concurrent                Run modules concurrently
      --fail-on <SEVERITY>        Exit code 1 if findings >= severity
      --oob                       Enable out-of-band testing
      --oob-host <HOST>           OOB callback host
```

## Intercept Proxy

Capture HTTP traffic for analysis:

```bash
argos proxy -p 8080 -o traffic.har
argos proxy -p 8080 --target example.com -o traffic.har
```

## Generate Report

Convert JSON results to HTML:

```bash
argos report -i scan_results.json -f html -o report.html
```

## Architecture

```
src/
  main.rs          CLI entry point
  models.rs        Core data models (Finding, Severity, ScanConfig)
  http/            HTTP client with retry and rate limiting
  crawler/         Concurrent BFS web crawler
  scanner/         Scanner modules
    injection/     Injection sub-modules (sqli, xss, command, ssti, etc.)
    templates/     YAML template engine (loader, engine, matcher, cluster)
    dast/          Dynamic testing (csrf, idor, session, access control)
  report/          Report generation (HTML, JSON, SARIF)
  proxy/           Intercept proxy with HAR export
  oob/             Out-of-Band callback servers (HTTP, DNS)
templates/         YAML detection templates (embedded in binary)
  cves/            CVE detection templates
  technologies/    Technology fingerprinting
  misconfigurations/
  exposures/
  default-logins/
  healthcare/      FHIR, DICOM, HL7 checks
  cloud/           AWS/Azure/GCP
  graphql/
```

## License

MIT
