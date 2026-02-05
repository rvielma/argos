# Argos Panoptes

Web Security Scanner for Healthcare Environments.

*"El que todo lo ve"*

## Features

- **15 scanner modules**: headers, SSL/TLS, cookies, CORS, info disclosure, discovery, injection, API security, templates, WAF detection, WebSocket, DAST, OOB testing, GraphQL
- **7 injection sub-modules**: SQLi (boolean + time-based), XSS (reflected + DOM), command injection, SSTI, path traversal, open redirect, CRLF
- **428 YAML detection templates** across 8 categories
- **SARIF v2.1.0 output** for GitHub Code Scanning integration
- **CI/CD ready** with `--fail-on` exit codes
- Concurrent BFS crawler with deduplication
- Intercept proxy with HAR export
- Authentication support (form, bearer, cookie)
- Out-of-Band (OOB) testing via HTTP/DNS callbacks

## Installation

```bash
cargo build --release
```

The binary will be at `target/release/argos`.

## Usage

### Basic scan

```bash
argos scan -t https://target.com
```

### Full options

```bash
argos scan \
  -t https://target.com \
  -o report.html \
  -f html \
  --threads 10 \
  --timeout 30 \
  --verbose
```

### Output formats

```bash
# HTML report (default)
argos scan -t https://target.com -f html

# JSON
argos scan -t https://target.com -f json

# SARIF (GitHub Code Scanning)
argos scan -t https://target.com -f sarif
```

### CI/CD integration

```bash
# Exit code 1 if high or critical findings
argos scan -t https://target.com --fail-on high

# SARIF for GitHub Actions
argos scan -t https://target.com -f sarif -o results.sarif.json --fail-on medium
```

### Select specific modules

```bash
argos scan -t https://target.com -m headers,ssl,injection,templates
```

### Authentication

```bash
# Bearer token
argos scan -t https://target.com --auth-type bearer --auth-token "eyJ..."

# Cookie
argos scan -t https://target.com --auth-type cookie --auth-cookie "session=abc123"

# Form-based
argos scan -t https://target.com --auth-type form \
  --auth-url https://target.com/login \
  --auth-user admin --auth-pass password
```

### Custom templates

```bash
argos scan -t https://target.com --templates-dir ./my-templates
argos scan -t https://target.com --extra-template-dirs ./custom1,./custom2
```

### Intercept proxy

```bash
argos proxy -p 8080 -o traffic.har
```

### Generate report from JSON

```bash
argos report -i scan_results.json -f html -o report.html
```

### List modules

```bash
argos modules
```

## Templates

428 YAML templates organized by category:

| Category | Count | Description |
|----------|-------|-------------|
| CVEs | 160 | Known vulnerability detection |
| Technologies | 79 | Technology fingerprinting |
| Misconfigurations | 57 | Security misconfiguration detection |
| Exposures | 57 | Exposed panels, APIs, services |
| Default Logins | 25 | Default credential detection |
| Healthcare | 25 | Healthcare-specific checks (HL7 FHIR, DICOM, etc.) |
| Cloud | 15 | AWS/Azure/GCP misconfigurations |
| GraphQL | 10 | GraphQL introspection and security |

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

## Scanner Modules

| Module | Description |
|--------|-------------|
| `headers` | Security headers analysis (HSTS, CSP, X-Frame-Options, etc.) |
| `ssl` | SSL/TLS configuration and certificate validation |
| `cookies` | Cookie security flags (Secure, HttpOnly, SameSite) |
| `cors` | CORS misconfiguration detection |
| `info_disclosure` | Information leakage (errors, comments, metadata) |
| `discovery` | Path and file discovery |
| `injection` | SQL injection, XSS, command injection, SSTI, path traversal, open redirect, CRLF |
| `api` | API security checks |
| `templates` | YAML-based CVE and vulnerability detection |
| `waf` | Web Application Firewall detection |
| `websocket` | WebSocket security analysis |
| `graphql` | GraphQL introspection and security checks |
| `dast` | Dynamic testing (CSRF, IDOR, session management, access control) |
| `oob` | Out-of-Band testing (SSRF, blind SQLi, XXE) |

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
templates/         YAML detection templates
  cves/            CVE detection templates
  technologies/    Technology fingerprinting
  misconfigurations/
  exposures/
  default-logins/
  healthcare/
  cloud/
  graphql/
```

## License

MIT
