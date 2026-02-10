# Argos Panoptes

Web Security Scanner with 800+ detection templates, 15 scanner modules, active secret verification, and healthcare-specific checks.

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
argos scan -t https://target.com -m headers,ssl,injection,templates,secrets

# Differential scan against a baseline
argos scan -t https://target.com -f json -o baseline.json
argos scan -t https://target.com --baseline baseline.json

# List available modules
argos modules
```

## Features

- **15 scanner modules**: headers, SSL/TLS, cookies, CORS, info disclosure, discovery, injection, API security, templates, WAF detection, WebSocket, DAST, OOB testing, GraphQL, secrets
- **7 injection sub-modules**: SQLi (boolean + time-based), XSS (reflected + DOM), command injection, SSTI, path traversal, open redirect, CRLF
- **Secrets scanner** with 50+ patterns, 15 active verification providers, JWT analysis with HS256 brute-force, JS config secrets, and git exposure deep scan
- **800+ YAML detection templates** across 8 categories, embedded in the binary
- **Differential reporting** with `--baseline` to track security posture over time
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
| `secrets` | Tokens, API keys, credentials, JWTs, source maps, git exposure |

## Secrets Scanner

The secrets module performs deep analysis across multiple attack surfaces:

### Detection (50+ patterns)

- **Service tokens**: GitHub, GitLab, Slack, OpenAI, Anthropic, HuggingFace, SendGrid, Mailgun, npm, DigitalOcean, New Relic, Sentry, Linear, Supabase, Stripe, Square, Shopify, and more
- **Cloud keys**: AWS (AKIA/ASIA), GCP (AIza), Azure connection strings
- **Credentials**: database connection strings (PostgreSQL, MongoDB, MySQL, Redis, JDBC), hardcoded passwords, email+password pairs
- **Crypto**: private keys (RSA, EC, DSA, OPENSSH, PGP), JWT tokens
- **Infrastructure**: internal IPs, localhost URLs, internal hostnames, Sentry DSNs

### JS Runtime Config Secrets

- **Window config objects**: `window.__CONFIG__`, `__INITIAL_STATE__`, `__ENV__`, `__NEXT_DATA__`
- **Leaked env vars**: `REACT_APP_*`, `NEXT_PUBLIC_*`, `VUE_APP_*`, `VITE_*` with sensitive keywords and entropy filtering
- **Unresolved process.env**: bundler misconfigurations leaving `process.env.VAR` in production

### Git Exposure Deep Scan

- **`.git/config`**: detects tokens embedded in remote URLs (`https://user:token@host/repo`)
- **`.git/logs/HEAD`**: scans reflog for leaked secrets across commit history

### Source Map Analysis

- Probes `{url}.map` and `sourceMappingURL` references
- Scans original source files inside source maps for secrets

### Active Verification (15 providers)

| Provider | Prefix | Method |
|----------|--------|--------|
| GitHub | `ghp_`, `github_pat_` | GET /user |
| GitLab | `glpat-` | GET /api/v4/user |
| Slack | `xoxb-`, `xoxp-` | POST auth.test |
| OpenAI | `sk-proj-` | GET /v1/models |
| HuggingFace | `hf_` | GET /api/whoami |
| SendGrid | `SG.` | GET /v3/scopes |
| Mailgun | `key-` | GET /v3/domains (Basic auth) |
| npm | `npm_` | GET /v1/user |
| DigitalOcean | `dop_v1_` | GET /v2/account |
| Anthropic | `sk-ant-api03-` | GET /v1/models (x-api-key) |
| New Relic | `NRAK-` | GET /v2/users.json |
| Sentry | `sntrys_` | GET /api/0/organizations/ |
| Linear | `lin_api_` | POST /graphql |
| Supabase | `sbp_` | GET /v1/projects |
| JWT | `eyJ` | Local decode + HS256 brute-force |

Verified tokens are marked as **confirmed**; revoked tokens are automatically removed from findings.

### JWT Analysis

- **Algorithm detection**: identifies `alg=none` (authentication bypass), HMAC vs asymmetric
- **HS256 brute-force**: tests 17 common weak secrets against the JWT signature
- **Claims extraction**: issuer, audience, subject, expiration status
- **Expiration tracking**: active (hours remaining), expired (days ago), no expiration

## Differential Reporting

Track security posture changes between scans:

```bash
# Create a baseline
argos scan -t https://target.com -f json -o baseline.json

# Compare against baseline
argos scan -t https://target.com --baseline baseline.json
```

Output shows:

```
═══ DIFFERENTIAL ANALYSIS ═══
Baseline: baseline.json
Trend: 14 findings → 12 findings

Delta: +1 new  -3 resolved  =11 persisting

NEW FINDINGS (regression):
  + [HIGH] Hardcoded Password → https://target.com/app.js

RESOLVED FINDINGS (fixed):
  - [CRITICAL] Exposed JWT Token → https://target.com/app.js
  - [MEDIUM] CORS Wildcard → https://target.com/
  - [LOW] Server Header Disclosure → https://target.com/
```

The `DiffReport` is included in JSON output for programmatic consumption.

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

# JSONL (one finding per line)
argos scan -t https://target.com -f jsonl

# CSV
argos scan -t https://target.com -f csv

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

# Differential scan in CI pipeline
argos scan -t https://target.com --baseline previous-scan.json --fail-on high
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
  -f, --format <FORMAT>           Output format: html, json, jsonl, csv, sarif
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
      --baseline <FILE>           Previous scan JSON for differential report
      --oob                       Enable out-of-band testing
      --oob-host <HOST>           OOB callback host
      --render                    Enable JS rendering for SPA crawling
```

## Intercept Proxy

Capture HTTP traffic for analysis:

```bash
argos proxy -p 8080 -o traffic.har
argos proxy -p 8080 --target example.com -o traffic.har
```

## Generate Report

Convert JSON results to other formats:

```bash
argos report -i scan_results.json -f html -o report.html
argos report -i scan_results.json -f sarif -o results.sarif
```

## Architecture

```
src/
  main.rs          CLI entry point
  models.rs        Core data models (Finding, Severity, ScanConfig, DiffReport)
  http/            HTTP client with retry and rate limiting
  crawler/         Concurrent BFS web crawler
  scanner/         Scanner modules
    injection/     Injection sub-modules (sqli, xss, command, ssti, etc.)
    templates/     YAML template engine (loader, engine, matcher, cluster)
    dast/          Dynamic testing (csrf, idor, session, access control)
    secrets.rs     Secrets scanner (50+ patterns, 15 providers, JWT analysis)
  report/          Report generation (HTML, JSON, JSONL, CSV, SARIF)
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
