//! WebSocket security scanner
//!
//! Detects WebSocket endpoints and checks for common security issues:
//! - Endpoint discovery on common paths
//! - Origin validation bypass (CWE-346)
//! - Missing authentication
//! - Encryption downgrade (ws:// vs wss://)

use crate::error::Result;
use crate::http::HttpClient;
use crate::models::{Finding, ScanConfig, Severity};
use async_trait::async_trait;
use futures::SinkExt;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::debug;
use url::Url;

/// Common WebSocket endpoint paths to probe
const WS_PATHS: &[&str] = &[
    "/ws",
    "/websocket",
    "/socket",
    "/socket.io/",
    "/signalr",
    "/hub",
    "/realtime",
    "/live",
    "/stream",
    "/events",
    "/chat",
    "/notifications",
    "/api/ws",
    "/api/websocket",
    "/graphql",
    "/subscriptions",
];

pub struct WebSocketScanner;

#[async_trait]
impl super::Scanner for WebSocketScanner {
    fn name(&self) -> &str {
        "websocket"
    }

    fn description(&self) -> &str {
        "Detects WebSocket endpoints and checks for origin validation, auth, and encryption issues"
    }

    async fn scan(
        &self,
        _client: &HttpClient,
        config: &ScanConfig,
        _crawled_urls: &[String],
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let base_url = match Url::parse(&config.target) {
            Ok(u) => u,
            Err(_) => return Ok(findings),
        };

        // Check 1: Discover WebSocket endpoints (with liveness validation)
        let discovered = discover_endpoints(&base_url, config.timeout_secs).await;

        if discovered.is_empty() {
            debug!("No WebSocket endpoints discovered on {}", config.target);
            return Ok(findings);
        }

        let endpoint_list = discovered
            .iter()
            .map(|e| e.as_str())
            .collect::<Vec<&str>>()
            .join("\n");

        findings.push(
            Finding::new(
                "WebSocket Endpoints Discovered",
                "WebSocket endpoints were found on the target.",
                Severity::Info,
                "WebSocket Security",
                &config.target,
            )
            .with_evidence(format!("Discovered endpoints:\n{}", endpoint_list))
            .with_recommendation(
                "Ensure all WebSocket endpoints have proper authentication and authorization.",
            ),
        );

        // Check 2: Origin validation on each discovered endpoint
        for ws_url in &discovered {
            if let Some(finding) = check_origin_validation(ws_url, config.timeout_secs).await {
                findings.push(finding);
            }
        }

        // Check 3: Authentication check
        for ws_url in &discovered {
            if let Some(finding) = check_authentication(ws_url, config.timeout_secs).await {
                findings.push(finding);
            }
        }

        // Check 4: Encryption check
        for ws_url in &discovered {
            if let Some(finding) = check_encryption(ws_url, &base_url, config.timeout_secs).await {
                findings.push(finding);
            }
        }

        Ok(findings)
    }
}

/// Discover WebSocket endpoints by attempting upgrades on common paths.
/// Only reports endpoints where the connection is confirmed as functional.
async fn discover_endpoints(base_url: &Url, timeout_secs: u64) -> Vec<String> {
    let mut discovered = Vec::new();

    let ws_scheme = match base_url.scheme() {
        "https" => "wss",
        _ => "ws",
    };

    let host = match base_url.host_str() {
        Some(h) => h,
        None => return discovered,
    };

    let port = base_url.port_or_known_default().unwrap_or(443);
    let base = format!("{}://{}:{}", ws_scheme, host, port);

    for path in WS_PATHS {
        let ws_url = format!("{}{}", base, path);

        if try_ws_connect_validated(&ws_url, None, timeout_secs).await {
            discovered.push(ws_url);
        }
    }

    discovered
}

/// Build a TLS connector that accepts invalid certs (for scanning purposes)
fn build_tls_connector() -> Option<tokio_tungstenite::Connector> {
    let tls = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .ok()?;
    Some(tokio_tungstenite::Connector::NativeTls(tls))
}

/// Attempt a WebSocket connection and validate it's a real endpoint.
///
/// Validation: after the handshake succeeds, we send a Ping frame and
/// wait briefly for any response (Pong, message, or the connection staying
/// alive). This filters out servers that accept the 101 upgrade on any
/// path but immediately close the connection (reverse proxy catch-all).
async fn try_ws_connect_validated(ws_url: &str, origin: Option<&str>, timeout_secs: u64) -> bool {
    let connect_future = async {
        let mut request = match ws_url.into_client_request() {
            Ok(r) => r,
            Err(_) => return false,
        };

        if let Some(origin_value) = origin {
            if let Ok(val) = HeaderValue::from_str(origin_value) {
                request.headers_mut().insert("Origin", val);
            }
        }

        let connector = if ws_url.starts_with("wss://") {
            build_tls_connector()
        } else {
            None
        };

        let (mut ws_stream, _response) =
            match tokio_tungstenite::connect_async_tls_with_config(request, None, false, connector)
                .await
            {
                Ok(result) => result,
                Err(_) => return false,
            };

        // Handshake succeeded. Now validate the connection is real:
        // Send a Ping and wait for any response within 3 seconds.
        // A real WebSocket server will respond with Pong or keep the
        // connection alive. A fake catch-all will close immediately.

        // Try sending a ping
        let ping_result = ws_stream.send(Message::Ping(vec![1, 2, 3, 4])).await;

        if ping_result.is_err() {
            // Server closed the connection right after handshake — not a real WS endpoint
            debug!(
                "WebSocket at {} closed immediately after handshake (not a real endpoint)",
                ws_url
            );
            return false;
        }

        // Wait briefly for any response (pong, message, or just the connection staying open)
        use futures::StreamExt;
        let wait_result =
            tokio::time::timeout(std::time::Duration::from_secs(3), ws_stream.next()).await;

        match wait_result {
            Ok(Some(Ok(_msg))) => {
                // Got a response (Pong, message, etc.) — confirmed real endpoint
                debug!(
                    "WebSocket at {} confirmed: received response after ping",
                    ws_url
                );
                true
            }
            Ok(Some(Err(_))) => {
                // Error reading — connection was closed or errored
                debug!(
                    "WebSocket at {} closed after ping (likely not a real endpoint)",
                    ws_url
                );
                false
            }
            Ok(None) => {
                // Stream ended — connection closed
                debug!("WebSocket at {} stream ended (not a real endpoint)", ws_url);
                false
            }
            Err(_) => {
                // Timeout waiting for response — the connection stayed open
                // which means it IS a real WebSocket endpoint (it just didn't
                // send any data). This is normal for endpoints waiting for
                // client messages.
                debug!(
                    "WebSocket at {} confirmed: connection stayed alive after ping",
                    ws_url
                );
                true
            }
        }
    };

    tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs.min(10)),
        connect_future,
    )
    .await
    .unwrap_or_default()
}

/// Check if the WebSocket endpoint validates the Origin header
async fn check_origin_validation(ws_url: &str, timeout_secs: u64) -> Option<Finding> {
    let evil_origin = "https://evil.attacker.com";

    if try_ws_connect_validated(ws_url, Some(evil_origin), timeout_secs).await {
        Some(
            Finding::new(
                "WebSocket Origin Validation Bypass",
                "The WebSocket endpoint accepts connections from arbitrary origins, allowing cross-site WebSocket hijacking.",
                Severity::High,
                "WebSocket Security",
                ws_url,
            )
            .with_evidence(format!(
                "WebSocket at {} accepted connection with Origin: {}",
                ws_url, evil_origin
            ))
            .with_recommendation(
                "Implement server-side Origin header validation to only accept connections from trusted domains.",
            )
            .with_cwe("CWE-346")
            .with_owasp("A01:2021 Broken Access Control"),
        )
    } else {
        None
    }
}

/// Check if the WebSocket endpoint requires authentication
async fn check_authentication(ws_url: &str, timeout_secs: u64) -> Option<Finding> {
    // This check is inherent in discovery — if we got here, the endpoint
    // already accepted an unauthenticated connection during discovery.
    // We just need to verify it's still true (it should be).
    if try_ws_connect_validated(ws_url, None, timeout_secs).await {
        Some(
            Finding::new(
                "WebSocket Missing Authentication",
                "The WebSocket endpoint accepts connections without authentication credentials.",
                Severity::Medium,
                "WebSocket Security",
                ws_url,
            )
            .with_evidence(format!(
                "WebSocket at {} accepted unauthenticated connection",
                ws_url
            ))
            .with_recommendation(
                "Require authentication tokens (JWT, session cookies, API keys) for WebSocket connections.",
            )
            .with_cwe("CWE-306")
            .with_owasp("A07:2021 Identification and Authentication Failures"),
        )
    } else {
        None
    }
}

/// Check for encryption issues (ws:// vs wss://)
async fn check_encryption(ws_url: &str, base_url: &Url, timeout_secs: u64) -> Option<Finding> {
    // Only check if the main site uses HTTPS but WS uses ws://
    if base_url.scheme() == "https" && ws_url.starts_with("ws://") {
        return Some(
            Finding::new(
                "WebSocket Unencrypted Connection",
                "The WebSocket endpoint uses unencrypted ws:// while the site uses HTTPS.",
                Severity::Medium,
                "WebSocket Security",
                ws_url,
            )
            .with_evidence(format!(
                "Site uses HTTPS but WebSocket at {} uses unencrypted ws://",
                ws_url
            ))
            .with_recommendation(
                "Use wss:// (WebSocket Secure) for all WebSocket connections on HTTPS sites.",
            )
            .with_cwe("CWE-319")
            .with_owasp("A02:2021 Cryptographic Failures"),
        );
    }

    // Check if wss:// endpoint also accepts ws:// (downgrade)
    if ws_url.starts_with("wss://") {
        let insecure_url = ws_url.replacen("wss://", "ws://", 1);
        if try_ws_connect_validated(&insecure_url, None, timeout_secs).await {
            return Some(
                Finding::new(
                    "WebSocket Encryption Downgrade",
                    "The WebSocket endpoint accepts both encrypted (wss://) and unencrypted (ws://) connections.",
                    Severity::Medium,
                    "WebSocket Security",
                    ws_url,
                )
                .with_evidence(format!(
                    "Endpoint {} also accepts connections on {}",
                    ws_url, insecure_url
                ))
                .with_recommendation(
                    "Disable ws:// and only accept wss:// connections. Redirect ws:// to wss://.",
                )
                .with_cwe("CWE-319")
                .with_owasp("A02:2021 Cryptographic Failures"),
            );
        }
    }

    None
}
