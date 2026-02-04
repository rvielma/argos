//! HTTP/HTTPS intercept proxy
//!
//! Captures HTTP traffic passing through the proxy for analysis.
//! HTTP requests are fully captured (request + response).
//! HTTPS connections are logged as metadata only (CONNECT tunnels).

pub mod handler;
pub mod har;
pub mod traffic;

use crate::error::{ArgosError, Result};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::path::Path;
use tokio::net::TcpListener;
use tracing::{debug, error, info};

use self::traffic::TrafficLog;

/// Intercept proxy server
pub struct InterceptProxy {
    port: u16,
    output_path: String,
    target_filter: Option<String>,
}

impl InterceptProxy {
    /// Create a new proxy with the given configuration
    pub fn new(port: u16, output_path: String, target_filter: Option<String>) -> Self {
        Self {
            port,
            output_path,
            target_filter,
        }
    }

    /// Start the proxy server. Blocks until Ctrl+C.
    pub async fn start(&self) -> Result<()> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| ArgosError::ProxyError(format!("Failed to bind to {}: {}", addr, e)))?;

        let log = TrafficLog::new(self.target_filter.clone());
        let output_path = self.output_path.clone();

        info!("Proxy listening on http://{}", addr);
        info!("Traffic will be saved to: {}", output_path);
        if let Some(ref target) = self.target_filter {
            info!("Filtering traffic for: {}", target);
        }

        // Handle Ctrl+C gracefully
        let log_for_shutdown = log.clone();
        let output_for_shutdown = output_path.clone();
        tokio::spawn(async move {
            if let Err(e) = tokio::signal::ctrl_c().await {
                error!("Failed to listen for ctrl+c: {}", e);
                return;
            }
            info!("Shutting down proxy...");

            let entries = log_for_shutdown.entries();
            info!("Captured {} traffic entries", entries.len());

            if !entries.is_empty() {
                let path = Path::new(&output_for_shutdown);
                match har::export_har(&entries, path) {
                    Ok(()) => info!("Traffic exported to {}", output_for_shutdown),
                    Err(e) => error!("Failed to export HAR: {}", e),
                }
            }

            std::process::exit(0);
        });

        loop {
            let (stream, client_addr) = listener
                .accept()
                .await
                .map_err(|e| ArgosError::ProxyError(format!("Accept failed: {}", e)))?;

            let io = TokioIo::new(stream);
            let log = log.clone();

            debug!("New connection from {}", client_addr);

            tokio::task::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let log = log.clone();
                    handler::handle_request(req, log)
                });

                if let Err(e) = http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .serve_connection(io, service)
                    .with_upgrades()
                    .await
                {
                    // Connection closed errors are normal, only log real errors
                    let err_str = e.to_string();
                    if !err_str.contains("connection closed") && !err_str.contains("early eof") {
                        debug!("Connection error from {}: {}", client_addr, e);
                    }
                }
            });
        }
    }
}
