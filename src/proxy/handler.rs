//! HTTP proxy request handler
//!
//! Handles both regular HTTP requests (full capture) and CONNECT tunnels
//! (metadata only for HTTPS).

use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::body::Incoming;
use hyper::header::HOST;
use hyper::{Method, Request, Response};
use std::time::Instant;
use tokio::net::TcpStream;
use tracing::{debug, error};

use super::traffic::{TrafficEntry, TrafficLog};

/// Handle an incoming proxy request
pub async fn handle_request(
    req: Request<Incoming>,
    log: TrafficLog,
) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
    if req.method() == Method::CONNECT {
        handle_connect(req, log).await
    } else {
        handle_http(req, log).await
    }
}

/// Handle a regular HTTP request: forward and capture full request/response
async fn handle_http(
    req: Request<Incoming>,
    log: TrafficLog,
) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
    let start = Instant::now();
    let method = req.method().to_string();
    let uri = req.uri().to_string();

    // Build the target URL
    let url = if uri.starts_with("http://") || uri.starts_with("https://") {
        uri.clone()
    } else {
        // Relative URI — construct from Host header
        let host = req
            .headers()
            .get(HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("localhost");
        format!("http://{}{}", host, uri)
    };

    // Capture request headers
    let request_headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    // Collect request body
    let request_body = match req.collect().await {
        Ok(body) => {
            let bytes = body.to_bytes();
            if bytes.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(&bytes).to_string())
            }
        }
        Err(e) => {
            error!("Failed to read request body: {}", e);
            None
        }
    };

    // Forward the request using reqwest
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let mut forward = client.request(
        reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET),
        &url,
    );

    for (k, v) in &request_headers {
        if k.to_lowercase() != "host" && k.to_lowercase() != "proxy-connection" {
            forward = forward.header(k.as_str(), v.as_str());
        }
    }

    if let Some(ref body) = request_body {
        forward = forward.body(body.clone());
    }

    match forward.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let response_headers: Vec<(String, String)> = resp
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();

            let response_body_bytes = resp.bytes().await.unwrap_or_default();
            let response_size = response_body_bytes.len() as u64;
            let response_body = String::from_utf8_lossy(&response_body_bytes).to_string();

            let elapsed = start.elapsed().as_millis() as u64;

            log.add(TrafficEntry {
                id: 0,
                started_at: Utc::now(),
                method,
                url,
                request_headers,
                request_body,
                status_code: Some(status),
                response_headers: response_headers.clone(),
                response_body: Some(response_body.clone()),
                response_size,
                elapsed_ms: elapsed,
                is_tunnel: false,
            });

            // Build response to send back to the client
            let mut builder = Response::builder().status(status);
            for (k, v) in &response_headers {
                builder = builder.header(k.as_str(), v.as_str());
            }

            Ok(builder
                .body(Full::new(response_body_bytes))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("Proxy Error")))))
        }
        Err(e) => {
            error!("Failed to forward request to {}: {}", url, e);
            Ok(Response::builder()
                .status(502)
                .body(Full::new(Bytes::from(format!("Bad Gateway: {}", e))))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("Bad Gateway")))))
        }
    }
}

/// Handle a CONNECT request: establish a TCP tunnel (HTTPS metadata only)
async fn handle_connect(
    req: Request<Incoming>,
    log: TrafficLog,
) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
    let start = Instant::now();
    let target = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_default();

    debug!("CONNECT tunnel to {}", target);

    // Log the CONNECT as metadata only
    log.add(TrafficEntry {
        id: 0,
        started_at: Utc::now(),
        method: "CONNECT".to_string(),
        url: format!("https://{}", target),
        request_headers: req
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect(),
        request_body: None,
        status_code: None,
        response_headers: Vec::new(),
        response_body: None,
        response_size: 0,
        elapsed_ms: start.elapsed().as_millis() as u64,
        is_tunnel: true,
    });

    // Spawn the tunnel in a background task
    tokio::task::spawn(async move {
        match TcpStream::connect(&target).await {
            Ok(mut upstream) => {
                // Upgrade the connection
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        let mut upgraded = hyper_util::rt::TokioIo::new(upgraded);
                        let (mut client_read, mut client_write) = tokio::io::split(&mut upgraded);
                        let (mut server_read, mut server_write) = tokio::io::split(&mut upstream);

                        let client_to_server = tokio::io::copy(&mut client_read, &mut server_write);
                        let server_to_client = tokio::io::copy(&mut server_read, &mut client_write);

                        let _ = tokio::try_join!(client_to_server, server_to_client);
                    }
                    Err(e) => {
                        error!("CONNECT upgrade failed: {}", e);
                    }
                }
            }
            Err(e) => {
                error!("Failed to connect to {}: {}", target, e);
            }
        }
    });

    // Send 200 Connection Established
    Ok(Response::builder()
        .status(200)
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))))
}
