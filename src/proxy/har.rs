//! HAR 1.2 export for captured traffic
//!
//! Generates HTTP Archive format compatible with Chrome DevTools,
//! Firefox HAR Viewer, and other analysis tools.

use crate::error::Result;
use serde::Serialize;
use std::path::Path;

use super::traffic::TrafficEntry;

/// HAR 1.2 root structure
#[derive(Serialize)]
struct Har {
    log: HarLog,
}

#[derive(Serialize)]
struct HarLog {
    version: String,
    creator: HarCreator,
    entries: Vec<HarEntry>,
}

#[derive(Serialize)]
struct HarCreator {
    name: String,
    version: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HarEntry {
    started_date_time: String,
    time: f64,
    request: HarRequest,
    response: HarResponse,
    cache: HarCache,
    timings: HarTimings,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HarRequest {
    method: String,
    url: String,
    http_version: String,
    headers: Vec<HarHeader>,
    query_string: Vec<HarQueryParam>,
    body_size: i64,
    headers_size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    post_data: Option<HarPostData>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HarResponse {
    status: u16,
    status_text: String,
    http_version: String,
    headers: Vec<HarHeader>,
    content: HarContent,
    redirect_url: String,
    body_size: i64,
    headers_size: i64,
}

#[derive(Serialize)]
struct HarHeader {
    name: String,
    value: String,
}

#[derive(Serialize)]
struct HarQueryParam {
    name: String,
    value: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HarPostData {
    mime_type: String,
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HarContent {
    size: i64,
    mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
}

#[derive(Serialize)]
struct HarCache {}

#[derive(Serialize)]
struct HarTimings {
    send: f64,
    wait: f64,
    receive: f64,
}

/// Export traffic entries to HAR 1.2 format
pub fn export_har(entries: &[TrafficEntry], output_path: &Path) -> Result<()> {
    let har_entries: Vec<HarEntry> = entries.iter().map(traffic_to_har_entry).collect();

    let har = Har {
        log: HarLog {
            version: "1.2".to_string(),
            creator: HarCreator {
                name: "Argos Panoptes".to_string(),
                version: "0.1.0".to_string(),
            },
            entries: har_entries,
        },
    };

    let json = serde_json::to_string_pretty(&har)?;
    std::fs::write(output_path, json)?;

    Ok(())
}

fn traffic_to_har_entry(entry: &TrafficEntry) -> HarEntry {
    let request_headers: Vec<HarHeader> = entry
        .request_headers
        .iter()
        .map(|(k, v)| HarHeader {
            name: k.clone(),
            value: v.clone(),
        })
        .collect();

    let response_headers: Vec<HarHeader> = entry
        .response_headers
        .iter()
        .map(|(k, v)| HarHeader {
            name: k.clone(),
            value: v.clone(),
        })
        .collect();

    let content_type = entry
        .response_headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == "content-type")
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let post_data = entry.request_body.as_ref().map(|body| HarPostData {
        mime_type: entry
            .request_headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "content-type")
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| "application/x-www-form-urlencoded".to_string()),
        text: body.clone(),
    });

    let body_size = entry
        .request_body
        .as_ref()
        .map(|b| b.len() as i64)
        .unwrap_or(-1);

    let status = entry.status_code.unwrap_or(0);
    let status_text = status_to_text(status);

    let elapsed = entry.elapsed_ms as f64;

    HarEntry {
        started_date_time: entry.started_at.to_rfc3339(),
        time: elapsed,
        request: HarRequest {
            method: entry.method.clone(),
            url: entry.url.clone(),
            http_version: "HTTP/1.1".to_string(),
            headers: request_headers,
            query_string: Vec::new(),
            body_size,
            headers_size: -1,
            post_data,
        },
        response: HarResponse {
            status,
            status_text,
            http_version: "HTTP/1.1".to_string(),
            headers: response_headers,
            content: HarContent {
                size: entry.response_size as i64,
                mime_type: content_type,
                text: entry.response_body.clone(),
            },
            redirect_url: String::new(),
            body_size: entry.response_size as i64,
            headers_size: -1,
        },
        cache: HarCache {},
        timings: HarTimings {
            send: 0.0,
            wait: elapsed,
            receive: 0.0,
        },
    }
}

fn status_to_text(status: u16) -> String {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        0 => "CONNECT Tunnel",
        _ => "Unknown",
    }
    .to_string()
}
