//! Minimal DNS callback server for OOB interaction detection
//!
//! Listens for DNS queries on a UDP port, extracts interaction IDs
//! from the first label of the queried name, and responds with 127.0.0.1.

use super::{Interaction, InteractionStore, InteractionType};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tracing::debug;

/// Starts the OOB DNS callback server
pub async fn start_dns_server(
    port: u16,
    store: InteractionStore,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let socket = UdpSocket::bind(addr).await?;
    debug!("OOB DNS server listening on {}", addr);

    let mut buf = [0u8; 512];

    loop {
        let (len, remote_addr) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                debug!("DNS recv error: {}", e);
                continue;
            }
        };

        if len < 12 {
            continue;
        }

        let data = &buf[..len];

        // Parse the query name from the DNS packet
        if let Some(name) = parse_dns_name(data) {
            // The interaction ID is the first label
            let interaction_id = name
                .split('.')
                .next()
                .unwrap_or("")
                .to_string();

            if !interaction_id.is_empty() {
                debug!(
                    "OOB DNS interaction: {} (query: {}) from {}",
                    interaction_id, name, remote_addr
                );

                let interaction = Interaction {
                    id: interaction_id.clone(),
                    interaction_type: InteractionType::Dns,
                    remote_addr,
                    timestamp: chrono::Utc::now(),
                    raw_data: format!("DNS query for {}", name),
                };

                let mut s = store.lock().await;
                s.entry(interaction_id).or_default().push(interaction);
            }

            // Send a minimal DNS response with A record 127.0.0.1
            let response = build_dns_response(data);
            let _ = socket.send_to(&response, remote_addr).await;
        }
    }
}

/// Parses the query name from a raw DNS packet
fn parse_dns_name(data: &[u8]) -> Option<String> {
    // DNS header is 12 bytes, question section starts at offset 12
    let mut offset = 12;
    let mut labels = Vec::new();

    loop {
        if offset >= data.len() {
            return None;
        }

        let label_len = data[offset] as usize;
        if label_len == 0 {
            break;
        }

        offset += 1;
        if offset + label_len > data.len() {
            return None;
        }

        let label = String::from_utf8_lossy(&data[offset..offset + label_len]).to_string();
        labels.push(label);
        offset += label_len;
    }

    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

/// Builds a minimal DNS response with A record 127.0.0.1
fn build_dns_response(query: &[u8]) -> Vec<u8> {
    let mut response = Vec::with_capacity(query.len() + 16);

    // Copy the transaction ID
    if query.len() >= 2 {
        response.extend_from_slice(&query[..2]);
    } else {
        response.extend_from_slice(&[0, 0]);
    }

    // Flags: standard response, no error
    response.extend_from_slice(&[0x81, 0x80]);

    // Questions: 1, Answers: 1, Authority: 0, Additional: 0
    response.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);

    // Copy the question section
    if query.len() > 12 {
        let mut offset = 12;
        // Skip name
        while offset < query.len() {
            let label_len = query[offset] as usize;
            if label_len == 0 {
                offset += 1;
                break;
            }
            offset += 1 + label_len;
        }
        // Skip QTYPE and QCLASS (4 bytes)
        offset += 4;

        // Copy question from query
        response.extend_from_slice(&query[12..offset.min(query.len())]);

        // Answer section: pointer to name in question
        response.extend_from_slice(&[0xC0, 0x0C]); // Name pointer to offset 12
        response.extend_from_slice(&[0, 1]); // Type A
        response.extend_from_slice(&[0, 1]); // Class IN
        response.extend_from_slice(&[0, 0, 0, 60]); // TTL 60 seconds
        response.extend_from_slice(&[0, 4]); // RDLENGTH 4
        response.extend_from_slice(&[127, 0, 0, 1]); // 127.0.0.1
    }

    response
}
