//! Minimal SMTP callback server for OOB interaction detection
//!
//! Implements just enough SMTP to receive emails and extract interaction IDs
//! from the RCPT TO local-part.

use super::{Interaction, InteractionStore, InteractionType};
use std::net::SocketAddr;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::debug;

/// Starts the OOB SMTP callback server
pub async fn start_smtp_server(
    port: u16,
    store: InteractionStore,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    debug!("OOB SMTP server listening on {}", addr);

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        let store = store.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_smtp_session(stream, remote_addr, store).await {
                debug!("OOB SMTP session error from {}: {}", remote_addr, e);
            }
        });
    }
}

async fn handle_smtp_session(
    stream: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    store: InteractionStore,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let mut interaction_id: Option<String> = None;
    let mut raw_lines: Vec<String> = Vec::new();

    // Send banner
    writer
        .write_all(b"220 argos SMTP OOB listener ready\r\n")
        .await?;

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }

        let trimmed = line.trim().to_uppercase();
        raw_lines.push(line.trim().to_string());

        if trimmed.starts_with("EHLO") || trimmed.starts_with("HELO") {
            writer
                .write_all(b"250 argos Hello\r\n")
                .await?;
        } else if trimmed.starts_with("MAIL FROM") {
            writer.write_all(b"250 OK\r\n").await?;
        } else if trimmed.starts_with("RCPT TO") {
            // Extract interaction ID from local-part: RCPT TO:<id@whatever>
            if let Some(id) = extract_id_from_rcpt(&line) {
                interaction_id = Some(id);
            }
            writer.write_all(b"250 OK\r\n").await?;
        } else if trimmed.starts_with("DATA") {
            writer
                .write_all(b"354 Send data, end with <CRLF>.<CRLF>\r\n")
                .await?;
            // Read until lone dot
            loop {
                line.clear();
                let n = reader.read_line(&mut line).await?;
                if n == 0 {
                    break;
                }
                raw_lines.push(line.trim().to_string());
                if line.trim() == "." {
                    break;
                }
            }
            writer.write_all(b"250 OK\r\n").await?;
        } else if trimmed.starts_with("QUIT") {
            writer.write_all(b"221 Bye\r\n").await?;
            break;
        } else if trimmed.starts_with("RSET") || trimmed.starts_with("NOOP") {
            writer.write_all(b"250 OK\r\n").await?;
        } else {
            writer.write_all(b"500 Unrecognized command\r\n").await?;
        }
    }

    // Record interaction if we got an ID
    if let Some(id) = interaction_id {
        debug!("OOB SMTP interaction: {} from {}", id, remote_addr);

        let interaction = Interaction {
            id: id.clone(),
            interaction_type: InteractionType::Smtp,
            remote_addr,
            timestamp: chrono::Utc::now(),
            raw_data: raw_lines.join("\n"),
        };

        let mut s = store.lock().await;
        s.entry(id).or_default().push(interaction);
    }

    Ok(())
}

/// Extracts the interaction ID from a RCPT TO line
/// Expected format: RCPT TO:<interaction_id@domain> or RCPT TO:<interaction_id>
fn extract_id_from_rcpt(line: &str) -> Option<String> {
    let lower = line.to_lowercase();
    let start = lower.find('<')?;
    let end = lower.find('>')?;
    if start >= end {
        return None;
    }
    let addr = &line[start + 1..end];
    // Take local-part (before @)
    let local = if let Some(at_pos) = addr.find('@') {
        &addr[..at_pos]
    } else {
        addr
    };

    if local.is_empty() {
        None
    } else {
        Some(local.to_string())
    }
}
