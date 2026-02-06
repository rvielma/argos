//! Minimal FTP callback server for OOB interaction detection
//!
//! Implements just enough FTP to accept connections and extract interaction IDs
//! from the USER command.

use super::{Interaction, InteractionStore, InteractionType};
use std::net::SocketAddr;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::debug;

/// Starts the OOB FTP callback server
pub async fn start_ftp_server(
    port: u16,
    store: InteractionStore,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    debug!("OOB FTP server listening on {}", addr);

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        let store = store.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_ftp_session(stream, remote_addr, store).await {
                debug!("OOB FTP session error from {}: {}", remote_addr, e);
            }
        });
    }
}

async fn handle_ftp_session(
    stream: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    store: InteractionStore,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let mut interaction_id: Option<String> = None;
    let mut raw_lines: Vec<String> = Vec::new();

    // Send FTP banner
    writer
        .write_all(b"220 argos FTP OOB listener ready\r\n")
        .await?;

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }

        let trimmed = line.trim();
        raw_lines.push(trimmed.to_string());
        let upper = trimmed.to_uppercase();

        if upper.starts_with("USER ") {
            // Extract interaction ID from username
            let username = trimmed[5..].trim();
            if !username.is_empty() {
                interaction_id = Some(username.to_string());
            }
            writer
                .write_all(b"331 User name okay, need password\r\n")
                .await?;
        } else if upper.starts_with("PASS ") {
            writer.write_all(b"230 User logged in\r\n").await?;
        } else if upper.starts_with("QUIT") {
            writer.write_all(b"221 Goodbye\r\n").await?;
            break;
        } else if upper.starts_with("SYST") {
            writer.write_all(b"215 UNIX Type: L8\r\n").await?;
        } else if upper.starts_with("TYPE") {
            writer.write_all(b"200 Type set\r\n").await?;
        } else if upper.starts_with("PWD") {
            writer.write_all(b"257 \"/\" is current directory\r\n").await?;
        } else {
            writer.write_all(b"502 Command not implemented\r\n").await?;
        }
    }

    // Record interaction if we got an ID
    if let Some(id) = interaction_id {
        debug!("OOB FTP interaction: {} from {}", id, remote_addr);

        let interaction = Interaction {
            id: id.clone(),
            interaction_type: InteractionType::Ftp,
            remote_addr,
            timestamp: chrono::Utc::now(),
            raw_data: raw_lines.join("\n"),
        };

        let mut s = store.lock().await;
        s.entry(id).or_default().push(interaction);
    }

    Ok(())
}
