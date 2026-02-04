//! Out-of-Band (OOB) testing infrastructure
//!
//! Provides embedded HTTP and DNS callback servers for detecting blind
//! vulnerabilities (SSRF, XXE, blind SQLi, etc.) through out-of-band interactions.

pub mod dns_server;
pub mod http_server;
pub mod payloads;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

/// Represents a detected out-of-band interaction
#[derive(Debug, Clone)]
pub struct Interaction {
    /// Unique interaction ID (links back to the payload)
    pub id: String,
    /// Type of interaction
    pub interaction_type: InteractionType,
    /// Remote address that made the request
    pub remote_addr: SocketAddr,
    /// Timestamp of the interaction
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Raw request data
    pub raw_data: String,
}

/// Type of OOB interaction
#[derive(Debug, Clone)]
pub enum InteractionType {
    Http,
    Dns,
}

/// Thread-safe store for received interactions
pub type InteractionStore = Arc<Mutex<HashMap<String, Vec<Interaction>>>>;

/// Creates a new empty interaction store
pub fn new_interaction_store() -> InteractionStore {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Generates a unique interaction ID (12 char hex)
pub fn generate_id() -> String {
    let id = uuid::Uuid::new_v4();
    let hex = format!("{:x}", id.as_u128());
    hex[..12].to_string()
}

/// OOB server managing HTTP and DNS callback listeners
pub struct OobServer {
    pub callback_host: String,
    pub http_port: u16,
    pub dns_port: u16,
    pub store: InteractionStore,
}

impl OobServer {
    /// Creates a new OOB server configuration
    pub fn new(callback_host: String, http_port: u16, dns_port: u16) -> Self {
        Self {
            callback_host,
            http_port,
            dns_port,
            store: new_interaction_store(),
        }
    }

    /// Starts the HTTP and DNS callback servers as background tasks
    pub async fn start(&self) -> crate::error::Result<()> {
        info!(
            "Starting OOB servers: HTTP on :{}, DNS on :{}",
            self.http_port, self.dns_port
        );

        let http_store = Arc::clone(&self.store);
        let http_port = self.http_port;
        tokio::spawn(async move {
            if let Err(e) = http_server::start_http_server(http_port, http_store).await {
                tracing::error!("OOB HTTP server error: {}", e);
            }
        });

        let dns_store = Arc::clone(&self.store);
        let dns_port = self.dns_port;
        tokio::spawn(async move {
            if let Err(e) = dns_server::start_dns_server(dns_port, dns_store).await {
                tracing::error!("OOB DNS server error: {}", e);
            }
        });

        // Give servers a moment to bind
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        Ok(())
    }

    /// Constructs a callback URL for a given interaction ID
    pub fn callback_url(&self, id: &str) -> String {
        format!("http://{}:{}/{}", self.callback_host, self.http_port, id)
    }

    /// Constructs a callback DNS name for a given interaction ID
    pub fn callback_dns(&self, id: &str) -> String {
        format!("{}.{}", id, self.callback_host)
    }

    /// Waits for an interaction with the given ID, up to timeout_secs
    pub async fn check_interaction(
        &self,
        id: &str,
        timeout_secs: u64,
    ) -> Option<Vec<Interaction>> {
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        let poll_interval = std::time::Duration::from_millis(500);

        loop {
            {
                let store = self.store.lock().await;
                if let Some(interactions) = store.get(id) {
                    if !interactions.is_empty() {
                        return Some(interactions.clone());
                    }
                }
            }

            if tokio::time::Instant::now() >= deadline {
                return None;
            }

            tokio::time::sleep(poll_interval).await;
        }
    }
}
