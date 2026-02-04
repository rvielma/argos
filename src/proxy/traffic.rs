//! Traffic logging for the intercept proxy

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::sync::{Arc, Mutex};

/// A single captured HTTP transaction
#[derive(Debug, Clone, Serialize)]
pub struct TrafficEntry {
    /// Unique entry ID
    pub id: u64,
    /// Timestamp of the request
    pub started_at: DateTime<Utc>,
    /// Request method
    pub method: String,
    /// Full request URL
    pub url: String,
    /// Request headers
    pub request_headers: Vec<(String, String)>,
    /// Request body (if captured)
    pub request_body: Option<String>,
    /// Response status code (None for CONNECT tunnels)
    pub status_code: Option<u16>,
    /// Response headers
    pub response_headers: Vec<(String, String)>,
    /// Response body (if captured)
    pub response_body: Option<String>,
    /// Response body size in bytes
    pub response_size: u64,
    /// Total time in milliseconds
    pub elapsed_ms: u64,
    /// Whether this is a CONNECT tunnel (HTTPS metadata only)
    pub is_tunnel: bool,
}

/// Thread-safe traffic log
#[derive(Debug, Clone)]
pub struct TrafficLog {
    entries: Arc<Mutex<Vec<TrafficEntry>>>,
    counter: Arc<Mutex<u64>>,
    target_filter: Option<String>,
}

impl TrafficLog {
    /// Create a new empty traffic log
    pub fn new(target_filter: Option<String>) -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
            counter: Arc::new(Mutex::new(0)),
            target_filter,
        }
    }

    /// Add a new entry to the log, returns the entry ID
    pub fn add(&self, mut entry: TrafficEntry) -> u64 {
        // Apply target filter if set
        if let Some(ref filter) = self.target_filter {
            if !entry.url.contains(filter) && !entry.method.eq_ignore_ascii_case("CONNECT") {
                return 0;
            }
            if entry.method.eq_ignore_ascii_case("CONNECT") && !entry.url.contains(filter) {
                return 0;
            }
        }

        let mut counter = self.counter.lock().unwrap_or_else(|e| e.into_inner());
        *counter += 1;
        entry.id = *counter;
        let id = entry.id;

        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.push(entry);
        id
    }

    /// Get all entries
    pub fn entries(&self) -> Vec<TrafficEntry> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.clone()
    }

    /// Get the total number of entries
    pub fn len(&self) -> usize {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.len()
    }

    /// Check if the log is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
