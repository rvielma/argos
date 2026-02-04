//! HTTP client module for Argos scanner

pub mod auth;
pub mod client;
pub use auth::{AuthConfig, AuthSession};
pub use client::HttpClient;
