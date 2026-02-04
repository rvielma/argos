//! Error types for Argos scanner

use thiserror::Error;

/// Main error type for Argos operations
#[derive(Debug, Error)]
pub enum ArgosError {
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("URL parse error: {0}")]
    UrlError(#[from] url::ParseError),

    #[error("TLS error: {0}")]
    TlsError(#[from] native_tls::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Template error: {0}")]
    TemplateError(#[from] tera::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("TOML parse error: {0}")]
    TomlError(#[from] toml::de::Error),

    #[error("YAML parse error: {0}")]
    YamlError(#[from] serde_yaml::Error),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Scanner error: {0}")]
    ScanError(String),

    #[error("Module '{0}' not found")]
    ModuleNotFound(String),

    #[error("Target unreachable: {0}")]
    TargetUnreachable(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Scan timeout after {0} seconds")]
    ScanTimeout(u64),

    #[error("WebSocket error: {0}")]
    WebSocketError(String),

    #[error("Template validation error in '{0}': {1}")]
    TemplateValidationError(String, String),

    #[error("Proxy error: {0}")]
    ProxyError(String),

    #[error("OOB error: {0}")]
    OobError(String),
}

/// Result type alias for Argos operations
pub type Result<T> = std::result::Result<T, ArgosError>;
