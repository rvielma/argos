//! Authentication support for authenticated scanning

use crate::error::{ArgosError, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::info;

/// Authentication configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum AuthConfig {
    /// No authentication
    #[default]
    None,
    /// Form-based authentication (POST to login URL)
    FormBased {
        login_url: String,
        username: String,
        password: String,
    },
    /// Bearer token authentication
    BearerToken { token: String },
    /// Cookie-based authentication (inject raw cookies)
    CookieBased { cookies: String },
}

/// Holds authentication session state (cookies or headers to inject)
#[derive(Debug, Clone)]
pub struct AuthSession {
    pub auth_headers: HashMap<String, String>,
}

impl AuthSession {
    /// Performs authentication and returns a session
    pub async fn authenticate(config: &AuthConfig, timeout_secs: u64) -> Result<Self> {
        match config {
            AuthConfig::None => Ok(Self {
                auth_headers: HashMap::new(),
            }),

            AuthConfig::BearerToken { token } => {
                info!("Using bearer token authentication");
                let mut headers = HashMap::new();
                headers.insert("Authorization".to_string(), format!("Bearer {token}"));
                Ok(Self {
                    auth_headers: headers,
                })
            }

            AuthConfig::CookieBased { cookies } => {
                info!("Using cookie-based authentication");
                let mut headers = HashMap::new();
                headers.insert("Cookie".to_string(), cookies.clone());
                Ok(Self {
                    auth_headers: headers,
                })
            }

            AuthConfig::FormBased {
                login_url,
                username,
                password,
            } => {
                info!("Performing form-based authentication to {login_url}");
                let client = Client::builder()
                    .timeout(Duration::from_secs(timeout_secs))
                    .cookie_store(true)
                    .danger_accept_invalid_certs(false)
                    .build()
                    .map_err(ArgosError::HttpError)?;

                let response = client
                    .post(login_url)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(format!("username={username}&password={password}"))
                    .send()
                    .await
                    .map_err(ArgosError::HttpError)?;

                let mut headers = HashMap::new();

                // Extract Set-Cookie headers from the login response
                let cookies: Vec<String> = response
                    .headers()
                    .get_all("set-cookie")
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .map(|cookie| {
                        // Extract just the cookie name=value part
                        cookie
                            .split(';')
                            .next()
                            .unwrap_or(cookie)
                            .trim()
                            .to_string()
                    })
                    .collect();

                if !cookies.is_empty() {
                    headers.insert("Cookie".to_string(), cookies.join("; "));
                    info!(
                        "Form authentication successful, captured {} cookies",
                        cookies.len()
                    );
                } else {
                    return Err(ArgosError::ConfigError(
                        "Form authentication did not return any cookies".to_string(),
                    ));
                }

                Ok(Self {
                    auth_headers: headers,
                })
            }
        }
    }
}
