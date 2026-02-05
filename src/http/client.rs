//! HTTP client wrapper with rate limiting, retries, and request tracking

use crate::error::{ArgosError, Result};
use crate::http::auth::AuthSession;
use crate::models::ScanConfig;
use reqwest::{Client, Response, StatusCode};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::sleep;
use tracing::{debug, warn};

/// HTTP client wrapper with rate limiting and request counting
#[derive(Clone)]
pub struct HttpClient {
    client: Client,
    request_count: Arc<AtomicU64>,
    rate_limiter: Option<Arc<Semaphore>>,
    rate_limit_delay: Option<Duration>,
    auth_headers: HashMap<String, String>,
}

impl HttpClient {
    /// Creates a new HttpClient from scan configuration
    pub async fn from_config(config: &ScanConfig) -> Result<Self> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .user_agent(&config.user_agent)
            .redirect(if config.follow_redirects {
                reqwest::redirect::Policy::limited(10)
            } else {
                reqwest::redirect::Policy::none()
            })
            .cookie_store(true)
            .danger_accept_invalid_certs(false);

        if let Some(ref proxy_url) = config.proxy {
            let proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|e| ArgosError::ConfigError(format!("Invalid proxy URL: {e}")))?;
            builder = builder.proxy(proxy);
        }

        let client = builder.build()?;

        let (rate_limiter, rate_limit_delay) = if let Some(rps) = config.rate_limit {
            if rps > 0 {
                (
                    Some(Arc::new(Semaphore::new(rps as usize))),
                    Some(Duration::from_millis(1000 / u64::from(rps))),
                )
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        // Authenticate if configured
        let auth_session = AuthSession::authenticate(&config.auth, config.timeout_secs).await?;

        Ok(Self {
            client,
            request_count: Arc::new(AtomicU64::new(0)),
            rate_limiter,
            rate_limit_delay,
            auth_headers: auth_session.auth_headers,
        })
    }

    /// Creates a copy of this client without authentication headers.
    /// Useful for testing access control — requests made with this client
    /// will not include any auth tokens/cookies.
    pub fn without_auth(&self) -> Self {
        Self {
            client: self.client.clone(),
            request_count: Arc::clone(&self.request_count),
            rate_limiter: self.rate_limiter.clone(),
            rate_limit_delay: self.rate_limit_delay,
            auth_headers: HashMap::new(),
        }
    }

    /// Sends a GET request with rate limiting and retry logic
    pub async fn get(&self, url: &str) -> Result<Response> {
        self.request_with_retry(|| self.client.get(url)).await
    }

    /// Sends a GET request with custom headers
    pub async fn get_with_headers(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<Response> {
        self.request_with_retry(|| {
            let mut req = self.client.get(url);
            for (key, value) in headers {
                req = req.header(key.as_str(), value.as_str());
            }
            req
        })
        .await
    }

    /// Sends a POST request with a body
    pub async fn post(&self, url: &str, body: &str) -> Result<Response> {
        self.request_with_retry(|| {
            self.client
                .post(url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(body.to_string())
        })
        .await
    }

    /// Sends a POST request with custom headers and a body
    pub async fn post_with_headers(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &str,
    ) -> Result<Response> {
        self.request_with_retry(|| {
            let mut req = self.client.post(url);
            for (key, value) in headers {
                req = req.header(key.as_str(), value.as_str());
            }
            req.body(body.to_string())
        })
        .await
    }

    /// Sends a generic request with a given method, optional headers and body
    pub async fn request(
        &self,
        method: reqwest::Method,
        url: &str,
        headers: &[(String, String)],
        body: Option<&str>,
    ) -> Result<Response> {
        self.request_with_retry(|| {
            let mut req = self.client.request(method.clone(), url);
            for (key, value) in headers {
                req = req.header(key.as_str(), value.as_str());
            }
            if let Some(b) = body {
                req = req.body(b.to_string());
            }
            req
        })
        .await
    }

    /// Sends an OPTIONS request
    pub async fn options(&self, url: &str) -> Result<Response> {
        self.request(reqwest::Method::OPTIONS, url, &[], None)
            .await
    }

    /// Returns the total number of requests made
    pub fn request_count(&self) -> u64 {
        self.request_count.load(Ordering::Relaxed)
    }

    /// Executes a request with retry logic and rate limiting
    async fn request_with_retry<F>(&self, build_request: F) -> Result<Response>
    where
        F: Fn() -> reqwest::RequestBuilder,
    {
        const MAX_RETRIES: u32 = 2;
        const INITIAL_BACKOFF_MS: u64 = 500;

        // Apply rate limiting via simple delay
        if let Some(delay) = self.rate_limit_delay {
            if let Some(ref limiter) = self.rate_limiter {
                let _permit = limiter
                    .acquire()
                    .await
                    .map_err(|_| ArgosError::RateLimitExceeded)?;
            }
            sleep(delay).await;
        }

        let mut last_error = None;

        for attempt in 0..MAX_RETRIES {
            if attempt > 0 {
                let backoff = Duration::from_millis(INITIAL_BACKOFF_MS * 2u64.pow(attempt - 1));
                debug!("Retry attempt {attempt}, waiting {backoff:?}");
                sleep(backoff).await;
            }

            self.request_count.fetch_add(1, Ordering::Relaxed);

            let mut req = build_request();
            for (key, value) in &self.auth_headers {
                req = req.header(key.as_str(), value.as_str());
            }

            match req.send().await {
                Ok(response) => {
                    let status = response.status();
                    debug!("Response: {status} for {}", response.url());

                    if status == StatusCode::TOO_MANY_REQUESTS {
                        warn!("Rate limited by server, backing off");
                        last_error = Some(ArgosError::RateLimitExceeded);
                        continue;
                    }

                    return Ok(response);
                }
                Err(e) => {
                    warn!("Request failed (attempt {attempt}): {e}");
                    last_error = Some(ArgosError::HttpError(e));
                }
            }
        }

        Err(last_error.unwrap_or_else(|| ArgosError::ScanError("Max retries exceeded".to_string())))
    }
}
