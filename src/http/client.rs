//! HTTP client wrapper with rate limiting, retries, and request tracking

use crate::error::{ArgosError, Result};
use crate::http::auth::AuthSession;
use crate::models::ScanConfig;
use reqwest::{Client, Response, StatusCode};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::sleep;
use tracing::{debug, warn};

/// Adaptive rate limiting state shared across cloned clients
#[derive(Debug, Default)]
struct AdaptiveState {
    /// Consecutive 429 responses
    consecutive_429s: u32,
    /// Current adaptive delay in ms (grows exponentially on 429, shrinks on success)
    current_delay_ms: u64,
    /// Whether a WAF block was detected (403 with known WAF body)
    waf_detected: bool,
    /// Last Retry-After value from server (seconds)
    last_retry_after: Option<u64>,
}

/// HTTP client wrapper with rate limiting and request counting
#[derive(Clone)]
pub struct HttpClient {
    client: Client,
    request_count: Arc<AtomicU64>,
    rate_limiter: Option<Arc<Semaphore>>,
    rate_limit_delay: Option<Duration>,
    auth_headers: HashMap<String, String>,
    adaptive: Arc<Mutex<AdaptiveState>>,
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
            adaptive: Arc::new(Mutex::new(AdaptiveState::default())),
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
            adaptive: Arc::clone(&self.adaptive),
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

    /// Parses the Retry-After header value as seconds
    fn parse_retry_after(value: &str) -> Option<u64> {
        // Try as integer seconds first
        if let Ok(secs) = value.trim().parse::<u64>() {
            return Some(secs.min(30));
        }
        // Try as HTTP-date (just use a reasonable default)
        if value.contains(',') || value.contains("GMT") {
            return Some(5);
        }
        None
    }

    /// Executes a request with retry logic, rate limiting, and adaptive backoff
    async fn request_with_retry<F>(&self, build_request: F) -> Result<Response>
    where
        F: Fn() -> reqwest::RequestBuilder,
    {
        const MAX_RETRIES: u32 = 3;
        const INITIAL_BACKOFF_MS: u64 = 500;

        // Apply configured rate limiting
        if let Some(delay) = self.rate_limit_delay {
            if let Some(ref limiter) = self.rate_limiter {
                let _permit = limiter
                    .acquire()
                    .await
                    .map_err(|_| ArgosError::RateLimitExceeded)?;
            }
            sleep(delay).await;
        }

        // Apply adaptive delay if active
        {
            let state = self.adaptive.lock().await;
            if state.current_delay_ms > 0 {
                debug!("Adaptive delay: {}ms", state.current_delay_ms);
                sleep(Duration::from_millis(state.current_delay_ms)).await;
            }
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

                    // Check X-RateLimit-Remaining header
                    if let Some(remaining) = response
                        .headers()
                        .get("x-ratelimit-remaining")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                    {
                        if remaining == 0 {
                            let mut state = self.adaptive.lock().await;
                            // Pre-emptive sleep — we're about to be rate limited
                            let wait_ms = state.current_delay_ms.max(1000);
                            state.current_delay_ms = wait_ms;
                            debug!("X-RateLimit-Remaining: 0, pre-emptive delay {}ms", wait_ms);
                        }
                    }

                    if status == StatusCode::TOO_MANY_REQUESTS {
                        let mut state = self.adaptive.lock().await;
                        state.consecutive_429s += 1;

                        // Parse Retry-After if present
                        let retry_after = response
                            .headers()
                            .get("retry-after")
                            .and_then(|v| v.to_str().ok())
                            .and_then(Self::parse_retry_after);

                        if let Some(secs) = retry_after {
                            state.last_retry_after = Some(secs);
                            let wait = Duration::from_secs(secs);
                            warn!("Rate limited (429), Retry-After: {secs}s");
                            drop(state);
                            sleep(wait).await;
                        } else {
                            // Exponential backoff: 1s, 2s, 4s, 8s... max 30s
                            let delay = (1000u64 * 2u64.pow(state.consecutive_429s.min(5) - 1)).min(30_000);
                            state.current_delay_ms = delay;
                            warn!("Rate limited (429), adaptive delay: {}ms", delay);
                            drop(state);
                            sleep(Duration::from_millis(delay)).await;
                        }

                        last_error = Some(ArgosError::RateLimitExceeded);
                        continue;
                    }

                    // Detect WAF blocks: 403 with known WAF body patterns
                    if status == StatusCode::FORBIDDEN {
                        // We need to peek at the body without consuming the response
                        // Only detect WAF on 403, don't consume body for non-403
                        let url = response.url().to_string();
                        let headers_clone: Vec<(String, String)> = response
                            .headers()
                            .iter()
                            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                            .collect();

                        // Check server header for WAF indicators
                        let server_header = headers_clone
                            .iter()
                            .find(|(k, _)| k == "server")
                            .map(|(_, v)| v.to_lowercase())
                            .unwrap_or_default();

                        let is_waf = server_header.contains("cloudflare")
                            || server_header.contains("akamai")
                            || server_header.contains("mod_security")
                            || server_header.contains("sucuri")
                            || server_header.contains("fortiweb")
                            || server_header.contains("barracuda")
                            || server_header.contains("bigip");

                        if is_waf {
                            let mut state = self.adaptive.lock().await;
                            if !state.waf_detected {
                                state.waf_detected = true;
                                warn!("WAF block detected on {url}, adjusting rate");
                            }
                            // Add moderate delay for WAF-blocked requests
                            state.current_delay_ms = state.current_delay_ms.max(2000);
                        }
                    }

                    // On success after rate limiting, gradually reduce adaptive delay
                    if status.is_success() {
                        let mut state = self.adaptive.lock().await;
                        if state.consecutive_429s > 0 {
                            state.consecutive_429s = 0;
                        }
                        if state.current_delay_ms > 0 {
                            // Decrease by 25% on each success, minimum 0
                            state.current_delay_ms = (state.current_delay_ms * 3) / 4;
                            if state.current_delay_ms < 50 {
                                state.current_delay_ms = 0;
                            }
                        }
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
