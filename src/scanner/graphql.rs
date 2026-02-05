//! GraphQL introspection and security scanner

use crate::error::Result;
use crate::http::HttpClient;
use crate::models::{Finding, ScanConfig, Severity};
use async_trait::async_trait;
use tracing::{debug, info};

/// Detects GraphQL endpoints and security issues
pub struct GraphQLScanner;

/// Common GraphQL endpoint paths
const GRAPHQL_ENDPOINTS: &[&str] = &[
    "/graphql",
    "/graphiql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/api/query",
    "/gql",
];

/// Introspection query to enumerate the schema
const INTROSPECTION_QUERY: &str = r#"{"query":"{ __schema { types { name } } }"}"#;

/// Field suggestion probe (intentional typo)
const SUGGESTION_QUERY: &str = r#"{"query":"{ __typo }"}"#;

/// Batch query probe
const BATCH_QUERY: &str = r#"[{"query":"{ __typename }"},{"query":"{ __typename }"}]"#;

#[async_trait]
impl super::Scanner for GraphQLScanner {
    fn name(&self) -> &str {
        "graphql"
    }

    fn description(&self) -> &str {
        "Detects GraphQL endpoints, introspection exposure, and misconfigurations"
    }

    async fn scan(
        &self,
        client: &HttpClient,
        config: &ScanConfig,
        _crawled_urls: &[String],
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let base_url = config.target.trim_end_matches('/');

        for endpoint in GRAPHQL_ENDPOINTS {
            let url = format!("{base_url}{endpoint}");
            debug!("Probing GraphQL endpoint: {url}");

            // 1. Check for introspection
            if let Some(finding) = check_introspection(client, &url).await {
                findings.push(finding);
            }

            // 2. Check for GraphiQL / Playground UI
            if let Some(finding) = check_graphql_ui(client, &url).await {
                findings.push(finding);
            }

            // 3. Check for field suggestions (info leak)
            if let Some(finding) = check_field_suggestions(client, &url).await {
                findings.push(finding);
            }

            // 4. Check for batch query support
            if let Some(finding) = check_batch_queries(client, &url).await {
                findings.push(finding);
            }
        }

        info!("GraphQL scanner found {} findings", findings.len());
        Ok(findings)
    }
}

/// Checks if GraphQL introspection is enabled
async fn check_introspection(client: &HttpClient, url: &str) -> Option<Finding> {
    let headers = vec![(
        "Content-Type".to_string(),
        "application/json".to_string(),
    )];

    let resp = client
        .post_with_headers(url, &headers, INTROSPECTION_QUERY)
        .await
        .ok()?;

    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();

    if status == 200 && body.contains("\"__schema\"") && body.contains("\"types\"") {
        Some(
            Finding::new(
                "GraphQL Introspection Enabled",
                "The GraphQL endpoint allows introspection queries, exposing the entire API schema including types, fields, mutations, and subscriptions.",
                Severity::High,
                "GraphQL",
                url,
            )
            .with_evidence(format!(
                "Endpoint: {url}\nQuery: {INTROSPECTION_QUERY}\nResponse contains __schema with types"
            ))
            .with_request(format!("POST {url}"))
            .with_recommendation(
                "Disable introspection in production. In Apollo Server: introspection: false. In graphql-java: use InstrumentationProvider.",
            )
            .with_cwe("CWE-200")
            .with_owasp("A01:2021 Broken Access Control"),
        )
    } else {
        None
    }
}

/// Checks if GraphiQL or GraphQL Playground UI is exposed
async fn check_graphql_ui(client: &HttpClient, url: &str) -> Option<Finding> {
    let resp = client.get(url).await.ok()?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();

    if status != 200 {
        return None;
    }

    let body_lower = body.to_lowercase();
    let has_graphiql = body_lower.contains("graphiql")
        || body_lower.contains("graphql playground")
        || body_lower.contains("graphql-playground")
        || body_lower.contains("altair graphql")
        || body_lower.contains("graphql explorer");

    if has_graphiql {
        Some(
            Finding::new(
                "GraphQL IDE Exposed",
                "A GraphQL development IDE (GraphiQL/Playground/Altair) is publicly accessible, allowing anyone to explore and query the API.",
                Severity::Medium,
                "GraphQL",
                url,
            )
            .with_evidence(format!("Endpoint: {url}\nGraphQL IDE detected in response body"))
            .with_request(format!("GET {url}"))
            .with_recommendation(
                "Disable GraphQL IDE interfaces in production environments. Only enable them behind authentication in development.",
            )
            .with_cwe("CWE-200")
            .with_owasp("A01:2021 Broken Access Control"),
        )
    } else {
        None
    }
}

/// Checks if the GraphQL endpoint leaks field suggestions
async fn check_field_suggestions(client: &HttpClient, url: &str) -> Option<Finding> {
    let headers = vec![(
        "Content-Type".to_string(),
        "application/json".to_string(),
    )];

    let resp = client
        .post_with_headers(url, &headers, SUGGESTION_QUERY)
        .await
        .ok()?;

    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();

    if status == 200 && body.contains("Did you mean") {
        Some(
            Finding::new(
                "GraphQL Field Suggestion Enabled",
                "The GraphQL endpoint provides field suggestions for invalid queries, leaking information about the schema structure.",
                Severity::Low,
                "GraphQL",
                url,
            )
            .with_evidence(format!(
                "Endpoint: {url}\nQuery: {SUGGESTION_QUERY}\nResponse contains 'Did you mean' suggestions"
            ))
            .with_request(format!("POST {url}"))
            .with_recommendation(
                "Disable field suggestions in production to prevent schema enumeration.",
            )
            .with_cwe("CWE-200")
            .with_owasp("A01:2021 Broken Access Control"),
        )
    } else {
        None
    }
}

/// Checks if batch queries are supported (potential DoS vector)
async fn check_batch_queries(client: &HttpClient, url: &str) -> Option<Finding> {
    let headers = vec![(
        "Content-Type".to_string(),
        "application/json".to_string(),
    )];

    let resp = client
        .post_with_headers(url, &headers, BATCH_QUERY)
        .await
        .ok()?;

    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();

    // A successful batch response is a JSON array with multiple results
    if status == 200 && body.starts_with('[') && body.contains("__typename") {
        Some(
            Finding::new(
                "GraphQL Batch Queries Enabled",
                "The GraphQL endpoint accepts batched queries, which could be abused for denial-of-service or brute-force attacks.",
                Severity::Info,
                "GraphQL",
                url,
            )
            .with_evidence(format!(
                "Endpoint: {url}\nBatch query returned multiple results"
            ))
            .with_request(format!("POST {url}"))
            .with_recommendation(
                "Limit batch query size or disable batching. Implement query complexity analysis and rate limiting.",
            )
            .with_cwe("CWE-400")
            .with_owasp("A05:2021 Security Misconfiguration"),
        )
    } else {
        None
    }
}
