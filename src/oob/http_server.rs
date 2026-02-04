//! Minimal HTTP callback server for OOB interaction detection

use super::{Interaction, InteractionStore, InteractionType};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::debug;

/// Starts the OOB HTTP callback server
pub async fn start_http_server(
    port: u16,
    store: InteractionStore,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    debug!("OOB HTTP server listening on {}", addr);

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        let store = store.clone();
        let io = TokioIo::new(stream);

        tokio::spawn(async move {
            let service = service_fn(move |req: Request<Incoming>| {
                let store = store.clone();
                async move {
                    handle_request(req, remote_addr, store).await
                }
            });

            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                debug!("OOB HTTP connection error: {}", e);
            }
        });
    }
}

async fn handle_request(
    req: Request<Incoming>,
    remote_addr: SocketAddr,
    store: InteractionStore,
) -> Result<Response<String>, hyper::Error> {
    let path = req.uri().path().to_string();
    let interaction_id = path.trim_start_matches('/').to_string();

    if !interaction_id.is_empty() {
        let interaction = Interaction {
            id: interaction_id.clone(),
            interaction_type: InteractionType::Http,
            remote_addr,
            timestamp: chrono::Utc::now(),
            raw_data: format!(
                "{} {} {:?}",
                req.method(),
                req.uri(),
                req.headers()
            ),
        };

        debug!(
            "OOB HTTP interaction: {} from {}",
            interaction_id, remote_addr
        );

        let mut store = store.lock().await;
        store
            .entry(interaction_id)
            .or_default()
            .push(interaction);
    }

    Ok(Response::new("ok".to_string()))
}
