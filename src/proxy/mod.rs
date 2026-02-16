use crate::config::Config;
use crate::error::ProxyError;
use anyhow::Result;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, body::Incoming};
use hyper_util::rt::TokioIo;
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};
use http_body_util::Full;
use hyper::body::Bytes;

pub struct ProxyServer {
    config: Arc<Config>,
    db_pool: PgPool,
    redis_conn: ConnectionManager,
}

impl ProxyServer {
    pub fn new(config: Config, db_pool: PgPool, redis_conn: ConnectionManager) -> Self {
        Self {
            config: Arc::new(config),
            db_pool,
            redis_conn,
        }
    }

    pub async fn serve(self, addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        let server = Arc::new(self);

        loop {
            let (stream, remote_addr) = listener.accept().await?;
            let io = TokioIo::new(stream);
            let server = Arc::clone(&server);

            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let server = Arc::clone(&server);
                    async move { server.handle_request(req, remote_addr).await }
                });

                if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                    error!("Error serving connection: {:?}", err);
                }
            });
        }
    }

    async fn handle_request(
        &self,
        req: Request<Incoming>,
        remote_addr: SocketAddr,
    ) -> Result<Response<Full<Bytes>>, ProxyError> {
        info!(
            "📨 Incoming request: {} {} from {}",
            req.method(),
            req.uri().path(),
            remote_addr
        );

        // Health check endpoint
        if req.uri().path() == "/health" {
            return Ok(Response::new(Full::new(Bytes::from("OK"))));
        }

        // Metrics endpoint
        if req.uri().path() == "/metrics" {
            return self.handle_metrics().await;
        }

        // Main proxy logic will be implemented here
        // For now, return a placeholder response
        let response = Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from("Zero-Trust Proxy - Authentication Required")))
            .map_err(|_| ProxyError::InternalError)?;

        Ok(response)
    }

    async fn handle_metrics(&self) -> Result<Response<Full<Bytes>>, ProxyError> {
        // Placeholder for Prometheus metrics
        let metrics = "# Zero-Trust Proxy Metrics\n\
                      ztp_requests_total 0\n\
                      ztp_auth_failures_total 0\n";

        Ok(Response::new(Full::new(Bytes::from(metrics))))
    }
}
