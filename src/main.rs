use anyhow::Result;
use std::net::SocketAddr;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod audit;
mod auth;
mod config;
mod db;
mod error;
mod policy;
mod proxy;
mod risk;

use crate::config::Config;
use crate::proxy::ProxyServer;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .json()
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");

    // Load configuration
    let config = Config::load()?;

    info!("🚀 Starting Zero-Trust Authentication Proxy");
    info!("📋 Configuration loaded successfully");

    // Initialize database connections
    let db_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .connect(&config.database.url)
        .await?;

    info!("✅ Database connection established");

    // Initialize Redis connection
    let redis_client = redis::Client::open(config.redis.url.as_str())?;
    let redis_conn = redis_client.get_connection_manager().await?;

    info!("✅ Redis connection established");

    // Build the proxy server
    let proxy_server = ProxyServer::new(config.clone(), db_pool, redis_conn);

    // Bind to address
    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .expect("Invalid server address");

    let scheme = if config.server.enable_tls {
        "https"
    } else {
        "http"
    };
    info!("🌐 Server listening on {}://{}", scheme, addr);
    if !config.server.enable_tls {
        info!("⚠️  TLS is disabled (server.enable_tls=false) -- traffic is plaintext");
    }
    info!("🔐 Zero-Trust enforcement: ENABLED");

    // Start the server
    proxy_server.serve(addr).await?;

    Ok(())
}
