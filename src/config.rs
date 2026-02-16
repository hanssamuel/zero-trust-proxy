use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub auth: AuthConfig,
    pub risk: RiskConfig,
    pub policy: PolicyConfig,
    pub upstream: UpstreamConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub enable_tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub session_duration_minutes: i64,
    pub require_mfa: bool,
    pub allowed_mfa_methods: Vec<String>,
    pub jwt_secret: String,
    pub jwt_expiration_hours: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskConfig {
    pub max_risk_score: u32,
    pub step_up_threshold: u32,
    pub block_threshold: u32,
    pub enable_geolocation: bool,
    pub enable_threat_intel: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub policy_file: String,
    pub enable_opa: bool,
    pub default_deny: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    pub default_backend: String,
    pub timeout_seconds: u64,
    pub enable_mtls: bool,
}

impl Config {
    pub fn load() -> Result<Self> {
        // Try to load from config file
        let config_path = std::env::var("CONFIG_PATH")
            .unwrap_or_else(|_| "config/config.toml".to_string());
        
        if std::path::Path::new(&config_path).exists() {
            let config_str = fs::read_to_string(&config_path)?;
            let config: Config = toml::from_str(&config_str)?;
            return Ok(config);
        }
        
        // Fallback to default configuration
        Ok(Self::default())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8443,
                tls_cert: None,
                tls_key: None,
                enable_tls: false,
            },
            database: DatabaseConfig {
                url: std::env::var("DATABASE_URL")
                    .unwrap_or_else(|_| "postgresql://localhost/ztp".to_string()),
                max_connections: 20,
            },
            redis: RedisConfig {
                url: std::env::var("REDIS_URL")
                    .unwrap_or_else(|_| "redis://localhost:6379".to_string()),
            },
            auth: AuthConfig {
                session_duration_minutes: 15,
                require_mfa: false,
                allowed_mfa_methods: vec!["totp".to_string()],
                jwt_secret: std::env::var("JWT_SECRET")
                    .unwrap_or_else(|_| "change-me-in-production".to_string()),
                jwt_expiration_hours: 24,
            },
            risk: RiskConfig {
                max_risk_score: 100,
                step_up_threshold: 60,
                block_threshold: 85,
                enable_geolocation: false,
                enable_threat_intel: false,
            },
            policy: PolicyConfig {
                policy_file: "config/policy.rego".to_string(),
                enable_opa: false,
                default_deny: true,
            },
            upstream: UpstreamConfig {
                default_backend: "http://localhost:8080".to_string(),
                timeout_seconds: 30,
                enable_mtls: false,
            },
        }
    }
}
