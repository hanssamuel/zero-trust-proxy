use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Authorization denied: {0}")]
    AuthorizationDenied(String),
    
    #[error("Invalid session: {0}")]
    InvalidSession(String),
    
    #[error("Risk threshold exceeded: score {score}, threshold {threshold}")]
    RiskThresholdExceeded { score: u32, threshold: u32 },
    
    #[error("Policy evaluation failed: {0}")]
    PolicyEvaluationFailed(String),
    
    #[error("MFA required")]
    MfaRequired,
    
    #[error("Invalid MFA token")]
    InvalidMfaToken,
    
    #[error("Device not trusted: {0}")]
    DeviceNotTrusted(String),
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    
    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError),
    
    #[error("HTTP error: {0}")]
    HttpError(#[from] hyper::Error),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),
    
    #[error("Internal server error")]
    InternalError,
}

impl ProxyError {
    pub fn status_code(&self) -> u16 {
        match self {
            ProxyError::AuthenticationFailed(_) => 401,
            ProxyError::AuthorizationDenied(_) => 403,
            ProxyError::InvalidSession(_) => 401,
            ProxyError::RiskThresholdExceeded { .. } => 403,
            ProxyError::PolicyEvaluationFailed(_) => 403,
            ProxyError::MfaRequired => 401,
            ProxyError::InvalidMfaToken => 401,
            ProxyError::DeviceNotTrusted(_) => 403,
            ProxyError::RateLimitExceeded => 429,
            ProxyError::ConfigError(_) => 500,
            ProxyError::DatabaseError(_) => 500,
            ProxyError::RedisError(_) => 500,
            ProxyError::HttpError(_) => 502,
            ProxyError::IoError(_) => 500,
            ProxyError::SerializationError(_) => 500,
            ProxyError::JwtError(_) => 401,
            ProxyError::InternalError => 500,
        }
    }
}

pub type ProxyResult<T> = Result<T, ProxyError>;
