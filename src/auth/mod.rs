use crate::error::{ProxyError, ProxyResult};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod session;
pub mod mfa;
pub mod device;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,          // Subject (user ID)
    pub exp: i64,             // Expiration time
    pub iat: i64,             // Issued at
    pub jti: String,          // JWT ID
    pub device_id: String,    // Device identifier
    pub risk_score: u32,      // Current risk score
    pub mfa_verified: bool,   // Whether MFA was completed
}

#[derive(Debug, Clone)]
pub struct JwtManager {
    secret: String,
    expiration_hours: i64,
}

impl JwtManager {
    pub fn new(secret: String, expiration_hours: i64) -> Self {
        Self {
            secret,
            expiration_hours,
        }
    }

    pub fn generate_token(
        &self,
        user_id: &str,
        device_id: &str,
        risk_score: u32,
        mfa_verified: bool,
    ) -> ProxyResult<String> {
        let now = Utc::now();
        let exp = now + Duration::hours(self.expiration_hours);

        let claims = Claims {
            sub: user_id.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
            device_id: device_id.to_string(),
            risk_score,
            mfa_verified,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )?;

        Ok(token)
    }

    pub fn validate_token(&self, token: &str) -> ProxyResult<Claims> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &Validation::default(),
        )?;

        Ok(token_data.claims)
    }

    pub fn extract_token_from_header(&self, auth_header: &str) -> ProxyResult<String> {
        if !auth_header.starts_with("Bearer ") {
            return Err(ProxyError::AuthenticationFailed(
                "Invalid authorization header format".to_string(),
            ));
        }

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| {
                ProxyError::AuthenticationFailed("Missing bearer token".to_string())
            })?
            .to_string();

        Ok(token)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub mfa_enabled: bool,
    pub mfa_secret: Option<String>,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub device_id: String,
    pub mfa_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub mfa_required: bool,
}

// Password hashing using Argon2
pub fn hash_password(password: &str) -> ProxyResult<String> {
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| ProxyError::AuthenticationFailed(e.to_string()))?
        .to_string();

    Ok(password_hash)
}

pub fn verify_password(password: &str, hash: &str) -> ProxyResult<bool> {
    use argon2::{
        password_hash::{PasswordHash, PasswordVerifier},
        Argon2,
    };

    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| ProxyError::AuthenticationFailed(e.to_string()))?;

    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let password = "test_password_123";
        let hash = hash_password(password).unwrap();
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_jwt_generation_and_validation() {
        let manager = JwtManager::new("test_secret".to_string(), 24);
        let token = manager
            .generate_token("user123", "device456", 25, true)
            .unwrap();
        let claims = manager.validate_token(&token).unwrap();
        
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.device_id, "device456");
        assert_eq!(claims.risk_score, 25);
        assert!(claims.mfa_verified);
    }
}
