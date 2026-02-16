use crate::error::{ProxyError, ProxyResult};
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaConfig {
    pub enabled: bool,
    pub algorithm: String,
    pub digits: usize,
    pub step: u64,
}

impl Default for MfaConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            algorithm: "SHA1".to_string(),
            digits: 6,
            step: 30,
        }
    }
}

pub struct TotpManager {
    config: MfaConfig,
}

impl TotpManager {
    pub fn new(config: MfaConfig) -> Self {
        Self { config }
    }

    pub fn generate_secret(&self) -> ProxyResult<String> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let secret: String = (0..32)
            .map(|_| {
                const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect();
        Ok(secret)
    }

    pub fn generate_qr_url(&self, secret: &str, account: &str, issuer: &str) -> ProxyResult<String> {
        Ok(format!("otpauth://totp/{}:{}?secret={}&issuer={}", issuer, account, secret, issuer))
    }

    pub fn verify_token(&self, secret: &str, token: &str) -> ProxyResult<bool> {
        let totp = TOTP::new(
            Algorithm::SHA1,
            self.config.digits,
            1,
            self.config.step,
            Secret::Encoded(secret.to_string()).to_bytes().unwrap(),
        )
        .map_err(|e| ProxyError::AuthenticationFailed(e.to_string()))?;

        let is_valid = totp.check_current(token)
            .map_err(|e| ProxyError::AuthenticationFailed(e.to_string()))?;

        if !is_valid {
            return Err(ProxyError::InvalidMfaToken);
        }

        Ok(true)
    }

    pub fn generate_current_token(&self, secret: &str) -> ProxyResult<String> {
        let totp = TOTP::new(
            Algorithm::SHA1,
            self.config.digits,
            1,
            self.config.step,
            Secret::Encoded(secret.to_string()).to_bytes().unwrap(),
        )
        .map_err(|e| ProxyError::AuthenticationFailed(e.to_string()))?;

        let token = totp.generate_current()
            .map_err(|e| ProxyError::AuthenticationFailed(e.to_string()))?;

        Ok(token)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaEnrollmentRequest {
    pub user_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaEnrollmentResponse {
    pub secret: String,
    pub qr_code_url: String,
    pub manual_entry_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaVerificationRequest {
    pub user_id: String,
    pub token: String,
}
