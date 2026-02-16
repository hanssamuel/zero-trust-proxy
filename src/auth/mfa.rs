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

    /// Generate a new TOTP secret for a user
    pub fn generate_secret(&self) -> ProxyResult<String> {
        let secret = Secret::generate_secret();
        Ok(secret.to_encoded().to_string())
    }

    /// Generate a QR code URL for TOTP enrollment
    pub fn generate_qr_url(&self, secret: &str, account: &str, issuer: &str) -> ProxyResult<String> {
        let totp = TOTP::new(
            Algorithm::SHA1,
            self.config.digits,
            1,
            self.config.step,
            Secret::Encoded(secret.to_string()).to_bytes().unwrap(),
            Some(issuer.to_string()),
            account.to_string(),
        )
        .map_err(|e| ProxyError::AuthenticationFailed(e.to_string()))?;

        let qr_url = totp.get_qr_base64()
            .map_err(|e| ProxyError::AuthenticationFailed(e.to_string()))?;

        Ok(qr_url)
    }

    /// Verify a TOTP token
    pub fn verify_token(&self, secret: &str, token: &str) -> ProxyResult<bool> {
        let totp = TOTP::new(
            Algorithm::SHA1,
            self.config.digits,
            1,
            self.config.step,
            Secret::Encoded(secret.to_string()).to_bytes().unwrap(),
            None,
            "".to_string(),
        )
        .map_err(|e| ProxyError::AuthenticationFailed(e.to_string()))?;

        let is_valid = totp.check_current(token)
            .map_err(|e| ProxyError::AuthenticationFailed(e.to_string()))?;

        if !is_valid {
            return Err(ProxyError::InvalidMfaToken);
        }

        Ok(true)
    }

    /// Generate the current TOTP code (for testing/debugging)
    pub fn generate_current_token(&self, secret: &str) -> ProxyResult<String> {
        let totp = TOTP::new(
            Algorithm::SHA1,
            self.config.digits,
            1,
            self.config.step,
            Secret::Encoded(secret.to_string()).to_bytes().unwrap(),
            None,
            "".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_generation_and_verification() {
        let manager = TotpManager::new(MfaConfig::default());
        let secret = manager.generate_secret().unwrap();
        let token = manager.generate_current_token(&secret).unwrap();
        
        // Token should be 6 digits
        assert_eq!(token.len(), 6);
        
        // Verification should succeed
        assert!(manager.verify_token(&secret, &token).unwrap());
        
        // Invalid token should fail
        assert!(manager.verify_token(&secret, "000000").is_err());
    }

    #[test]
    fn test_qr_code_generation() {
        let manager = TotpManager::new(MfaConfig::default());
        let secret = manager.generate_secret().unwrap();
        let qr_url = manager.generate_qr_url(&secret, "test@example.com", "ZeroTrustProxy").unwrap();
        
        // QR code should be a base64 data URL
        assert!(qr_url.starts_with("data:image/png;base64,"));
    }
}
