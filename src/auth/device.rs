use crate::error::ProxyResult;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFingerprint {
    pub id: String,
    pub user_id: String,
    pub fingerprint_hash: String,
    pub user_agent: String,
    pub ip_address: String,
    pub platform: String,
    pub browser: String,
    pub trust_score: u32,  // 0-100
    pub is_trusted: bool,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub metadata: DeviceMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceMetadata {
    pub screen_resolution: Option<String>,
    pub timezone: Option<String>,
    pub language: Option<String>,
    pub platform_version: Option<String>,
    pub hardware_concurrency: Option<u32>,
}

impl DeviceFingerprint {
    pub fn new(
        user_id: String,
        user_agent: String,
        ip_address: String,
        metadata: DeviceMetadata,
    ) -> Self {
        let fingerprint_hash = Self::generate_hash(&user_agent, &ip_address, &metadata);
        let (platform, browser) = Self::parse_user_agent(&user_agent);

        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            fingerprint_hash,
            user_agent,
            ip_address,
            platform,
            browser,
            trust_score: 50, // Start with neutral trust
            is_trusted: false,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            metadata,
        }
    }

    fn generate_hash(user_agent: &str, ip_address: &str, metadata: &DeviceMetadata) -> String {
        let mut hasher = Sha256::new();
        hasher.update(user_agent.as_bytes());
        hasher.update(ip_address.as_bytes());
        
        if let Some(resolution) = &metadata.screen_resolution {
            hasher.update(resolution.as_bytes());
        }
        if let Some(tz) = &metadata.timezone {
            hasher.update(tz.as_bytes());
        }
        if let Some(lang) = &metadata.language {
            hasher.update(lang.as_bytes());
        }

        format!("{:x}", hasher.finalize())
    }

    fn parse_user_agent(user_agent: &str) -> (String, String) {
        // Simple user agent parsing (in production, use a proper parser)
        let platform = if user_agent.contains("Windows") {
            "Windows"
        } else if user_agent.contains("Mac") {
            "macOS"
        } else if user_agent.contains("Linux") {
            "Linux"
        } else if user_agent.contains("Android") {
            "Android"
        } else if user_agent.contains("iOS") {
            "iOS"
        } else {
            "Unknown"
        };

        let browser = if user_agent.contains("Chrome") {
            "Chrome"
        } else if user_agent.contains("Firefox") {
            "Firefox"
        } else if user_agent.contains("Safari") {
            "Safari"
        } else if user_agent.contains("Edge") {
            "Edge"
        } else {
            "Unknown"
        };

        (platform.to_string(), browser.to_string())
    }

    pub fn update_last_seen(&mut self) {
        self.last_seen = Utc::now();
    }

    pub fn increase_trust(&mut self, amount: u32) {
        self.trust_score = (self.trust_score + amount).min(100);
        if self.trust_score >= 70 {
            self.is_trusted = true;
        }
    }

    pub fn decrease_trust(&mut self, amount: u32) {
        self.trust_score = self.trust_score.saturating_sub(amount);
        if self.trust_score < 70 {
            self.is_trusted = false;
        }
    }
}

pub struct DeviceManager;

impl DeviceManager {
    pub fn new() -> Self {
        Self
    }

    pub fn calculate_device_risk_score(device: &DeviceFingerprint) -> u32 {
        let mut risk = 0u32;

        // New device carries some risk
        let days_since_first_seen = (Utc::now() - device.first_seen).num_days();
        if days_since_first_seen < 1 {
            risk += 30;
        } else if days_since_first_seen < 7 {
            risk += 15;
        }

        // Untrusted device
        if !device.is_trusted {
            risk += 20;
        }

        // Low trust score
        if device.trust_score < 50 {
            risk += 25;
        }

        // Unknown platform or browser
        if device.platform == "Unknown" || device.browser == "Unknown" {
            risk += 15;
        }

        risk.min(100)
    }

    pub fn should_require_step_up_auth(device: &DeviceFingerprint) -> bool {
        !device.is_trusted || device.trust_score < 60
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_fingerprint_creation() {
        let metadata = DeviceMetadata {
            screen_resolution: Some("1920x1080".to_string()),
            timezone: Some("America/New_York".to_string()),
            language: Some("en-US".to_string()),
            platform_version: Some("10.0".to_string()),
            hardware_concurrency: Some(8),
        };

        let device = DeviceFingerprint::new(
            "user123".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0".to_string(),
            "192.168.1.1".to_string(),
            metadata,
        );

        assert_eq!(device.platform, "Windows");
        assert_eq!(device.browser, "Chrome");
        assert_eq!(device.trust_score, 50);
        assert!(!device.is_trusted);
    }

    #[test]
    fn test_trust_score_updates() {
        let metadata = DeviceMetadata {
            screen_resolution: None,
            timezone: None,
            language: None,
            platform_version: None,
            hardware_concurrency: None,
        };

        let mut device = DeviceFingerprint::new(
            "user123".to_string(),
            "Mozilla/5.0".to_string(),
            "192.168.1.1".to_string(),
            metadata,
        );

        device.increase_trust(30);
        assert_eq!(device.trust_score, 80);
        assert!(device.is_trusted);

        device.decrease_trust(20);
        assert_eq!(device.trust_score, 60);
        assert!(!device.is_trusted);
    }

    #[test]
    fn test_risk_calculation() {
        let metadata = DeviceMetadata {
            screen_resolution: None,
            timezone: None,
            language: None,
            platform_version: None,
            hardware_concurrency: None,
        };

        let device = DeviceFingerprint::new(
            "user123".to_string(),
            "Mozilla/5.0".to_string(),
            "192.168.1.1".to_string(),
            metadata,
        );

        let risk = DeviceManager::calculate_device_risk_score(&device);
        assert!(risk > 0); // New, untrusted device should have risk
    }
}
