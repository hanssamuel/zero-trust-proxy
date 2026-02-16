use crate::auth::device::DeviceFingerprint;
use crate::error::ProxyResult;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub mod analyzer;
pub mod threat_intel;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskContext {
    pub user_id: String,
    pub device: DeviceFingerprint,
    pub ip_address: IpAddr,
    pub timestamp: DateTime<Utc>,
    pub geolocation: Option<GeoLocation>,
    pub previous_ip: Option<IpAddr>,
    pub session_age_minutes: i64,
    pub failed_attempts: u32,
    pub time_since_last_success_hours: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub country: String,
    pub city: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub total_score: u32,
    pub factors: Vec<RiskFactor>,
    pub level: RiskLevel,
    pub recommendation: RiskRecommendation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub name: String,
    pub score: u32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskLevel {
    Low,       // 0-30
    Medium,    // 31-60
    High,      // 61-85
    Critical,  // 86-100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskRecommendation {
    Allow,
    StepUpAuth,
    Block,
}

pub struct RiskEngine {
    step_up_threshold: u32,
    block_threshold: u32,
}

impl RiskEngine {
    pub fn new(step_up_threshold: u32, block_threshold: u32) -> Self {
        Self {
            step_up_threshold,
            block_threshold,
        }
    }

    pub fn calculate_risk(&self, context: &RiskContext) -> ProxyResult<RiskScore> {
        let mut factors = Vec::new();
        let mut total_score = 0u32;

        // Device trust factor
        let device_risk = self.calculate_device_risk(&context.device);
        if device_risk > 0 {
            factors.push(RiskFactor {
                name: "Device Trust".to_string(),
                score: device_risk,
                description: format!("Device trust score: {}", context.device.trust_score),
            });
            total_score += device_risk;
        }

        // Geographic anomaly
        if let Some(geo_risk) = self.calculate_geo_risk(context) {
            factors.push(geo_risk.clone());
            total_score += geo_risk.score;
        }

        // Failed authentication attempts
        if context.failed_attempts > 0 {
            let attempt_risk = self.calculate_failed_attempts_risk(context.failed_attempts);
            factors.push(RiskFactor {
                name: "Failed Attempts".to_string(),
                score: attempt_risk,
                description: format!("{} failed attempts", context.failed_attempts),
            });
            total_score += attempt_risk;
        }

        // Time-based anomaly
        if let Some(time_risk) = self.calculate_time_risk(context) {
            factors.push(time_risk.clone());
            total_score += time_risk.score;
        }

        // IP change detection
        if let Some(ip_risk) = self.calculate_ip_change_risk(context) {
            factors.push(ip_risk.clone());
            total_score += ip_risk.score;
        }

        // Session age risk
        let session_risk = self.calculate_session_age_risk(context.session_age_minutes);
        if session_risk > 0 {
            factors.push(RiskFactor {
                name: "Session Age".to_string(),
                score: session_risk,
                description: format!("Session age: {} minutes", context.session_age_minutes),
            });
            total_score += session_risk;
        }

        // Cap at 100
        total_score = total_score.min(100);

        let level = match total_score {
            0..=30 => RiskLevel::Low,
            31..=60 => RiskLevel::Medium,
            61..=85 => RiskLevel::High,
            _ => RiskLevel::Critical,
        };

        let recommendation = if total_score >= self.block_threshold {
            RiskRecommendation::Block
        } else if total_score >= self.step_up_threshold {
            RiskRecommendation::StepUpAuth
        } else {
            RiskRecommendation::Allow
        };

        Ok(RiskScore {
            total_score,
            factors,
            level,
            recommendation,
        })
    }

    fn calculate_device_risk(&self, device: &DeviceFingerprint) -> u32 {
        let mut risk = 0u32;

        if !device.is_trusted {
            risk += 25;
        }

        if device.trust_score < 50 {
            risk += 15;
        }

        // New device
        let days_since_first_seen = (Utc::now() - device.first_seen).num_days();
        if days_since_first_seen < 1 {
            risk += 20;
        } else if days_since_first_seen < 7 {
            risk += 10;
        }

        risk
    }

    fn calculate_geo_risk(&self, context: &RiskContext) -> Option<RiskFactor> {
        // TODO: Implement geolocation-based risk
        // For now, return None
        None
    }

    fn calculate_failed_attempts_risk(&self, attempts: u32) -> u32 {
        match attempts {
            1..=2 => 10,
            3..=5 => 25,
            6..=10 => 40,
            _ => 60,
        }
    }

    fn calculate_time_risk(&self, context: &RiskContext) -> Option<RiskFactor> {
        // Check for unusual login times
        let hour = context.timestamp.hour();
        
        // Flag logins between 2 AM and 5 AM as potentially risky
        if (2..5).contains(&hour) {
            return Some(RiskFactor {
                name: "Unusual Time".to_string(),
                score: 15,
                description: "Login during unusual hours".to_string(),
            });
        }

        None
    }

    fn calculate_ip_change_risk(&self, context: &RiskContext) -> Option<RiskFactor> {
        if let Some(prev_ip) = context.previous_ip {
            if prev_ip != context.ip_address {
                return Some(RiskFactor {
                    name: "IP Change".to_string(),
                    score: 20,
                    description: "IP address changed within session".to_string(),
                });
            }
        }
        None
    }

    fn calculate_session_age_risk(&self, age_minutes: i64) -> u32 {
        // Longer sessions carry more risk of hijacking
        if age_minutes > 120 {
            30
        } else if age_minutes > 60 {
            15
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::device::DeviceMetadata;
    use std::str::FromStr;

    fn create_test_device() -> DeviceFingerprint {
        DeviceFingerprint::new(
            "user123".to_string(),
            "Mozilla/5.0".to_string(),
            "192.168.1.1".to_string(),
            DeviceMetadata {
                screen_resolution: None,
                timezone: None,
                language: None,
                platform_version: None,
                hardware_concurrency: None,
            },
        )
    }

    #[test]
    fn test_risk_calculation_low() {
        let engine = RiskEngine::new(60, 85);
        let mut device = create_test_device();
        device.increase_trust(30); // Make it trusted

        let context = RiskContext {
            user_id: "user123".to_string(),
            device,
            ip_address: IpAddr::from_str("192.168.1.1").unwrap(),
            timestamp: Utc::now(),
            geolocation: None,
            previous_ip: Some(IpAddr::from_str("192.168.1.1").unwrap()),
            session_age_minutes: 10,
            failed_attempts: 0,
            time_since_last_success_hours: Some(1),
        };

        let risk = engine.calculate_risk(&context).unwrap();
        assert_eq!(risk.level, RiskLevel::Low);
        assert!(matches!(risk.recommendation, RiskRecommendation::Allow));
    }

    #[test]
    fn test_risk_calculation_high() {
        let engine = RiskEngine::new(60, 85);
        let device = create_test_device(); // New, untrusted device

        let context = RiskContext {
            user_id: "user123".to_string(),
            device,
            ip_address: IpAddr::from_str("10.0.0.1").unwrap(),
            timestamp: Utc::now(),
            geolocation: None,
            previous_ip: Some(IpAddr::from_str("192.168.1.1").unwrap()),
            session_age_minutes: 150,
            failed_attempts: 3,
            time_since_last_success_hours: Some(48),
        };

        let risk = engine.calculate_risk(&context).unwrap();
        assert!(risk.total_score >= 60);
        assert!(matches!(
            risk.recommendation,
            RiskRecommendation::StepUpAuth | RiskRecommendation::Block
        ));
    }
}
