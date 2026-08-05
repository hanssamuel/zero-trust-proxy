use crate::auth::device::DeviceFingerprint;
use crate::error::ProxyResult;
use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

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
    Low,
    Medium,
    High,
    Critical,
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

        let device_risk = self.calculate_device_risk(&context.device);
        if device_risk > 0 {
            factors.push(RiskFactor {
                name: "Device Trust".to_string(),
                score: device_risk,
                description: format!("Device trust score: {}", context.device.trust_score),
            });
            total_score += device_risk;
        }

        if let Some(geo_risk) = self.calculate_geo_risk() {
            factors.push(geo_risk.clone());
            total_score += geo_risk.score;
        }

        if context.failed_attempts > 0 {
            let attempt_risk = self.calculate_failed_attempts_risk(context.failed_attempts);
            factors.push(RiskFactor {
                name: "Failed Attempts".to_string(),
                score: attempt_risk,
                description: format!("{} failed attempts", context.failed_attempts),
            });
            total_score += attempt_risk;
        }

        if let Some(time_risk) = self.calculate_time_risk(context) {
            factors.push(time_risk.clone());
            total_score += time_risk.score;
        }

        if let Some(ip_risk) = self.calculate_ip_change_risk(context) {
            factors.push(ip_risk.clone());
            total_score += ip_risk.score;
        }

        let session_risk = self.calculate_session_age_risk(context.session_age_minutes);
        if session_risk > 0 {
            factors.push(RiskFactor {
                name: "Session Age".to_string(),
                score: session_risk,
                description: format!("Session age: {} minutes", context.session_age_minutes),
            });
            total_score += session_risk;
        }

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
        let days_since_first_seen = (Utc::now() - device.first_seen).num_days();
        if days_since_first_seen < 1 {
            risk += 20;
        } else if days_since_first_seen < 7 {
            risk += 10;
        }
        risk
    }

    fn calculate_geo_risk(&self) -> Option<RiskFactor> {
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
        let hour = context.timestamp.hour();
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

    fn trusted_device() -> DeviceFingerprint {
        let mut device = DeviceFingerprint::new(
            "user123".to_string(),
            "Mozilla/5.0".to_string(),
            "10.0.0.1".to_string(),
            DeviceMetadata {
                screen_resolution: None,
                timezone: None,
                language: None,
                platform_version: None,
                hardware_concurrency: None,
            },
        );
        device.trust_score = 90;
        device.is_trusted = true;
        device
    }

    fn base_context(device: DeviceFingerprint) -> RiskContext {
        RiskContext {
            user_id: "user123".to_string(),
            device,
            ip_address: "10.0.0.1".parse().unwrap(),
            timestamp: Utc::now(),
            geolocation: None,
            previous_ip: None,
            session_age_minutes: 0,
            failed_attempts: 0,
            time_since_last_success_hours: None,
        }
    }

    #[test]
    fn test_trusted_low_activity_session_allows() {
        let engine = RiskEngine::new(60, 85);
        let ctx = base_context(trusted_device());

        let score = engine.calculate_risk(&ctx).unwrap();
        assert!(matches!(score.recommendation, RiskRecommendation::Allow));
    }

    #[test]
    fn test_untrusted_new_device_plus_failed_attempts_blocks() {
        let engine = RiskEngine::new(60, 85);
        let mut ctx = base_context(DeviceFingerprint::new(
            "user123".to_string(),
            "curl/8.0".to_string(),
            "203.0.113.9".to_string(),
            DeviceMetadata {
                screen_resolution: None,
                timezone: None,
                language: None,
                platform_version: None,
                hardware_concurrency: None,
            },
        ));
        ctx.failed_attempts = 12;
        ctx.previous_ip = Some("198.51.100.1".parse().unwrap());

        let score = engine.calculate_risk(&ctx).unwrap();
        assert!(matches!(score.recommendation, RiskRecommendation::Block));
        assert!(score.total_score >= 85);
    }

    #[test]
    fn test_moderate_risk_triggers_step_up() {
        let engine = RiskEngine::new(30, 90);
        let mut ctx = base_context(trusted_device());
        // Same device, but a handful of failed attempts and a stale session
        // should be enough to cross a low step-up threshold without blocking.
        ctx.failed_attempts = 2;
        ctx.session_age_minutes = 130;

        let score = engine.calculate_risk(&ctx).unwrap();
        assert!(matches!(
            score.recommendation,
            RiskRecommendation::StepUpAuth
        ));
    }
}
