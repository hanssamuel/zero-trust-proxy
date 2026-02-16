use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub user_id: Option<String>,
    pub device_id: Option<String>,
    pub ip_address: String,
    pub resource: String,
    pub action: String,
    pub outcome: Outcome,
    pub risk_score: Option<u32>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    Authentication,
    Authorization,
    AccessGranted,
    AccessDenied,
    MfaVerification,
    SessionCreated,
    SessionExpired,
    RiskEvaluation,
    PolicyEvaluation,
    DeviceRegistration,
    AnomalyDetected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Success,
    Failure,
    Blocked,
}

impl AuditEvent {
    pub fn new(
        event_type: EventType,
        user_id: Option<String>,
        device_id: Option<String>,
        ip_address: String,
        resource: String,
        action: String,
        outcome: Outcome,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            user_id,
            device_id,
            ip_address,
            resource,
            action,
            outcome,
            risk_score: None,
            metadata: serde_json::json!({}),
        }
    }

    pub fn with_risk_score(mut self, score: u32) -> Self {
        self.risk_score = Some(score);
        self
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }
}

pub struct AuditLogger {
    db_pool: PgPool,
}

impl AuditLogger {
    pub fn new(db_pool: PgPool) -> Self {
        Self { db_pool }
    }

    pub async fn log(&self, event: AuditEvent) -> Result<(), sqlx::Error> {
        // For now, just log to stdout
        // In production, this would write to database
        tracing::info!(
            event_id = %event.id,
            event_type = ?event.event_type,
            user_id = ?event.user_id,
            outcome = ?event.outcome,
            "Audit event"
        );

        // TODO: Implement database logging
        // sqlx::query!(
        //     "INSERT INTO audit_log (...) VALUES (...)",
        //     ...
        // )
        // .execute(&self.db_pool)
        // .await?;

        Ok(())
    }

    pub async fn log_authentication(
        &self,
        user_id: &str,
        device_id: &str,
        ip_address: &str,
        success: bool,
    ) -> Result<(), sqlx::Error> {
        let event = AuditEvent::new(
            EventType::Authentication,
            Some(user_id.to_string()),
            Some(device_id.to_string()),
            ip_address.to_string(),
            "/auth/login".to_string(),
            "authenticate".to_string(),
            if success {
                Outcome::Success
            } else {
                Outcome::Failure
            },
        );

        self.log(event).await
    }

    pub async fn log_authorization(
        &self,
        user_id: &str,
        resource: &str,
        action: &str,
        allowed: bool,
        risk_score: u32,
    ) -> Result<(), sqlx::Error> {
        let event = AuditEvent::new(
            EventType::Authorization,
            Some(user_id.to_string()),
            None,
            "unknown".to_string(),
            resource.to_string(),
            action.to_string(),
            if allowed {
                Outcome::Success
            } else {
                Outcome::Blocked
            },
        )
        .with_risk_score(risk_score);

        self.log(event).await
    }

    pub async fn log_risk_evaluation(
        &self,
        user_id: &str,
        device_id: &str,
        ip_address: &str,
        risk_score: u32,
        factors: serde_json::Value,
    ) -> Result<(), sqlx::Error> {
        let event = AuditEvent::new(
            EventType::RiskEvaluation,
            Some(user_id.to_string()),
            Some(device_id.to_string()),
            ip_address.to_string(),
            "/".to_string(),
            "evaluate_risk".to_string(),
            Outcome::Success,
        )
        .with_risk_score(risk_score)
        .with_metadata(factors);

        self.log(event).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent::new(
            EventType::Authentication,
            Some("user123".to_string()),
            Some("device456".to_string()),
            "192.168.1.1".to_string(),
            "/auth/login".to_string(),
            "authenticate".to_string(),
            Outcome::Success,
        );

        assert_eq!(event.user_id, Some("user123".to_string()));
        assert!(matches!(event.event_type, EventType::Authentication));
        assert!(matches!(event.outcome, Outcome::Success));
    }

    #[test]
    fn test_audit_event_with_risk_score() {
        let event = AuditEvent::new(
            EventType::RiskEvaluation,
            Some("user123".to_string()),
            None,
            "192.168.1.1".to_string(),
            "/".to_string(),
            "evaluate".to_string(),
            Outcome::Success,
        )
        .with_risk_score(75);

        assert_eq!(event.risk_score, Some(75));
    }
}
