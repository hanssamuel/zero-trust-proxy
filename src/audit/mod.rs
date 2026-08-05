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
        tracing::info!(
            event_id = %event.id,
            event_type = ?event.event_type,
            user_id = ?event.user_id,
            outcome = ?event.outcome,
            "Audit event"
        );

        // audit_log.device_id is a FK to devices(id), but the device_id we
        // carry here is the caller-supplied opaque string from the JWT/login
        // body -- not that row's UUID primary key. Rather than force a FK
        // that may not resolve, fold it into metadata instead.
        let mut metadata = event.metadata.clone();
        if let Some(device_id) = &event.device_id {
            match metadata.as_object_mut() {
                Some(obj) => {
                    obj.insert("device_id".to_string(), serde_json::json!(device_id));
                }
                None => metadata = serde_json::json!({ "device_id": device_id }),
            }
        }

        let user_uuid = event
            .user_id
            .as_deref()
            .and_then(|s| Uuid::parse_str(s).ok());
        let event_id = Uuid::parse_str(&event.id).unwrap_or_else(|_| Uuid::new_v4());
        let ip_address = if event.ip_address.parse::<std::net::IpAddr>().is_ok() {
            event.ip_address.clone()
        } else {
            "0.0.0.0".to_string()
        };
        let event_type = json_str(&event.event_type);
        let outcome = json_str(&event.outcome);

        sqlx::query(
            "INSERT INTO audit_log (id, event_type, user_id, ip_address, resource, action, outcome, risk_score, metadata)
             VALUES ($1, $2, $3, $4::inet, $5, $6, $7, $8, $9)",
        )
        .bind(event_id)
        .bind(event_type)
        .bind(user_uuid)
        .bind(ip_address)
        .bind(&event.resource)
        .bind(&event.action)
        .bind(outcome)
        .bind(event.risk_score.map(|s| s as i32))
        .bind(metadata)
        .execute(&self.db_pool)
        .await?;

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
        ip_address: &str,
        resource: &str,
        action: &str,
        allowed: bool,
        risk_score: u32,
    ) -> Result<(), sqlx::Error> {
        let event = AuditEvent::new(
            EventType::Authorization,
            Some(user_id.to_string()),
            None,
            ip_address.to_string(),
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

/// Renders a serde-tagged enum to the same lowercase/snake_case string its
/// `#[serde(rename_all = ...)]` attribute produces, for storing as plain text.
fn json_str<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| "unknown".to_string())
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
