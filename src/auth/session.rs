use crate::error::{ProxyError, ProxyResult};
use chrono::{DateTime, Duration, Utc};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub device_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub ip_address: String,
    pub user_agent: String,
    pub mfa_verified: bool,
    pub risk_score: u32,
}

impl Session {
    pub fn new(
        user_id: String,
        device_id: String,
        ip_address: String,
        user_agent: String,
        duration_minutes: i64,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            device_id,
            created_at: now,
            expires_at: now + Duration::minutes(duration_minutes),
            last_activity: now,
            ip_address,
            user_agent,
            mfa_verified: false,
            risk_score: 0,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn update_activity(&mut self) {
        self.last_activity = Utc::now();
    }
}

pub struct SessionManager {
    redis: ConnectionManager,
    session_duration_minutes: i64,
}

impl SessionManager {
    pub fn new(redis: ConnectionManager, session_duration_minutes: i64) -> Self {
        Self {
            redis,
            session_duration_minutes,
        }
    }

    /// Create a new session
    pub async fn create_session(
        &mut self,
        user_id: String,
        device_id: String,
        ip_address: String,
        user_agent: String,
    ) -> ProxyResult<Session> {
        let session = Session::new(
            user_id,
            device_id,
            ip_address,
            user_agent,
            self.session_duration_minutes,
        );

        // Store in Redis
        let key = format!("session:{}", session.id);
        let serialized = serde_json::to_string(&session)?;
        let ttl = self.session_duration_minutes * 60; // Convert to seconds

        self.redis
            .set_ex::<_, _, ()>(&key, serialized, ttl as u64)
            .await?;

        Ok(session)
    }

    /// Get a session by ID
    pub async fn get_session(&mut self, session_id: &str) -> ProxyResult<Session> {
        let key = format!("session:{}", session_id);
        let data: Option<String> = self.redis.get(&key).await?;

        match data {
            Some(serialized) => {
                let mut session: Session = serde_json::from_str(&serialized)?;

                if session.is_expired() {
                    self.delete_session(session_id).await?;
                    return Err(ProxyError::InvalidSession("Session expired".to_string()));
                }

                session.update_activity();
                self.update_session(&session).await?;

                Ok(session)
            }
            None => Err(ProxyError::InvalidSession("Session not found".to_string())),
        }
    }

    /// Update an existing session
    pub async fn update_session(&mut self, session: &Session) -> ProxyResult<()> {
        let key = format!("session:{}", session.id);
        let serialized = serde_json::to_string(session)?;
        let ttl = (session.expires_at - Utc::now()).num_seconds();

        if ttl > 0 {
            self.redis
                .set_ex::<_, _, ()>(&key, serialized, ttl as u64)
                .await?;
        }

        Ok(())
    }

    /// Delete a session
    pub async fn delete_session(&mut self, session_id: &str) -> ProxyResult<()> {
        let key = format!("session:{}", session_id);
        self.redis.del::<_, ()>(&key).await?;
        Ok(())
    }

    /// SCAN (not KEYS) so a large keyspace doesn't block the Redis server
    /// while a security-critical proxy is trying to make auth decisions.
    async fn scan_session_keys(&mut self) -> ProxyResult<Vec<String>> {
        let mut keys = Vec::new();
        let mut iter: redis::AsyncIter<String> = self.redis.scan_match("session:*").await?;
        while let Some(key) = iter.next_item().await {
            keys.push(key);
        }
        Ok(keys)
    }

    /// Get all sessions for a user
    pub async fn get_user_sessions(&mut self, user_id: &str) -> ProxyResult<Vec<Session>> {
        let keys = self.scan_session_keys().await?;

        let mut sessions = Vec::new();
        for key in keys {
            if let Ok(Some(data)) = self.redis.get::<_, Option<String>>(&key).await {
                if let Ok(session) = serde_json::from_str::<Session>(&data) {
                    if session.user_id == user_id && !session.is_expired() {
                        sessions.push(session);
                    }
                }
            }
        }

        Ok(sessions)
    }

    /// Revoke all sessions for a user
    pub async fn revoke_user_sessions(&mut self, user_id: &str) -> ProxyResult<usize> {
        let sessions = self.get_user_sessions(user_id).await?;
        let count = sessions.len();

        for session in sessions {
            self.delete_session(&session.id).await?;
        }

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = Session::new(
            "user123".to_string(),
            "device456".to_string(),
            "192.168.1.1".to_string(),
            "Mozilla/5.0".to_string(),
            15,
        );

        assert_eq!(session.user_id, "user123");
        assert_eq!(session.device_id, "device456");
        assert!(!session.is_expired());
        assert!(!session.mfa_verified);
    }

    #[test]
    fn test_session_expiration() {
        let mut session = Session::new(
            "user123".to_string(),
            "device456".to_string(),
            "192.168.1.1".to_string(),
            "Mozilla/5.0".to_string(),
            0,
        );

        // Manually set expiration to the past
        session.expires_at = Utc::now() - Duration::minutes(1);
        assert!(session.is_expired());
    }
}
