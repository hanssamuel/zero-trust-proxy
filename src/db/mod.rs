use crate::error::ProxyResult;
use serde::Serialize;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct UserRow {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub mfa_enabled: bool,
    pub mfa_secret: Option<String>,
    pub is_active: bool,
}

pub async fn find_user_by_username(pool: &PgPool, username: &str) -> ProxyResult<Option<UserRow>> {
    let row = sqlx::query_as::<_, UserRow>(
        "SELECT id, username, email, password_hash, mfa_enabled, mfa_secret, is_active
         FROM users WHERE username = $1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

pub async fn find_user_by_id(pool: &PgPool, id: Uuid) -> ProxyResult<Option<UserRow>> {
    let row = sqlx::query_as::<_, UserRow>(
        "SELECT id, username, email, password_hash, mfa_enabled, mfa_secret, is_active
         FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

#[derive(Debug, Clone, FromRow)]
pub struct DeviceRow {
    pub trust_score: i32,
    pub is_trusted: bool,
}

pub async fn find_device_by_fingerprint(
    pool: &PgPool,
    user_id: Uuid,
    fingerprint_hash: &str,
) -> ProxyResult<Option<DeviceRow>> {
    let row = sqlx::query_as::<_, DeviceRow>(
        "SELECT trust_score, is_trusted FROM devices WHERE user_id = $1 AND fingerprint_hash = $2",
    )
    .bind(user_id)
    .bind(fingerprint_hash)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

#[allow(clippy::too_many_arguments)]
pub async fn upsert_device(
    pool: &PgPool,
    user_id: Uuid,
    fingerprint_hash: &str,
    user_agent: &str,
    platform: &str,
    browser: &str,
    ip_address: &str,
    trust_score: i32,
    is_trusted: bool,
) -> ProxyResult<()> {
    sqlx::query(
        "INSERT INTO devices (user_id, fingerprint_hash, user_agent, platform, browser, ip_address, trust_score, is_trusted, last_seen)
         VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8, NOW())
         ON CONFLICT (fingerprint_hash) DO UPDATE
           SET trust_score = EXCLUDED.trust_score,
               is_trusted = EXCLUDED.is_trusted,
               last_seen = NOW(),
               ip_address = EXCLUDED.ip_address",
    )
    .bind(user_id)
    .bind(fingerprint_hash)
    .bind(user_agent)
    .bind(platform)
    .bind(browser)
    .bind(ip_address)
    .bind(trust_score)
    .bind(is_trusted)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn set_user_mfa_secret(pool: &PgPool, id: Uuid, secret: &str) -> ProxyResult<()> {
    sqlx::query("UPDATE users SET mfa_enabled = TRUE, mfa_secret = $1 WHERE id = $2")
        .bind(secret)
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn create_user(
    pool: &PgPool,
    username: &str,
    email: &str,
    password_hash: &str,
) -> ProxyResult<UserRow> {
    let row = sqlx::query_as::<_, UserRow>(
        "INSERT INTO users (username, email, password_hash)
         VALUES ($1, $2, $3)
         RETURNING id, username, email, password_hash, mfa_enabled, mfa_secret, is_active",
    )
    .bind(username)
    .bind(email)
    .bind(password_hash)
    .fetch_one(pool)
    .await?;

    Ok(row)
}
