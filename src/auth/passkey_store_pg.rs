// The items in this module are the Postgres passkey store, consumed by the
// passkey HTTP handlers once they are wired up (see the walkthrough in
// `super::webauthn`). Until then the binary does not call them yet, hence this.
#![allow(dead_code)]

//! Postgres-backed [`PasskeyStore`](super::webauthn::PasskeyStore).
//!
//! [`PostgresPasskeyStore`] persists finished passkey credentials in the
//! `passkeys` table (`migrations/001_passkeys.sql`): one row per credential,
//! keyed by `(user_id, cred_id)`, with the `webauthn_rs::Passkey` held as
//! JSONB so it round-trips without loss. The sign counter advances through
//! [`update_passkey`](super::webauthn::PasskeyStore::update_passkey), which
//! also stamps `last_used_at`.
//!
//! Use [`connect_passkey_store`] to pick the backend from configuration:
//! Postgres in production, the in-memory store for local dev and tests
//! (`WEBAUTHN_PASSKEY_STORE=memory`).

use super::webauthn::{InMemoryPasskeyStore, PasskeyRecord, PasskeyStore};
use crate::config::PasskeyStoreKind;
use crate::error::{ProxyError, ProxyResult};
use sqlx::postgres::PgPoolOptions;
use sqlx::types::Json;
use sqlx::{FromRow, PgPool};
use std::time::Duration;
use webauthn_rs::prelude::*;

/// Postgres implementation of [`PasskeyStore`].
///
/// Backed by a `sqlx` connection pool over the `passkeys` table. Cheap to
/// clone: clones share the pool.
#[derive(Debug, Clone)]
pub struct PostgresPasskeyStore {
    pool: PgPool,
}

impl PostgresPasskeyStore {
    /// Wrap an existing pool (the binary already builds one at startup).
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Connect from a database URL. Mirrors the pool setup in `main.rs`.
    pub async fn connect(url: &str, max_connections: u32) -> ProxyResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(10))
            .connect(url)
            .await?;
        Ok(Self { pool })
    }
}

/// One row of the `passkeys` table.
#[derive(Debug, FromRow)]
struct PasskeyRow {
    user_id: String,
    cred_id: String,
    passkey: Json<Passkey>,
}

impl From<PasskeyRow> for PasskeyRecord {
    fn from(row: PasskeyRow) -> Self {
        PasskeyRecord {
            user_id: row.user_id,
            cred_id: row.cred_id,
            passkey: row.passkey.0,
        }
    }
}

impl PasskeyStore for PostgresPasskeyStore {
    async fn save_passkey(&self, record: PasskeyRecord) -> ProxyResult<()> {
        // Plain INSERT: the `(user_id, cred_id)` primary key rejects a
        // duplicate credential with an error rather than silently replacing
        // the row, so re-registration must go through an explicit
        // delete-then-save.
        sqlx::query(
            "INSERT INTO passkeys (user_id, cred_id, passkey)
             VALUES ($1, $2, $3)",
        )
        .bind(&record.user_id)
        .bind(&record.cred_id)
        .bind(Json(record.passkey))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_passkeys(&self, user_id: &str) -> ProxyResult<Vec<PasskeyRecord>> {
        let rows = sqlx::query_as::<_, PasskeyRow>(
            "SELECT user_id, cred_id, passkey FROM passkeys
             WHERE user_id = $1 ORDER BY created_at",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(PasskeyRecord::from).collect())
    }

    async fn update_passkey(&self, record: &PasskeyRecord) -> ProxyResult<()> {
        // Persists the advanced sign counter inside `record.passkey` (see
        // `refresh_passkey`) and stamps when the credential was last used.
        let result = sqlx::query(
            "UPDATE passkeys SET passkey = $3, last_used_at = NOW()
             WHERE user_id = $1 AND cred_id = $2",
        )
        .bind(&record.user_id)
        .bind(&record.cred_id)
        .bind(Json(record.passkey.clone()))
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(ProxyError::AuthenticationFailed(format!(
                "unknown passkey credential {} for user {}",
                record.cred_id, record.user_id
            )));
        }
        Ok(())
    }

    async fn delete_passkey(&self, user_id: &str, cred_id: &str) -> ProxyResult<()> {
        sqlx::query("DELETE FROM passkeys WHERE user_id = $1 AND cred_id = $2")
            .bind(user_id)
            .bind(cred_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

/// The configured passkey store backend, as a concrete type.
///
/// `PasskeyStore` is not object-safe (async trait methods), so the factory
/// cannot return a trait object; this enum holds whichever backend the
/// configuration selects and delegates every trait method to it.
#[derive(Debug)]
pub enum PasskeyStoreHandle {
    Postgres(PostgresPasskeyStore),
    Memory(InMemoryPasskeyStore),
}

impl PasskeyStore for PasskeyStoreHandle {
    async fn save_passkey(&self, record: PasskeyRecord) -> ProxyResult<()> {
        match self {
            Self::Postgres(store) => store.save_passkey(record).await,
            Self::Memory(store) => store.save_passkey(record).await,
        }
    }

    async fn get_passkeys(&self, user_id: &str) -> ProxyResult<Vec<PasskeyRecord>> {
        match self {
            Self::Postgres(store) => store.get_passkeys(user_id).await,
            Self::Memory(store) => store.get_passkeys(user_id).await,
        }
    }

    async fn update_passkey(&self, record: &PasskeyRecord) -> ProxyResult<()> {
        match self {
            Self::Postgres(store) => store.update_passkey(record).await,
            Self::Memory(store) => store.update_passkey(record).await,
        }
    }

    async fn delete_passkey(&self, user_id: &str, cred_id: &str) -> ProxyResult<()> {
        match self {
            Self::Postgres(store) => store.delete_passkey(user_id, cred_id).await,
            Self::Memory(store) => store.delete_passkey(user_id, cred_id).await,
        }
    }
}

/// Build the passkey store selected by configuration.
///
/// Production deployments use Postgres (the default); local dev and tests can
/// opt into the in-memory store with `WEBAUTHN_PASSKEY_STORE=memory`.
pub async fn connect_passkey_store(
    kind: PasskeyStoreKind,
    database_url: &str,
    max_connections: u32,
) -> ProxyResult<PasskeyStoreHandle> {
    match kind {
        PasskeyStoreKind::Postgres => Ok(PasskeyStoreHandle::Postgres(
            PostgresPasskeyStore::connect(database_url, max_connections).await?,
        )),
        PasskeyStoreKind::Memory => Ok(PasskeyStoreHandle::Memory(InMemoryPasskeyStore::new())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    /// Apply the real embedded migrations (the same `sqlx::migrate!()` the
    /// binary runs at startup), so tests exercise the DDL that ships in
    /// `migrations/`. The migrator takes an advisory lock, so parallel tests
    /// applying it concurrently is safe.
    async fn apply_ddl(pool: &PgPool) -> Result<(), sqlx::Error> {
        sqlx::migrate!().run(pool).await?;
        Ok(())
    }

    /// Build a store against the `DATABASE_URL` Postgres, or `None` when
    /// `DATABASE_URL` is unset. If it IS set, connection or migration
    /// failures panic instead of skipping, so a broken database or broken
    /// DDL can never masquerade as a skipped test. Each test uses its own
    /// user id so parallel tests never share rows.
    async fn test_store() -> Option<PostgresPasskeyStore> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&url)
            .await
            .expect("DATABASE_URL is set but Postgres is unreachable");
        apply_ddl(&pool)
            .await
            .expect("passkeys migration must apply");
        Some(PostgresPasskeyStore::new(pool))
    }

    macro_rules! require_store {
        () => {
            match test_store().await {
                Some(store) => store,
                None => {
                    eprintln!("skipping postgres passkey test: DATABASE_URL unset");
                    return;
                }
            }
        };
    }

    /// A structurally valid (not cryptographically real) passkey, mirroring
    /// the fixture in `super::webauthn` tests. Good enough to exercise the
    /// storage layer; it will never pass cryptographic verification.
    fn fixture_passkey() -> Passkey {
        let fixture = serde_json::json!({
            "cred": {
                "cred_id": "dGVzdC1jcmVkZW50aWFsLWlk",
                "cred": {
                    "type_": "ES256",
                    "key": {
                        "EC_EC2": {
                            "curve": "SECP256R1",
                            "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                            "y": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                        }
                    }
                },
                "counter": 0,
                "transports": null,
                "user_verified": true,
                "backup_eligible": false,
                "backup_state": false,
                "registration_policy": "required",
                "extensions": {},
                "attestation": { "data": "None", "metadata": "None" },
                "attestation_format": "none"
            }
        });
        serde_json::from_value(fixture).expect("fixture passkey must deserialise")
    }

    fn unique_user() -> String {
        format!("pg-test-user-{}", Uuid::new_v4())
    }

    #[tokio::test]
    async fn save_and_fetch_round_trip_without_loss() {
        let store = require_store!();
        let user_id = unique_user();
        let passkey = fixture_passkey();
        let record = PasskeyRecord::new(user_id.clone(), passkey.clone());

        store.save_passkey(record.clone()).await.unwrap();

        let fetched = store.get_passkeys(&user_id).await.unwrap();
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].user_id, user_id);
        assert_eq!(fetched[0].cred_id, record.cred_id);

        // The JSONB column must round-trip the passkey without loss.
        assert_eq!(
            serde_json::to_value(&fetched[0].passkey).unwrap(),
            serde_json::to_value(&passkey).unwrap()
        );

        store
            .delete_passkey(&user_id, &record.cred_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn duplicate_save_errors_and_keeps_single_row() {
        let store = require_store!();
        let user_id = unique_user();
        let record = PasskeyRecord::new(user_id.clone(), fixture_passkey());

        store.save_passkey(record.clone()).await.unwrap();
        // The `(user_id, cred_id)` primary key rejects the duplicate with an
        // error; the stored row count must not change.
        assert!(store.save_passkey(record.clone()).await.is_err());

        let fetched = store.get_passkeys(&user_id).await.unwrap();
        assert_eq!(fetched.len(), 1);

        store
            .delete_passkey(&user_id, &record.cred_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn fetch_is_scoped_to_user() {
        let store = require_store!();
        let alice = unique_user();
        let bob = unique_user();
        let record_a = PasskeyRecord::new(alice.clone(), fixture_passkey());
        let record_b = PasskeyRecord::new(bob.clone(), fixture_passkey());

        store.save_passkey(record_a.clone()).await.unwrap();
        store.save_passkey(record_b.clone()).await.unwrap();

        let fetched_a = store.get_passkeys(&alice).await.unwrap();
        assert_eq!(fetched_a.len(), 1);
        assert_eq!(fetched_a[0].user_id, alice);

        let fetched_b = store.get_passkeys(&bob).await.unwrap();
        assert_eq!(fetched_b.len(), 1);
        assert_eq!(fetched_b[0].user_id, bob);

        store
            .delete_passkey(&alice, &record_a.cred_id)
            .await
            .unwrap();
        store.delete_passkey(&bob, &record_b.cred_id).await.unwrap();
    }

    #[tokio::test]
    async fn update_persists_counter_and_stamps_last_used() {
        let store = require_store!();
        let user_id = unique_user();
        let record = PasskeyRecord::new(user_id.clone(), fixture_passkey());
        store.save_passkey(record.clone()).await.unwrap();

        // Simulate what `refresh_passkey` does after a live ceremony: the
        // sign counter inside the stored passkey advances.
        let mut passkey_json = serde_json::to_value(&record.passkey).unwrap();
        passkey_json["cred"]["counter"] = serde_json::json!(42);
        let advanced: Passkey = serde_json::from_value(passkey_json).unwrap();
        let mut updated = record.clone();
        updated.passkey = advanced;

        store.update_passkey(&updated).await.unwrap();

        let fetched = store.get_passkeys(&user_id).await.unwrap();
        assert_eq!(fetched.len(), 1);
        let fetched_json = serde_json::to_value(&fetched[0].passkey).unwrap();
        assert_eq!(fetched_json["cred"]["counter"], 42);

        let stamped: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT last_used_at FROM passkeys WHERE user_id = $1 AND cred_id = $2",
        )
        .bind(&user_id)
        .bind(&record.cred_id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert!(stamped.is_some(), "update must stamp last_used_at");

        // Updating a credential that was never saved fails loudly, matching
        // the in-memory store.
        let mut unknown = updated.clone();
        unknown.cred_id = "bm90LXJlZ2lzdGVyZWQ".to_string();
        assert!(store.update_passkey(&unknown).await.is_err());

        store
            .delete_passkey(&user_id, &record.cred_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_removes_credential() {
        let store = require_store!();
        let user_id = unique_user();
        let record = PasskeyRecord::new(user_id.clone(), fixture_passkey());

        store.save_passkey(record.clone()).await.unwrap();
        store
            .delete_passkey(&user_id, &record.cred_id)
            .await
            .unwrap();
        assert!(store.get_passkeys(&user_id).await.unwrap().is_empty());

        // Deleting a missing credential is a no-op, like the in-memory store.
        store
            .delete_passkey(&user_id, &record.cred_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn factory_selects_backend_from_config() {
        // The memory backend never needs a database.
        let memory = connect_passkey_store(PasskeyStoreKind::Memory, "", 1)
            .await
            .expect("memory backend must build without a database");
        let user_id = unique_user();
        memory
            .save_passkey(PasskeyRecord::new(user_id.clone(), fixture_passkey()))
            .await
            .unwrap();
        assert_eq!(memory.get_passkeys(&user_id).await.unwrap().len(), 1);

        // The Postgres backend needs a live database; skip without one.
        if std::env::var("DATABASE_URL").is_err() {
            eprintln!("skipping postgres factory check: DATABASE_URL unset");
            return;
        }
        let url = std::env::var("DATABASE_URL").unwrap();
        // The factory only connects; apply the table DDL on a scratch pool so
        // the table exists for the round-trip below.
        let scratch = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .expect("scratch pool must connect with DATABASE_URL set");
        apply_ddl(&scratch).await.expect("passkeys DDL must apply");
        scratch.close().await;
        let pg = connect_passkey_store(PasskeyStoreKind::Postgres, &url, 5)
            .await
            .expect("postgres backend must connect with DATABASE_URL set");
        let user_id = unique_user();
        let record = PasskeyRecord::new(user_id.clone(), fixture_passkey());
        pg.save_passkey(record.clone()).await.unwrap();
        assert_eq!(pg.get_passkeys(&user_id).await.unwrap().len(), 1);
        pg.delete_passkey(&user_id, &record.cred_id).await.unwrap();
    }
}
