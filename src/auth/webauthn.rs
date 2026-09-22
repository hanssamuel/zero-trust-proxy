// The items in this module are the passkey ceremony API, consumed by the
// passkey HTTP handlers once they are wired up (see the walkthrough in the
// module docs). Until then the binary does not call them yet, hence this.
#![allow(dead_code)]

//! WebAuthn / passkey authentication.
//!
//! This module wraps `webauthn-rs` and exposes the two ceremonies needed for
//! passwordless sign-in:
//!
//! 1. **Registration** ([`WebauthnManager::start_passkey_registration`] /
//!    [`WebauthnManager::finish_passkey_registration`]): the user enrols an
//!    authenticator (platform passkey or security key). The finished
//!    [`Passkey`] is persisted through a [`PasskeyStore`].
//! 2. **Authentication** ([`WebauthnManager::start_passkey_authentication`] /
//!    [`WebauthnManager::finish_passkey_authentication`]): the user proves
//!    possession of the private key. On success the caller refreshes the stored
//!    sign counter via [`refresh_passkey`] and mints a JWT with
//!    `mfa_verified = true` (these ceremonies require user verification by
//!    policy, so a successful authentication already satisfies the MFA factor).
//!
//! Challenge state ([`PasskeyRegistration`] / [`PasskeyAuthentication`]) is
//! opaque to the caller: it must be held server-side between the start and
//! finish calls (in memory, in Redis, or serialised as JSON into a session)
//! and is single-use. It is deliberately NOT part of [`PasskeyStore`]; only
//! finished credentials are stored there.
//!
//! Serialising challenge state to JSON needs the webauthn-rs cargo feature
//! `danger-allow-state-serialisation`, which this crate enables. The name is
//! the upstream crate's warning, not ours: state blobs must stay server-side.

use crate::auth::JwtManager;
use crate::config::WebauthnConfig;
use crate::error::{ProxyError, ProxyResult};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;
use webauthn_rs::prelude::*;

fn ceremony_err(e: WebauthnError) -> ProxyError {
    ProxyError::AuthenticationFailed(format!("webauthn ceremony failed: {e}"))
}

/// A finished passkey credential as the proxy stores it.
///
/// `cred_id` is the base64url credential ID, the primary key within a user's
/// credential set. `passkey` is the `webauthn_rs::Passkey` (credential public
/// key plus sign counter) and serialises cleanly to JSON, which is how a
/// Postgres backend would hold it in a `JSONB` column.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyRecord {
    pub user_id: String,
    pub cred_id: String,
    pub passkey: Passkey,
}

impl PasskeyRecord {
    pub fn new(user_id: String, passkey: Passkey) -> Self {
        let raw: &[u8] = passkey.cred_id().as_ref();
        let cred_id = URL_SAFE_NO_PAD.encode(raw);
        Self {
            user_id,
            cred_id,
            passkey,
        }
    }
}

/// Persistent storage for finished passkey credentials.
///
/// The ceremony logic ([`WebauthnManager`]) only depends on this trait, never
/// on a concrete backend, so the proxy can run against Postgres, Redis, or an
/// in-memory map without changing ceremony code.
///
/// Only finished credentials are stored here. Short-lived ceremony state is
/// the caller's responsibility and is NOT part of this trait.
///
/// A Postgres implementation maps one row per credential:
/// `(user_id TEXT, cred_id TEXT, passkey JSONB, created_at TIMESTAMPTZ,
/// last_used_at TIMESTAMPTZ, PRIMARY KEY (user_id, cred_id))`.
/// See `migrations/001_passkeys.sql` for the table definition.
pub trait PasskeyStore: Send + Sync {
    /// Persist a newly registered passkey. `(user_id, cred_id)` is unique.
    async fn save_passkey(&self, record: PasskeyRecord) -> ProxyResult<()>;
    /// Every passkey enrolled by a user (the allow-list for authentication).
    async fn get_passkeys(&self, user_id: &str) -> ProxyResult<Vec<PasskeyRecord>>;
    /// Persist sign-counter / metadata changes after an authentication.
    async fn update_passkey(&self, record: &PasskeyRecord) -> ProxyResult<()>;
    /// Remove a credential (user-initiated unenrolment).
    async fn delete_passkey(&self, user_id: &str, cred_id: &str) -> ProxyResult<()>;
}

/// In-memory [`PasskeyStore`] backed by a tokio `RwLock`-guarded map.
///
/// Intended for development and tests only: credentials live in process
/// memory, so every registered passkey is lost on restart and nothing is
/// shared between instances. For persistence across restarts use
/// [`PostgresPasskeyStore`](super::passkey_store_pg::PostgresPasskeyStore),
/// which stores credentials in Postgres using the schema in
/// `migrations/001_passkeys.sql`.
#[derive(Debug, Default)]
pub struct InMemoryPasskeyStore {
    inner: RwLock<HashMap<(String, String), PasskeyRecord>>,
}

impl InMemoryPasskeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(user_id: &str, cred_id: &str) -> (String, String) {
        (user_id.to_string(), cred_id.to_string())
    }
}

impl PasskeyStore for InMemoryPasskeyStore {
    async fn save_passkey(&self, record: PasskeyRecord) -> ProxyResult<()> {
        self.inner
            .write()
            .await
            .insert(Self::key(&record.user_id, &record.cred_id), record);
        Ok(())
    }

    async fn get_passkeys(&self, user_id: &str) -> ProxyResult<Vec<PasskeyRecord>> {
        Ok(self
            .inner
            .read()
            .await
            .iter()
            .filter(|((uid, _), _)| uid == user_id)
            .map(|(_, record)| record.clone())
            .collect())
    }

    async fn update_passkey(&self, record: &PasskeyRecord) -> ProxyResult<()> {
        let mut guard = self.inner.write().await;
        if let std::collections::hash_map::Entry::Occupied(mut entry) =
            guard.entry(Self::key(&record.user_id, &record.cred_id))
        {
            entry.insert(record.clone());
            Ok(())
        } else {
            Err(ProxyError::AuthenticationFailed(format!(
                "unknown passkey credential {} for user {}",
                record.cred_id, record.user_id
            )))
        }
    }

    async fn delete_passkey(&self, user_id: &str, cred_id: &str) -> ProxyResult<()> {
        self.inner
            .write()
            .await
            .remove(&Self::key(user_id, cred_id));
        Ok(())
    }
}

/// Wraps `webauthn-rs` for the proxy's passkey ceremonies.
///
/// Build once at startup from [`WebauthnConfig`]:
/// `WebauthnManager::new(config.webauthn)`.
pub struct WebauthnManager {
    webauthn: Webauthn,
}

impl WebauthnManager {
    /// Build the manager from relying-party config. Fails when `rp_origin` is
    /// not a parseable URL.
    pub fn new(config: WebauthnConfig) -> ProxyResult<Self> {
        let rp_origin = url::Url::parse(&config.rp_origin).map_err(|e| {
            ProxyError::AuthenticationFailed(format!("invalid webauthn rp_origin: {e}"))
        })?;
        let webauthn = WebauthnBuilder::new(&config.rp_id, &rp_origin)
            .map_err(ceremony_err)?
            .rp_name(&config.rp_name)
            .build()
            .map_err(ceremony_err)?;
        Ok(Self { webauthn })
    }

    /// Begin passkey registration for a user.
    ///
    /// Returns the creation-challenge response (serialise to JSON and hand to
    /// the browser via `navigator.credentials.create`) plus opaque state the
    /// server must hold until [`WebauthnManager::finish_passkey_registration`].
    /// `exclude` should be the user's already-enrolled passkeys so the
    /// authenticator refuses to re-register an existing credential.
    pub fn start_passkey_registration(
        &self,
        user_id: Uuid,
        username: &str,
        display_name: &str,
        exclude: &[Passkey],
    ) -> ProxyResult<(CreationChallengeResponse, PasskeyRegistration)> {
        let exclude_ids: Vec<CredentialID> = exclude
            .iter()
            .map(|passkey| passkey.cred_id().clone())
            .collect();
        self.webauthn
            .start_passkey_registration(user_id, username, display_name, Some(exclude_ids))
            .map_err(ceremony_err)
    }

    /// Complete passkey registration.
    ///
    /// `response` is the `RegisterPublicKeyCredential` the browser posts back
    /// (deserialise it from the request body). On success returns the
    /// [`Passkey`] to persist via [`PasskeyStore::save_passkey`].
    //
    // Only used by the passkey HTTP handlers (not yet wired); kept public as
    // the second half of the registration ceremony.
    pub fn finish_passkey_registration(
        &self,
        response: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> ProxyResult<Passkey> {
        self.webauthn
            .finish_passkey_registration(response, state)
            .map_err(ceremony_err)
    }

    /// Begin passkey authentication for the user's enrolled credentials.
    ///
    /// Returns the request-challenge response (serialise to JSON for
    /// `navigator.credentials.get`) plus opaque state the server must hold
    /// until [`WebauthnManager::finish_passkey_authentication`].
    ///
    /// Fails closed when the user has no enrolled credentials: an empty
    /// credential list is never a valid login attempt.
    pub fn start_passkey_authentication(
        &self,
        passkeys: &[Passkey],
    ) -> ProxyResult<(RequestChallengeResponse, PasskeyAuthentication)> {
        if passkeys.is_empty() {
            return Err(ProxyError::AuthenticationFailed(
                "no passkeys enrolled for this user".to_string(),
            ));
        }
        self.webauthn
            .start_passkey_authentication(passkeys)
            .map_err(ceremony_err)
    }

    /// Complete passkey authentication.
    ///
    /// `response` is the `PublicKeyCredential` the browser posts back. On
    /// success returns the [`AuthenticationResult`]; the caller MUST then call
    /// [`refresh_passkey`] so the stored sign counter advances (a stale or
    /// replayed counter is how cloned credentials are detected).
    //
    // Only used by the passkey HTTP handlers (not yet wired); kept public as
    // the second half of the authentication ceremony.
    pub fn finish_passkey_authentication(
        &self,
        response: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> ProxyResult<AuthenticationResult> {
        self.webauthn
            .finish_passkey_authentication(response, state)
            .map_err(ceremony_err)
    }
}

/// Apply a successful authentication result to the stored credential.
///
/// Applies the sign-counter update from `result` to the record's passkey and
/// persists it through `store`. Call this after
/// [`WebauthnManager::finish_passkey_authentication`] succeeds; a stale or
/// replayed counter is the signal for a cloned credential.
//
// Only used by the passkey HTTP handlers (not yet wired); kept public as part
// of the ceremony API.
pub async fn refresh_passkey<S: PasskeyStore>(
    store: &S,
    record: &mut PasskeyRecord,
    result: &AuthenticationResult,
) -> ProxyResult<()> {
    record.passkey.update_credential(result);
    store.update_passkey(record).await
}

/// Mint a session JWT after a successful passkey authentication.
///
/// Passkey ceremonies in this proxy require user verification by policy, so a
/// successful authentication already satisfies the MFA factor: the token is
/// minted with `mfa_verified = true`.
pub fn mint_passkey_jwt(
    jwt_manager: &JwtManager,
    user_id: &str,
    device_id: &str,
    session_id: &str,
    risk_score: u32,
) -> ProxyResult<String> {
    jwt_manager.generate_token(user_id, device_id, risk_score, true, session_id)
}

/// Full ceremony walkthrough (untested against a live authenticator; see unit
/// tests below for what is covered):
///
/// ```text
/// // 1. Registration, start: the browser needs the creation challenge.
/// let (challenge, state) = manager.start_passkey_registration(
///     user.id, &user.username, &user.username, &existing_passkeys)?;
/// //    -> POST challenge as JSON to the browser; stash `state` server-side
/// //       (JSON-serialised into Redis or the session) keyed to this attempt.
///
/// // 2. Registration, finish: the browser posts back its response.
/// let state: PasskeyRegistration = /* restore the stashed state */;
/// let response: RegisterPublicKeyCredential = /* from the request body */;
/// let passkey = manager.finish_passkey_registration(&response, &state)?;
/// store.save_passkey(PasskeyRecord::new(user.id.to_string(), passkey)).await?;
///
/// // 3. Authentication, start.
/// let records = store.get_passkeys(&user.id.to_string()).await?;
/// let passkeys: Vec<Passkey> = records.iter().map(|r| r.passkey.clone()).collect();
/// let (challenge, state) = manager.start_passkey_authentication(&passkeys)?;
/// //    -> POST challenge as JSON; stash `state` server-side.
///
/// // 4. Authentication, finish: the browser posts back its assertion.
/// let mut record = /* the record whose cred_id matches the assertion */;
/// let result = manager.finish_passkey_authentication(&response, &state)?;
/// refresh_passkey(store, &mut record, &result).await?;
///
/// // 5. The user is now authenticated AND MFA-verified: mint the session JWT.
/// let token = mint_passkey_jwt(&jwt_manager, &user.id.to_string(), device_id, session_id, risk_score)?;
/// ```
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PasskeyStoreKind;

    fn test_manager() -> WebauthnManager {
        WebauthnManager::new(WebauthnConfig {
            rp_id: "example.com".to_string(),
            rp_origin: "https://example.com".to_string(),
            rp_name: "Test Proxy".to_string(),
            enabled: true,
            passkey_store: PasskeyStoreKind::Memory,
        })
        .expect("test webauthn manager must build")
    }

    /// A structurally valid (not cryptographically real) passkey, built by
    /// deserialising the same JSON shape a real `finish_passkey_registration`
    /// would produce. Good enough to exercise the storage trait and the
    /// challenge plumbing; it will never pass cryptographic verification.
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

    #[test]
    fn rejects_invalid_rp_origin() {
        let config = WebauthnConfig {
            rp_origin: "://not-a-url".to_string(),
            ..WebauthnConfig::default()
        };
        assert!(WebauthnManager::new(config).is_err());
    }

    #[test]
    fn registration_challenge_is_browser_json_and_state_round_trips() {
        let manager = test_manager();
        let (challenge, state) = manager
            .start_passkey_registration(Uuid::new_v4(), "alice", "Alice", &[])
            .expect("registration start must succeed");

        // The challenge goes to the browser as JSON.
        let challenge_json = serde_json::to_value(&challenge).expect("challenge must serialise");
        assert!(challenge_json.get("publicKey").is_some());

        // The state is held server-side; it must survive a JSON round trip
        // (e.g. stashed in Redis between the start and finish calls).
        let state_json = serde_json::to_string(&state).expect("state must serialise");
        let restored: PasskeyRegistration =
            serde_json::from_str(&state_json).expect("state must deserialise");
        assert_eq!(
            serde_json::to_string(&restored).unwrap(),
            state_json,
            "state must be identical after a JSON round trip"
        );
    }

    #[test]
    fn authentication_needs_enrolled_credentials() {
        let manager = test_manager();
        // No credentials to challenge against: the ceremony cannot start.
        assert!(manager.start_passkey_authentication(&[]).is_err());
    }

    #[test]
    fn authentication_challenge_lists_enrolled_credential_ids() {
        let manager = test_manager();
        let passkey = fixture_passkey();
        let (challenge, state) = manager
            .start_passkey_authentication(std::slice::from_ref(&passkey))
            .expect("authentication start must succeed");

        let challenge_json = serde_json::to_value(&challenge).expect("challenge must serialise");
        let allow: Vec<&str> = challenge_json["publicKey"]["allowCredentials"]
            .as_array()
            .expect("allowCredentials must be an array")
            .iter()
            .map(|cred| cred["id"].as_str().expect("credential id must be a string"))
            .collect();
        assert_eq!(allow.len(), 1);
        assert_eq!(allow[0], "dGVzdC1jcmVkZW50aWFsLWlk");

        // Auth state survives the same server-side JSON round trip.
        let state_json = serde_json::to_string(&state).expect("state must serialise");
        let restored: PasskeyAuthentication =
            serde_json::from_str(&state_json).expect("state must deserialise");
        assert_eq!(serde_json::to_string(&restored).unwrap(), state_json);
    }

    #[tokio::test]
    async fn in_memory_store_round_trip() {
        let store = InMemoryPasskeyStore::new();
        let record = PasskeyRecord::new("user-1".to_string(), fixture_passkey());

        // Empty store: no credentials for the user.
        assert!(store.get_passkeys("user-1").await.unwrap().is_empty());

        // Save and read back.
        store.save_passkey(record.clone()).await.unwrap();
        let fetched = store.get_passkeys("user-1").await.unwrap();
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].cred_id, record.cred_id);
        assert_eq!(fetched[0].user_id, "user-1");

        // Other users are isolated.
        assert!(store.get_passkeys("user-2").await.unwrap().is_empty());

        // Update of an unknown credential fails loudly.
        let mut unknown = record.clone();
        unknown.cred_id = "bm90LXJlZ2lzdGVyZWQ".to_string();
        assert!(store.update_passkey(&unknown).await.is_err());

        // Update of a known credential succeeds (idempotent re-save of the
        // same record). Sign-counter advancement via `refresh_passkey` needs a
        // real AuthenticationResult from a live ceremony, so it is covered by
        // integration, not here.
        store.update_passkey(&record).await.unwrap();
        let fetched = store.get_passkeys("user-1").await.unwrap();
        assert_eq!(fetched.len(), 1);

        // Delete removes it.
        store
            .delete_passkey("user-1", &record.cred_id)
            .await
            .unwrap();
        assert!(store.get_passkeys("user-1").await.unwrap().is_empty());
    }

    #[test]
    fn passkey_jwt_is_mfa_verified() {
        use crate::auth::JwtManager;
        let jwt = JwtManager::new("test_secret".to_string(), 24);
        let token = mint_passkey_jwt(&jwt, "user-1", "device-1", "session-1", 10).unwrap();
        let claims = jwt.validate_token(&token).unwrap();
        assert_eq!(claims.sub, "user-1");
        assert!(claims.mfa_verified);
    }

    #[test]
    fn excluded_credentials_are_not_rechallenged() {
        let manager = test_manager();
        let existing = fixture_passkey();
        let (challenge, _) = manager
            .start_passkey_registration(
                Uuid::new_v4(),
                "alice",
                "Alice",
                std::slice::from_ref(&existing),
            )
            .expect("registration start must succeed");

        let challenge_json = serde_json::to_value(&challenge).unwrap();
        let excluded: Vec<&str> = challenge_json["publicKey"]["excludeCredentials"]
            .as_array()
            .expect("excludeCredentials must be an array")
            .iter()
            .map(|cred| cred["id"].as_str().expect("credential id must be a string"))
            .collect();
        assert_eq!(excluded, vec!["dGVzdC1jcmVkZW50aWFsLWlk"]);
    }
}
