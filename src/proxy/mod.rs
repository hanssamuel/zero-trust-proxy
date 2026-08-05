use crate::audit::AuditLogger;
use crate::auth::device::{DeviceFingerprint, DeviceMetadata};
use crate::auth::mfa::{MfaConfig, TotpManager};
use crate::auth::session::SessionManager;
use crate::auth::{hash_password, verify_password, Claims, JwtManager, LoginResponse};
use crate::config::Config;
use crate::db;
use crate::error::ProxyError;
use crate::policy::{Effect, Policy, PolicyContext, PolicyEngine, PolicyRule};
use crate::risk::{RiskContext, RiskEngine, RiskLevel, RiskRecommendation, RiskScore};
use anyhow::Result;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, HOST, USER_AGENT};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};
use uuid::Uuid;

type HttpClient = Client<HttpConnector, Full<Bytes>>;

pub struct ProxyServer {
    config: Arc<Config>,
    db_pool: PgPool,
    redis_conn: ConnectionManager,
    jwt_manager: JwtManager,
    policy_engine: Arc<PolicyEngine>,
    risk_engine: Arc<RiskEngine>,
    audit_logger: Arc<AuditLogger>,
    http_client: HttpClient,
}

impl ProxyServer {
    pub fn new(config: Config, db_pool: PgPool, redis_conn: ConnectionManager) -> Self {
        let jwt_manager = JwtManager::new(
            config.auth.jwt_secret.clone(),
            config.auth.jwt_expiration_hours,
        );
        let policy_engine = Arc::new(build_default_policy_engine(config.policy.default_deny));
        let risk_engine = Arc::new(RiskEngine::new(
            config.risk.step_up_threshold,
            config.risk.block_threshold,
        ));
        let audit_logger = Arc::new(AuditLogger::new(db_pool.clone()));
        let http_client: HttpClient = Client::builder(TokioExecutor::new()).build_http();

        Self {
            config: Arc::new(config),
            db_pool,
            redis_conn,
            jwt_manager,
            policy_engine,
            risk_engine,
            audit_logger,
            http_client,
        }
    }

    pub async fn serve(self, addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        let tls_acceptor = self.build_tls_acceptor()?;
        let server = Arc::new(self);

        loop {
            let (stream, remote_addr) = listener.accept().await?;
            let server = Arc::clone(&server);
            let tls_acceptor = tls_acceptor.clone();

            tokio::spawn(async move {
                match tls_acceptor {
                    Some(acceptor) => match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            serve_connection(TokioIo::new(tls_stream), server, remote_addr).await;
                        }
                        Err(err) => error!("TLS handshake failed from {}: {:?}", remote_addr, err),
                    },
                    None => {
                        serve_connection(TokioIo::new(stream), server, remote_addr).await;
                    }
                }
            });
        }
    }

    fn build_tls_acceptor(&self) -> Result<Option<TlsAcceptor>> {
        if !self.config.server.enable_tls {
            return Ok(None);
        }

        let cert_path =
            self.config.server.tls_cert.as_ref().ok_or_else(|| {
                anyhow::anyhow!("server.enable_tls is true but tls_cert is not set")
            })?;
        let key_path =
            self.config.server.tls_key.as_ref().ok_or_else(|| {
                anyhow::anyhow!("server.enable_tls is true but tls_key is not set")
            })?;

        let certs = load_certs(cert_path)?;
        let key = load_private_key(key_path)?;

        let tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        Ok(Some(TlsAcceptor::from(Arc::new(tls_config))))
    }

    async fn handle_request(
        &self,
        req: Request<Incoming>,
        remote_addr: SocketAddr,
    ) -> Response<Full<Bytes>> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();

        info!("📨 {} {} from {}", method, path, remote_addr);

        if path == "/health" {
            return text_response(StatusCode::OK, "OK");
        }
        if path == "/metrics" {
            return self.handle_metrics();
        }

        let result = if path == "/auth/login" && method == Method::POST {
            self.handle_login(req, remote_addr).await
        } else if path == "/auth/register" && method == Method::POST {
            self.handle_register(req, remote_addr).await
        } else if path == "/auth/mfa/enroll" && method == Method::POST {
            self.handle_mfa_enroll(req).await
        } else if path == "/auth/mfa/verify" && method == Method::POST {
            self.handle_mfa_verify(req, remote_addr).await
        } else if path == "/auth/logout" && method == Method::POST {
            self.handle_logout(req).await
        } else if path == "/auth/logout_all" && method == Method::POST {
            self.handle_logout_all(req).await
        } else {
            match self.authorize(&req, &method, &path, remote_addr).await {
                Ok(()) => self.forward_upstream(req).await,
                Err(e) => Err(e),
            }
        };

        result.unwrap_or_else(error_response)
    }

    fn handle_metrics(&self) -> Response<Full<Bytes>> {
        let metrics = "# Zero-Trust Proxy Metrics\n\
                      ztp_requests_total 0\n\
                      ztp_auth_failures_total 0\n";
        text_response(StatusCode::OK, metrics)
    }

    /// The zero-trust gate every non-public request goes through:
    /// valid JWT -> live (non-expired) session -> policy allow -> risk check.
    async fn authorize(
        &self,
        req: &Request<Incoming>,
        method: &Method,
        path: &str,
        remote_addr: SocketAddr,
    ) -> Result<(), ProxyError> {
        let auth_header = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let token = self.jwt_manager.extract_token_from_header(auth_header)?;
        let claims = self.jwt_manager.validate_token(&token)?;

        let mut session_manager = SessionManager::new(
            self.redis_conn.clone(),
            self.config.auth.session_duration_minutes,
        );
        let session = session_manager.get_session(&claims.session_id).await?;

        if session.user_id != claims.sub {
            return Err(ProxyError::InvalidSession(
                "session/token subject mismatch".to_string(),
            ));
        }

        let policy_ctx = PolicyContext {
            user_id: claims.sub.clone(),
            resource: path.to_string(),
            action: method.as_str().to_lowercase(),
            attributes: std::collections::HashMap::new(),
        };
        let decision = self.policy_engine.evaluate(&policy_ctx)?;
        if !decision.allowed {
            self.audit_logger
                .log_authorization(
                    &claims.sub,
                    &remote_addr.ip().to_string(),
                    path,
                    method.as_str(),
                    false,
                    session.risk_score,
                )
                .await
                .ok();
            return Err(ProxyError::AuthorizationDenied(decision.reason));
        }

        let risk = self.evaluate_request_risk(&session, remote_addr, &claims);
        self.audit_logger
            .log_risk_evaluation(
                &claims.sub,
                &claims.device_id,
                &remote_addr.ip().to_string(),
                risk.total_score,
                serde_json::json!({ "factors": risk.factors }),
            )
            .await
            .ok();

        // Global require_mfa hard-gates every protected resource. It does NOT
        // gate login itself (see handle_login) -- otherwise a fresh user with
        // no enrolled TOTP secret could never log in to reach the enroll
        // endpoint in the first place.
        if self.config.auth.require_mfa && !session.mfa_verified {
            return Err(ProxyError::MfaRequired);
        }

        match risk.recommendation {
            RiskRecommendation::Block => {
                self.audit_logger
                    .log_authorization(
                        &claims.sub,
                        &remote_addr.ip().to_string(),
                        path,
                        method.as_str(),
                        false,
                        risk.total_score,
                    )
                    .await
                    .ok();
                Err(ProxyError::RiskThresholdExceeded {
                    score: risk.total_score,
                    threshold: self.config.risk.block_threshold,
                })
            }
            RiskRecommendation::StepUpAuth if !session.mfa_verified => Err(ProxyError::MfaRequired),
            _ => {
                self.audit_logger
                    .log_authorization(
                        &claims.sub,
                        &remote_addr.ip().to_string(),
                        path,
                        method.as_str(),
                        true,
                        risk.total_score,
                    )
                    .await
                    .ok();
                Ok(())
            }
        }
    }

    /// Approximates a live device fingerprint from the current request and
    /// scores risk against the session's history. This is a simplification:
    /// device trust isn't persisted across logins yet (see docs/README), so
    /// "trusted" here only means "same device_id as the one that logged in".
    fn evaluate_request_risk(
        &self,
        session: &crate::auth::session::Session,
        remote_addr: SocketAddr,
        claims: &Claims,
    ) -> RiskScore {
        let metadata = DeviceMetadata {
            screen_resolution: None,
            timezone: None,
            language: None,
            platform_version: None,
            hardware_concurrency: None,
        };
        let mut device = DeviceFingerprint::new(
            claims.sub.clone(),
            session.user_agent.clone(),
            remote_addr.ip().to_string(),
            metadata,
        );
        device.trust_score = if claims.device_id == session.device_id {
            70
        } else {
            40
        };
        device.is_trusted = device.trust_score >= 70;

        let session_age_minutes = (chrono::Utc::now() - session.created_at).num_minutes();

        let ctx = RiskContext {
            user_id: claims.sub.clone(),
            device,
            ip_address: remote_addr.ip(),
            timestamp: chrono::Utc::now(),
            geolocation: None,
            previous_ip: session.ip_address.parse().ok(),
            session_age_minutes,
            failed_attempts: 0,
            time_since_last_success_hours: None,
        };

        self.risk_engine.calculate_risk(&ctx).unwrap_or(RiskScore {
            total_score: 0,
            factors: vec![],
            level: RiskLevel::Low,
            recommendation: RiskRecommendation::Allow,
        })
    }

    async fn forward_upstream(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, ProxyError> {
        let (parts, body) = req.into_parts();
        let body_bytes = body
            .collect()
            .await
            .map_err(|_| ProxyError::InternalError)?
            .to_bytes();

        let upstream_base = self.config.upstream.default_backend.trim_end_matches('/');
        let path_and_query = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let upstream_uri: Uri = format!("{}{}", upstream_base, path_and_query)
            .parse()
            .map_err(|_| ProxyError::InternalError)?;

        let mut builder = Request::builder()
            .method(parts.method.clone())
            .uri(upstream_uri);
        for (name, value) in parts.headers.iter() {
            if name == HOST {
                continue;
            }
            builder = builder.header(name, value);
        }
        let upstream_req = builder
            .body(Full::new(body_bytes))
            .map_err(|_| ProxyError::InternalError)?;

        let upstream_resp = self.http_client.request(upstream_req).await.map_err(|e| {
            error!("upstream request failed: {:?}", e);
            ProxyError::InternalError
        })?;

        let (resp_parts, resp_body) = upstream_resp.into_parts();
        let resp_bytes = resp_body
            .collect()
            .await
            .map_err(|_| ProxyError::InternalError)?
            .to_bytes();

        Ok(Response::from_parts(resp_parts, Full::new(resp_bytes)))
    }

    /// Fixed-window counter in Redis, keyed by (bucket, source IP). Used to
    /// throttle the auth endpoints -- login/register/MFA verify are the only
    /// places an attacker gets unlimited guesses without a valid token.
    async fn check_rate_limit(
        &self,
        remote_addr: SocketAddr,
        bucket: &str,
        limit: i64,
        window_secs: i64,
    ) -> Result<(), ProxyError> {
        let key = format!("ratelimit:{}:{}", bucket, remote_addr.ip());
        let mut conn = self.redis_conn.clone();
        let count: i64 = conn.incr(&key, 1).await?;
        if count == 1 {
            let _: () = conn.expire(&key, window_secs).await?;
        }
        if count > limit {
            return Err(ProxyError::RateLimitExceeded);
        }
        Ok(())
    }

    async fn handle_login(
        &self,
        req: Request<Incoming>,
        remote_addr: SocketAddr,
    ) -> Result<Response<Full<Bytes>>, ProxyError> {
        self.check_rate_limit(remote_addr, "login", 10, 300).await?;

        let (parts, body) = req.into_parts();
        let user_agent = parts
            .headers
            .get(USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string();
        let body_bytes = body
            .collect()
            .await
            .map_err(|_| ProxyError::InternalError)?
            .to_bytes();
        let login_body: LoginBody = serde_json::from_slice(&body_bytes)
            .map_err(|_| ProxyError::AuthenticationFailed("invalid request body".to_string()))?;

        let user = db::find_user_by_username(&self.db_pool, &login_body.username)
            .await?
            .filter(|u| u.is_active)
            .ok_or_else(|| ProxyError::AuthenticationFailed("invalid credentials".to_string()))?;

        // Built before the password check so a failed attempt can decay this
        // device's trust score too, not just successful ones.
        let metadata = DeviceMetadata {
            screen_resolution: None,
            timezone: None,
            language: None,
            platform_version: None,
            hardware_concurrency: None,
        };
        let mut device = DeviceFingerprint::new(
            user.id.to_string(),
            user_agent.clone(),
            remote_addr.ip().to_string(),
            metadata,
        );
        let existing_device =
            db::find_device_by_fingerprint(&self.db_pool, user.id, &device.fingerprint_hash)
                .await?;
        if let Some(existing) = &existing_device {
            device.trust_score = existing.trust_score.max(0) as u32;
            device.is_trusted = existing.is_trusted;
        }

        if !verify_password(&login_body.password, &user.password_hash)? {
            device.decrease_trust(15);
            db::upsert_device(
                &self.db_pool,
                user.id,
                &device.fingerprint_hash,
                &device.user_agent,
                &device.platform,
                &device.browser,
                &remote_addr.ip().to_string(),
                device.trust_score as i32,
                device.is_trusted,
            )
            .await?;
            self.audit_logger
                .log_authentication(
                    &user.id.to_string(),
                    login_body.device_id.as_deref().unwrap_or("unknown"),
                    &remote_addr.ip().to_string(),
                    false,
                )
                .await
                .ok();
            return Err(ProxyError::AuthenticationFailed(
                "invalid credentials".to_string(),
            ));
        }

        // Only gate login on MFA if this user has actually enrolled a TOTP
        // secret. The global require_mfa flag is enforced per-request in
        // authorize() instead -- gating it here too would permanently lock
        // out any user who hasn't enrolled yet, since enrolling requires
        // being logged in.
        let mut mfa_verified = false;
        if user.mfa_enabled {
            let secret = user.mfa_secret.clone().ok_or(ProxyError::MfaRequired)?;
            match &login_body.mfa_token {
                Some(token) => {
                    let totp = TotpManager::new(MfaConfig::default());
                    mfa_verified = totp.verify_token(&secret, token).unwrap_or(false);
                    if !mfa_verified {
                        return Err(ProxyError::InvalidMfaToken);
                    }
                }
                None => return Err(ProxyError::MfaRequired),
            }
        }

        // A device seen before on this account nudges trust up further;
        // a brand-new fingerprint keeps the neutral default from ::new().
        if existing_device.is_some() {
            device.increase_trust(10);
        }
        device.update_last_seen();
        db::upsert_device(
            &self.db_pool,
            user.id,
            &device.fingerprint_hash,
            &device.user_agent,
            &device.platform,
            &device.browser,
            &remote_addr.ip().to_string(),
            device.trust_score as i32,
            device.is_trusted,
        )
        .await?;

        let login_risk_ctx = RiskContext {
            user_id: user.id.to_string(),
            device: device.clone(),
            ip_address: remote_addr.ip(),
            timestamp: chrono::Utc::now(),
            geolocation: None,
            previous_ip: None,
            session_age_minutes: 0,
            failed_attempts: 0,
            time_since_last_success_hours: None,
        };
        let login_risk = self
            .risk_engine
            .calculate_risk(&login_risk_ctx)
            .unwrap_or(RiskScore {
                total_score: 0,
                factors: vec![],
                level: RiskLevel::Low,
                recommendation: RiskRecommendation::Allow,
            });

        if matches!(login_risk.recommendation, RiskRecommendation::Block) {
            self.audit_logger
                .log_authentication(
                    &user.id.to_string(),
                    &device.id,
                    &remote_addr.ip().to_string(),
                    false,
                )
                .await
                .ok();
            return Err(ProxyError::RiskThresholdExceeded {
                score: login_risk.total_score,
                threshold: self.config.risk.block_threshold,
            });
        }

        let device_id = login_body
            .device_id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let mut session_manager = SessionManager::new(
            self.redis_conn.clone(),
            self.config.auth.session_duration_minutes,
        );
        let mut session = session_manager
            .create_session(
                user.id.to_string(),
                device_id.clone(),
                remote_addr.ip().to_string(),
                user_agent,
            )
            .await?;
        session.mfa_verified = mfa_verified;
        session.risk_score = login_risk.total_score;
        session_manager.update_session(&session).await?;

        self.audit_logger
            .log_authentication(
                &user.id.to_string(),
                &device_id,
                &remote_addr.ip().to_string(),
                true,
            )
            .await
            .ok();

        let token = self.jwt_manager.generate_token(
            &user.id.to_string(),
            &device_id,
            session.risk_score,
            mfa_verified,
            &session.id,
        )?;

        let resp = LoginResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.auth.jwt_expiration_hours * 3600,
            mfa_required: user.mfa_enabled && !mfa_verified,
        };

        json_response(StatusCode::OK, &resp)
    }

    async fn handle_register(
        &self,
        req: Request<Incoming>,
        remote_addr: SocketAddr,
    ) -> Result<Response<Full<Bytes>>, ProxyError> {
        self.check_rate_limit(remote_addr, "register", 10, 300)
            .await?;

        let body_bytes = req
            .into_body()
            .collect()
            .await
            .map_err(|_| ProxyError::InternalError)?
            .to_bytes();
        let body: RegisterBody = serde_json::from_slice(&body_bytes)
            .map_err(|_| ProxyError::AuthenticationFailed("invalid request body".to_string()))?;

        if body.password.len() < 12 {
            return Err(ProxyError::AuthenticationFailed(
                "password must be at least 12 characters".to_string(),
            ));
        }

        if db::find_user_by_username(&self.db_pool, &body.username)
            .await?
            .is_some()
        {
            return Err(ProxyError::AuthenticationFailed(
                "username already exists".to_string(),
            ));
        }

        let password_hash = hash_password(&body.password)?;
        let user =
            db::create_user(&self.db_pool, &body.username, &body.email, &password_hash).await?;

        json_response(
            StatusCode::CREATED,
            &serde_json::json!({ "id": user.id, "username": user.username, "email": user.email }),
        )
    }

    /// Authenticated (bearer token required) but deliberately NOT routed
    /// through authorize()'s require_mfa gate -- enrolling is how a user
    /// gets a TOTP secret in the first place, so it can't itself require MFA.
    async fn handle_mfa_enroll(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, ProxyError> {
        let auth_header = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let token = self.jwt_manager.extract_token_from_header(auth_header)?;
        let claims = self.jwt_manager.validate_token(&token)?;

        let user_id: Uuid = claims
            .sub
            .parse()
            .map_err(|_| ProxyError::AuthenticationFailed("invalid subject".to_string()))?;
        let user = db::find_user_by_id(&self.db_pool, user_id)
            .await?
            .ok_or_else(|| ProxyError::AuthenticationFailed("user not found".to_string()))?;

        let totp = TotpManager::new(MfaConfig::default());
        let secret = totp.generate_secret()?;
        let qr_url = totp.generate_qr_url(&secret, &user.email, "zero-trust-proxy")?;

        db::set_user_mfa_secret(&self.db_pool, user_id, &secret).await?;

        json_response(
            StatusCode::OK,
            &crate::auth::mfa::MfaEnrollmentResponse {
                secret: secret.clone(),
                qr_code_url: qr_url,
                manual_entry_key: secret,
            },
        )
    }

    /// Lets a caller with a valid (but not-yet-MFA'd) session step up by
    /// submitting a TOTP code, upgrading the live session in place.
    async fn handle_mfa_verify(
        &self,
        req: Request<Incoming>,
        remote_addr: SocketAddr,
    ) -> Result<Response<Full<Bytes>>, ProxyError> {
        // 6-digit TOTP codes are low-entropy (~1M combos); throttle guesses
        // tighter than login even though a valid bearer token is required.
        self.check_rate_limit(remote_addr, "mfa_verify", 10, 300)
            .await?;

        let (parts, body) = req.into_parts();
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let token = self.jwt_manager.extract_token_from_header(auth_header)?;
        let claims = self.jwt_manager.validate_token(&token)?;

        let body_bytes = body
            .collect()
            .await
            .map_err(|_| ProxyError::InternalError)?
            .to_bytes();
        let mfa_body: MfaVerifyBody = serde_json::from_slice(&body_bytes)
            .map_err(|_| ProxyError::AuthenticationFailed("invalid request body".to_string()))?;

        let user_id: Uuid = claims
            .sub
            .parse()
            .map_err(|_| ProxyError::AuthenticationFailed("invalid subject".to_string()))?;
        let user = db::find_user_by_id(&self.db_pool, user_id)
            .await?
            .ok_or_else(|| ProxyError::AuthenticationFailed("user not found".to_string()))?;
        let secret = user.mfa_secret.ok_or(ProxyError::MfaRequired)?;

        let totp = TotpManager::new(MfaConfig::default());
        if !totp
            .verify_token(&secret, &mfa_body.mfa_token)
            .unwrap_or(false)
        {
            return Err(ProxyError::InvalidMfaToken);
        }

        let mut session_manager = SessionManager::new(
            self.redis_conn.clone(),
            self.config.auth.session_duration_minutes,
        );
        let mut session = session_manager.get_session(&claims.session_id).await?;
        session.mfa_verified = true;
        session_manager.update_session(&session).await?;

        json_response(StatusCode::OK, &serde_json::json!({ "mfa_verified": true }))
    }

    /// Revokes just the session tied to the presented token.
    async fn handle_logout(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, ProxyError> {
        let auth_header = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let token = self.jwt_manager.extract_token_from_header(auth_header)?;
        let claims = self.jwt_manager.validate_token(&token)?;

        let mut session_manager = SessionManager::new(
            self.redis_conn.clone(),
            self.config.auth.session_duration_minutes,
        );
        session_manager.delete_session(&claims.session_id).await?;

        json_response(StatusCode::OK, &serde_json::json!({ "ok": true }))
    }

    /// Revokes every live session for this user -- e.g. "log out everywhere"
    /// after a suspected compromise, not just the caller's own session.
    async fn handle_logout_all(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, ProxyError> {
        let auth_header = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let token = self.jwt_manager.extract_token_from_header(auth_header)?;
        let claims = self.jwt_manager.validate_token(&token)?;

        let mut session_manager = SessionManager::new(
            self.redis_conn.clone(),
            self.config.auth.session_duration_minutes,
        );
        let revoked = session_manager.revoke_user_sessions(&claims.sub).await?;

        json_response(
            StatusCode::OK,
            &serde_json::json!({ "ok": true, "revoked": revoked }),
        )
    }
}

/// MVP default: any request that clears JWT + session + policy + risk is
/// allowed. This is intentionally permissive so the proxy is usable out of
/// the box -- operators should add explicit Deny rules (or a real OPA/rego
/// integration, which isn't wired in yet) for finer-grained access control.
fn build_default_policy_engine(default_deny: bool) -> PolicyEngine {
    let mut engine = PolicyEngine::new(default_deny);
    engine.add_policy(Policy {
        id: "default-allow-authenticated".to_string(),
        name: "Allow all authenticated requests (MVP default)".to_string(),
        description: "Passes through anything that already cleared JWT/session/risk checks."
            .to_string(),
        rules: vec![PolicyRule {
            resource_pattern: "*".to_string(),
            actions: ["get", "post", "put", "patch", "delete", "head", "options"]
                .into_iter()
                .map(String::from)
                .collect(),
            conditions: vec![],
            effect: Effect::Allow,
        }],
    });
    engine
}

async fn serve_connection<I>(io: TokioIo<I>, server: Arc<ProxyServer>, remote_addr: SocketAddr)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req| {
        let server = Arc::clone(&server);
        async move { Ok::<_, std::convert::Infallible>(server.handle_request(req, remote_addr).await) }
    });

    if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
        error!("Error serving connection from {}: {:?}", remote_addr, err);
    }
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("failed to open TLS cert {}: {}", path, e))?;
    let mut reader = std::io::BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        warn!("no certificates found in {}", path);
    }
    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("failed to open TLS key {}: {}", path, e))?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", path))
}

fn text_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("error"))))
}

fn json_response<T: serde::Serialize>(
    status: StatusCode,
    body: &T,
) -> Result<Response<Full<Bytes>>, ProxyError> {
    let bytes = serde_json::to_vec(body)?;
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .map_err(|_| ProxyError::InternalError)
}

fn error_response(err: ProxyError) -> Response<Full<Bytes>> {
    let status =
        StatusCode::from_u16(err.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = serde_json::json!({ "error": err.to_string() });
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(
            serde_json::to_vec(&body).unwrap_or_default(),
        )))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("error"))))
}

#[derive(Debug, Deserialize)]
struct LoginBody {
    username: String,
    password: String,
    device_id: Option<String>,
    mfa_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RegisterBody {
    username: String,
    email: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct MfaVerifyBody {
    mfa_token: String,
}
