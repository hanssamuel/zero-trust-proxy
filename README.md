# Zero-Trust Authentication Proxy

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A high-performance, production-ready Zero-Trust Authentication Proxy built in Rust. This proxy enforces "never trust, always verify" principles by continuously authenticating and authorizing every request based on context, device posture, user behavior, and real-time risk assessment.

## 🎯 Project Overview

Traditional perimeter-based security assumes that users and devices inside the network can be trusted. Zero-Trust Architecture (ZTA) eliminates this assumption by treating every access request as potentially hostile, regardless of origin.

This proxy acts as a security gateway that:
- **Authenticates** every request with multi-factor verification
- **Authorizes** based on fine-grained policies and real-time context
- **Monitors** continuously for anomalies and suspicious behavior
- **Adapts** security posture based on calculated risk scores
- **Enforces** least-privilege access dynamically

## ✨ Key Features

### 🔐 Authentication & Identity
- Multi-factor authentication (TOTP, WebAuthn/passkeys, hardware keys planned)
- Session management with short-lived tokens
- Device fingerprinting and trust scoring
- Certificate-based authentication (mTLS)
- Integration ready for identity providers (OAuth2, SAML)

### 📋 Policy Engine
- Attribute-based access control (ABAC)
- Context-aware authorization
- Dynamic policy evaluation per request
- Least-privilege enforcement

### 🎯 Risk Scoring
- Real-time risk calculation engine
- Behavioral anomaly detection
- Geolocation and time-based analysis
- Device posture assessment
- Threat intelligence integration ready

### ��️ Security Controls
- Adaptive authentication (step-up when risk increases)
- Rate limiting and DDoS protection
- IP reputation checking ready
- Request sanitization and validation
- Encrypted connections (TLS 1.3)

### 📊 Observability
- Comprehensive audit logging
- Prometheus metrics export
- Real-time security dashboards
- Alerting on suspicious activity
- Request tracing and correlation

## 🏗️ Architecture
```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────────┐
│    Zero-Trust Proxy (Rust)          │
│  ┌─────────────────────────────┐   │
│  │   Authentication Layer      │   │
│  │   - MFA Verification        │   │
│  │   - Session Management      │   │
│  │   - Device Fingerprinting   │   │
│  └─────────────────────────────┘   │
│               │                      │
│  ┌─────────────────────────────┐   │
│  │   Policy Engine             │   │
│  │   - ABAC Evaluation         │   │
│  │   - Context Analysis        │   │
│  │   - Permission Scoping      │   │
│  └─────────────────────────────┘   │
│               │                      │
│  ┌─────────────────────────────┐   │
│  │   Risk Scoring Engine       │   │
│  │   - Behavioral Analysis     │   │
│  │   - Threat Intel Lookup     │   │
│  │   - Anomaly Detection       │   │
│  └─────────────────────────────┘   │
│               │                      │
│  ┌─────────────────────────────┐   │
│  │   Audit & Monitoring        │   │
│  │   - Event Logging           │   │
│  │   - Metrics Collection      │   │
│  │   - Alert Generation        │   │
│  └─────────────────────────────┘   │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│      Protected Backend Services     │
└─────────────────────────────────────┘
```

## 🚀 Getting Started

### Prerequisites

- Rust 1.70 or higher
- PostgreSQL 14+ (for user/session data)
- Redis 7+ (for caching and session storage)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/hanssamuel/zero-trust-proxy.git
cd zero-trust-proxy
```

2. Copy the example configuration:
```bash
cp config/config.example.toml config/config.toml
```

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your database credentials and secrets
```

4. Build the project:
```bash
cargo build --release
```

5. Run database migrations:
```bash
cargo run --bin migrate
```

6. Start the proxy:
```bash
cargo run --release
```

## 📖 Configuration

The proxy is configured via `config/config.toml`:
```toml
[server]
host = "0.0.0.0"
port = 8443
tls_cert = "certs/server.crt"
tls_key = "certs/server.key"

[database]
url = "postgresql://user:pass@localhost/ztp"
max_connections = 20

[redis]
url = "redis://localhost:6379"

[auth]
session_duration_minutes = 15
require_mfa = true
allowed_mfa_methods = ["totp", "webauthn"]

[risk]
max_risk_score = 100
step_up_threshold = 60
block_threshold = 85
```

## 🔑 WebAuthn / Passkeys

Passkey registration and authentication are implemented in `src/auth/webauthn.rs`
on top of `webauthn-rs`. Configure the relying party in `[webauthn]`
(`config/config.toml`) or via `WEBAUTHN_RP_ID` / `WEBAUTHN_RP_ORIGIN` /
`WEBAUTHN_RP_NAME` / `WEBAUTHN_ENABLED`; dev defaults target `localhost`.

> **Storage:** credentials are persisted in Postgres by default via
> `PostgresPasskeyStore` (`src/auth/passkey_store_pg.rs`), using the `passkeys`
> table from `migrations/001_passkeys.sql`. Migrations run automatically at
> startup. Set `WEBAUTHN_PASSKEY_STORE=memory` to use `InMemoryPasskeyStore`
> instead; it loses every passkey on restart, so keep it to local dev and tests.
> The store layer is complete; the passkey HTTP routes are not wired into the
> proxy yet.

Usage sketch (see the module docs for the full ceremony walkthrough):

```rust
let manager = WebauthnManager::new(config.webauthn.clone())?;
let store = connect_passkey_store(
    config.webauthn.passkey_store,
    &config.database.url,
    config.database.max_connections,
)
.await?;
// `WEBAUTHN_PASSKEY_STORE=memory` selects the in-memory store for local dev;
// the default is the Postgres-backed `PostgresPasskeyStore`.

// Registration
let (challenge, state) =
    manager.start_passkey_registration(user_id, username, display_name, &[])?;
// -> POST `challenge` as JSON to the browser; stash `state` server-side
let passkey = manager.finish_passkey_registration(&browser_response, &state)?;
store.save_passkey(PasskeyRecord::new(user_id.to_string(), passkey)).await?;

// Authentication
let passkeys: Vec<Passkey> = store.get_passkeys(&user_id.to_string()).await?
    .into_iter().map(|r| r.passkey).collect();
let (challenge, state) = manager.start_passkey_authentication(&passkeys)?;
// -> POST `challenge` as JSON; stash `state`; browser posts back an assertion
let result = manager.finish_passkey_authentication(&browser_assertion, &state)?;
refresh_passkey(&store, &mut record, &result).await?;

// Passkey ceremonies require user verification, so the session JWT is
// minted with mfa_verified = true.
let token = mint_passkey_jwt(&jwt_manager, &user_id.to_string(), device_id, session_id, risk_score)?;
```

Credential storage is decoupled through the `PasskeyStore` trait:
`PostgresPasskeyStore` persists credentials in the `passkeys` table
(`migrations/001_passkeys.sql`) so they survive restarts, and an in-memory
implementation is included for dev/tests (select it with
`WEBAUTHN_PASSKEY_STORE=memory`).

## 🧪 Testing

Run the test suite:
```bash
cargo test
```

Run integration tests:
```bash
cargo test --test integration_tests
```

Run benchmarks:
```bash
cargo bench
```

## 📊 Monitoring

The proxy exposes Prometheus metrics at `/metrics`:
```bash
curl http://localhost:9090/metrics
```

Key metrics:
- `ztp_requests_total` - Total requests processed
- `ztp_auth_failures_total` - Authentication failures
- `ztp_risk_score_histogram` - Distribution of risk scores
- `ztp_policy_evaluations_duration` - Policy evaluation latency

## 🔒 Security Considerations

- All credentials should be stored in environment variables, never committed to git
- TLS certificates must be properly configured and rotated
- Database connections use encrypted channels
- Secrets are encrypted at rest using strong encryption
- Regular security audits and dependency updates are recommended

## 🗺️ Roadmap

- [x] Basic reverse proxy functionality
- [x] Authentication layer with JWT
- [x] Multi-factor authentication (TOTP)
- [x] Risk scoring engine
- [x] Policy engine with ABAC
- [x] Device fingerprinting
- [x] WebAuthn/passkey support (registration + authentication ceremonies, credential storage trait)
- [ ] Behavioral anomaly detection with ML
- [ ] Threat intelligence integration
- [ ] Admin dashboard and UI

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Osayemwenre Sam Jegbefumwen**
- Security Engineer specializing in zero-trust architectures
- GitHub: [@hanssamuel](https://github.com/hanssamuel)

## 🙏 Acknowledgments

- NIST Zero Trust Architecture (SP 800-207)
- Google BeyondCorp whitepaper
- Open Policy Agent (OPA) community
- Rust security community

## 📚 References

- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [Google BeyondCorp](https://cloud.google.com/beyondcorp)
- [Zero Trust Extended (ZTX) Ecosystem](https://www.nist.gov/programs-projects/ztx)

---

**⚠️ Security Notice**: This is a security-critical application. Always conduct thorough security reviews before deploying to production.

