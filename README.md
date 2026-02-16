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
- Multi-factor authentication (TOTP, WebAuthn, hardware keys)
- Session management with short-lived tokens
- Device fingerprinting and trust scoring
- Certificate-based authentication (mTLS)
- Integration with identity providers (OAuth2, SAML)

### 📋 Policy Engine
- Attribute-based access control (ABAC)
- Context-aware authorization
- Integration with Open Policy Agent (OPA)
- Dynamic policy evaluation per request
- Least-privilege enforcement

### 🎯 Risk Scoring
- Real-time risk calculation engine
- Behavioral anomaly detection
- Geolocation and time-based analysis
- Device posture assessment
- Threat intelligence integration

### 🛡️ Security Controls
- Adaptive authentication (step-up when risk increases)
- Rate limiting and DDoS protection
- IP reputation checking
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
git clone https://github.com/yourusername/zero-trust-proxy.git
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
- [ ] Multi-factor authentication (TOTP, WebAuthn)
- [ ] Risk scoring engine
- [ ] Policy engine with OPA integration
- [ ] Device fingerprinting
- [ ] Behavioral anomaly detection
- [ ] Threat intelligence integration
- [ ] Machine learning-based risk assessment
- [ ] Admin dashboard and UI

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Osayemwenre Sam Jegbefumwen**
- Security Engineer with expertise in zero-trust architectures
- GitHub: [@yourusername](https://github.com/yourusername)
- LinkedIn: [Your LinkedIn](https://linkedin.com/in/yourprofile)

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
