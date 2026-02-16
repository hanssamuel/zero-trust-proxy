# Contributing to Zero-Trust Proxy

Thank you for your interest in contributing to Zero-Trust Proxy! This document provides guidelines and information for contributors.

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- A clear and descriptive title
- Detailed steps to reproduce the problem
- Expected behavior vs actual behavior
- Version information (Rust version, OS, etc.)
- Relevant logs or error messages

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- A clear and descriptive title
- Detailed description of the proposed functionality
- Explanation of why this enhancement would be useful
- Examples of how it would be used

### Pull Requests

1. Fork the repository and create your branch from `main`
2. If you've added code, add tests
3. Ensure the test suite passes: `cargo test`
4. Ensure your code follows Rust best practices: `cargo clippy`
5. Format your code: `cargo fmt`
6. Update documentation as needed
7. Write a clear commit message

## Development Setup

### Prerequisites

- Rust 1.70 or higher
- PostgreSQL 14+
- Redis 7+
- Docker (optional, for local development)

### Local Development

1. Clone the repository:
```bash
git clone https://github.com/yourusername/zero-trust-proxy.git
cd zero-trust-proxy
```

2. Install dependencies:
```bash
cargo build
```

3. Set up the database:
```bash
psql -U postgres -f docs/schema.sql
```

4. Copy environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Run the project:
```bash
cargo run
```

### Running Tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_name

# Run benchmarks
cargo bench
```

### Code Style

We follow standard Rust conventions:

- Use `cargo fmt` to format code
- Use `cargo clippy` to catch common mistakes
- Write meaningful comments for complex logic
- Keep functions focused and small
- Use descriptive variable names

### Documentation

- Document all public APIs with doc comments (`///`)
- Include examples in documentation where helpful
- Update README.md for user-facing changes
- Keep inline comments minimal but meaningful

## Security

### Reporting Security Vulnerabilities

**DO NOT** create public issues for security vulnerabilities. Instead, email security details to [your-security-email].

### Security Guidelines

When contributing security-related code:

- Follow OWASP guidelines
- Never commit secrets or credentials
- Use secure coding practices
- Add security tests for new features
- Document security implications

## Architecture Guidelines

### Project Structure

```
src/
├── auth/        # Authentication and session management
├── policy/      # Policy engine and ABAC
├── proxy/       # Core proxy functionality
├── risk/        # Risk scoring engine
├── audit/       # Audit logging
└── config/      # Configuration management
```

### Design Principles

1. **Zero Trust**: Every request is authenticated and authorized
2. **Defense in Depth**: Multiple layers of security
3. **Least Privilege**: Grant minimum necessary permissions
4. **Fail Secure**: Default to deny on errors
5. **Auditability**: Log all security-relevant events

## Testing Strategy

### Unit Tests

- Test individual functions and modules
- Use mocks for external dependencies
- Aim for >80% code coverage

### Integration Tests

- Test component interactions
- Use test databases/Redis instances
- Test realistic scenarios

### Security Tests

- Test authentication flows
- Test authorization edge cases
- Test injection vulnerabilities
- Test rate limiting

## Commit Message Guidelines

Format:
```
type(scope): subject

body

footer
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test additions or changes
- `chore`: Build process or auxiliary tool changes

Example:
```
feat(auth): add WebAuthn support

Implement WebAuthn authentication method for hardware
security keys. Includes enrollment and verification flows.

Closes #123
```

## Release Process

1. Update version in `Cargo.toml`
2. Update CHANGELOG.md
3. Create git tag: `git tag -a v0.1.0 -m "Release v0.1.0"`
4. Push tag: `git push origin v0.1.0`

## Questions?

Feel free to open an issue for questions about contributing!

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
