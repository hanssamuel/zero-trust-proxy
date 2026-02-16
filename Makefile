.PHONY: help build run test clean fmt lint docker-up docker-down db-setup

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the project
	cargo build

build-release: ## Build the project in release mode
	cargo build --release

run: ## Run the project
	cargo run

test: ## Run tests
	cargo test

test-verbose: ## Run tests with verbose output
	cargo test -- --nocapture

bench: ## Run benchmarks
	cargo bench

fmt: ## Format code
	cargo fmt

fmt-check: ## Check code formatting
	cargo fmt -- --check

lint: ## Run clippy linter
	cargo clippy -- -D warnings

clean: ## Clean build artifacts
	cargo clean

docker-up: ## Start development services (PostgreSQL, Redis, Prometheus, Grafana)
	docker-compose up -d

docker-down: ## Stop development services
	docker-compose down

docker-logs: ## View logs from development services
	docker-compose logs -f

db-setup: ## Set up the database schema
	psql $${DATABASE_URL} -f docs/schema.sql

db-reset: ## Reset the database
	psql $${DATABASE_URL} -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
	$(MAKE) db-setup

dev: docker-up ## Start development environment
	@echo "Waiting for services to be ready..."
	@sleep 5
	cargo run

check-all: fmt-check lint test ## Run all checks (format, lint, test)

security-audit: ## Run security audit
	cargo audit

outdated: ## Check for outdated dependencies
	cargo outdated

update: ## Update dependencies
	cargo update

doc: ## Generate documentation
	cargo doc --no-deps --open

install: ## Install the binary
	cargo install --path .

coverage: ## Generate code coverage report
	cargo tarpaulin --out Html --output-dir coverage

.DEFAULT_GOAL := help
