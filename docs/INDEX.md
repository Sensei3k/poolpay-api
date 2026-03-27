# Documentation Index

Last Updated: 2026-03-27

Quick reference to all documentation for the Rust Receipt Engine project.

## For Developers

Start here if you're setting up the development environment or contributing code.

- **[CONTRIBUTING.md](./CONTRIBUTING.md)** — Development setup and contribution guidelines
  - Prerequisites (Rust, Tesseract, system deps)
  - Building and running locally
  - Testing procedures (unit tests, integration tests)
  - Code standards and best practices
  - Git workflow and commit conventions
  - Troubleshooting common build issues

## For Operations

Start here if you're deploying, running, or troubleshooting the service in production.

- **[RUNBOOK.md](./RUNBOOK.md)** — Operational procedures and troubleshooting
  - Quick start (development and production)
  - Environment configuration
  - Service architecture overview
  - API routes and health checks
  - Database management
  - Common issues and fixes
  - Production monitoring and deployment

## For Understanding the Project

- **[README.md](../README.md)** (in root) — Project overview
  - What the service does
  - Architecture and structure
  - Google Sheets integration details
  - Testing overview
  - Known limitations

## Key Topics at a Glance

### Setup & Installation
- System dependencies: [CONTRIBUTING.md - Prerequisites](./CONTRIBUTING.md#prerequisites)
- Environment configuration: [RUNBOOK.md - Environment Configuration](./RUNBOOK.md#environment-configuration)
- Development setup: [CONTRIBUTING.md - Development Workflow](./CONTRIBUTING.md#development-workflow)

### Running the Service
- Development mode: [RUNBOOK.md - Quick Start](./RUNBOOK.md#quick-start)
- Production deployment: [RUNBOOK.md - Production](./RUNBOOK.md#production)
- Service architecture: [RUNBOOK.md - Service Architecture](./RUNBOOK.md#service-architecture)

### Testing
- Running tests: [CONTRIBUTING.md - Testing](./CONTRIBUTING.md#testing)
- Test organization: [CONTRIBUTING.md - Project Structure](./CONTRIBUTING.md#project-structure)
- Test counts and coverage: [README.md - Testing](../README.md#testing)

### API Reference
- All endpoints: [RUNBOOK.md - API Routes](./RUNBOOK.md#api-routes)
- Error responses: [CONTRIBUTING.md - API Endpoints](./CONTRIBUTING.md#adding-an-api-endpoint)

### Environment Variables
- Development setup: [CONTRIBUTING.md - Environment Variables](./CONTRIBUTING.md#environment-variables)
- Production configuration: [RUNBOOK.md - Environment Configuration](./RUNBOOK.md#environment-configuration)

### Troubleshooting
- Build issues: [CONTRIBUTING.md - Troubleshooting](./CONTRIBUTING.md#troubleshooting)
- Runtime issues: [RUNBOOK.md - Common Issues & Fixes](./RUNBOOK.md#common-issues--fixes)
- Database issues: [RUNBOOK.md - Database Corruption](./RUNBOOK.md#database-corruption)

### Code Standards
- Best practices: [CONTRIBUTING.md - Code Standards](./CONTRIBUTING.md#code-standards)
- Commit conventions: [CONTRIBUTING.md - Git Workflow](./CONTRIBUTING.md#git-workflow)
- Linting and formatting: [CONTRIBUTING.md - Linting & Formatting](./CONTRIBUTING.md#linting--formatting)

## Quick Commands

### Development
```bash
# Setup
cp .env.example .env
# (edit .env with your credentials)

# Run
cargo run

# Test
cargo test

# Format & lint
cargo fmt
cargo clippy -- -D warnings
```

### Production
```bash
# Build
cargo build --release

# Run
APP_ENV=production DASHBOARD_ORIGIN=https://dashboard.example.com \
  ./target/release/receipt-engine
```

## Architecture Overview

Three concurrent tasks:

1. **Receipt Loop** (5-second polling)
   - Monitors Green API for incoming messages
   - Extracts text via Tesseract OCR
   - Parses receipt details
   - Replies and writes to Google Sheet

2. **Confirmation Loop** (30-second polling)
   - Checks Google Sheet for confirmed entries
   - Sends "Acknowledged" replies
   - Updates sheet with timestamp

3. **API Server** (port 8080)
   - Serves REST endpoints
   - Manages members, cycles, and payments
   - Development-only database reset endpoint

See [RUNBOOK.md - Service Architecture](./RUNBOOK.md#service-architecture) for details.

## Tech Stack

- **Language:** Rust 2021 edition
- **Web Framework:** Axum
- **Database:** SurrealDB (RocksDB storage)
- **OCR:** Tesseract
- **Integrations:** Green API (WhatsApp), Google Sheets API
- **Testing:** Rust built-in test framework with in-memory SurrealDB

## Support

For issues or questions:

1. Check [RUNBOOK.md - Common Issues & Fixes](./RUNBOOK.md#common-issues--fixes)
2. Enable debug logging: `RUST_LOG=debug cargo run`
3. Review code comments in source files
4. Check recent commits for recent changes: `git log --oneline -10`
