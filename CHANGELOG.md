# Changelog

All notable changes to komainu are documented in this file. All crates in the workspace share
one version number.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the version is `0.x`,
a breaking change bumps the minor version.

## [Unreleased]

## [0.1.0-alpha.3] - 2026-11-24

### Added

- New crate `komainu-jose`: JWS Compact Serialization, JWK / JWK Set and JWT with RS256 and
  ES256, built on RustCrypto. Nothing else in the workspace depends on it yet.
- `cargo deny check advisories` in CI (`deny.toml`).

## [0.1.0-alpha.2] - 2026-11-24

### Added

- Token revocation endpoint (`POST /revoke`, [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009)).
  Revoking either an access token or a refresh token revokes the whole grant.
- `TokenService::revoke` and the public types `RevocationRequest`, `RevocationError` and
  `TokenTypeHint`.
- Audit event `token_revocation.client_mismatch`.
- Metric `komainu_revocation_requests_total`.
- Migration `0002` (applied automatically by `migrate`) allows the revocation reason
  `client_request`.
- Store conformance case `grant_revoked_by_client_request_roundtrip` in
  `komainu_testkit::conformance`. A store must persist the new revocation reason
  `client_request` to pass the suite.

### Changed

- `AuditKind::TokenRevocationClientMismatch` and `RevocationReason::ClientRequest` were added.
  Both enums are exhaustive, so a `match` over them without a wildcard arm no longer compiles.

## [0.1.0-alpha.1] - 2026-11-23

First pre-release. komainu is an OAuth 2.0 authorization server
([RFC 6749](https://www.rfc-editor.org/rfc/rfc6749)) that runs as a standalone binary or embeds
in an axum application.

### Added

#### Authorization server

- Authorization endpoint (`GET`/`POST /authorize`, `response_type=code` only) with login,
  consent and logout screens.
- Token endpoint (`POST /token`) with the `authorization_code`, `client_credentials` and
  `refresh_token` grants.
- Client authentication with `client_secret_basic` and, per client, `client_secret_post`.
  Public clients are disabled by default (`clients.allow_public`).
- Refresh token rotation. Reusing a rotated refresh token revokes the whole token series, and
  reusing an authorization code revokes the tokens issued from it.
- Remembered consent and a per-client `skip_consent` option.
- Access token verification for resource servers (`TokenService::verify_access_token`).
- Tokens, codes, client secrets and session IDs are stored only as SHA-256 hashes, passwords
  with Argon2id, and none of them is written to the logs.

#### Standalone server (`komainu-server`)

- The `komainu` binary with `serve`, `migrate`, and `client` and `user` admin commands.
- TOML configuration (`--config` or `./komainu.toml`) with `KOMAINU_<SECTION>__<KEY>`
  environment variable overrides. See `config/komainu.example.toml`.
- `server.content_security_policy` to set the `Content-Security-Policy` of the HTML screens.
- Structured logs, audit events stored in the database, Prometheus metrics, `/healthz` and
  `/readyz` on a separate ops listener, periodic deletion of expired data, and graceful
  shutdown.
- PostgreSQL 16 or later as the database, with embedded migrations.

#### Library

- `komainu` facade crate: `Komainu::builder()` assembles a store, an optional
  `ResourceOwnerAuthenticator` and optional `ScreenRenderer` into the use case services and an
  axum `Router`. The `http`, `postgres` and `std` features (all on by default) select the
  re-exported crates.
- Replaceable login, consent, error and logged-out screens (`ScreenRenderer`, `DefaultScreens`).
  komainu keeps the status codes, headers, cookies and CSRF checks.
- `komainu-domain`, `komainu-application`, `komainu-adapter-postgres`, `komainu-adapter-std` and
  `komainu-http` as separate crates for the domain model, use cases and ports, and adapters.
- `komainu-testkit` with in-memory adapters, fixed clocks and a store conformance suite
  (`komainu_testkit::conformance`).
- `minimal` and `custom_screens` examples in the `komainu` crate.

[Unreleased]: https://github.com/ryoshrimp/komainu/compare/v0.1.0-alpha.3...HEAD
[0.1.0-alpha.3]: https://github.com/ryoshrimp/komainu/compare/v0.1.0-alpha.2...v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/ryoshrimp/komainu/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/ryoshrimp/komainu/releases/tag/v0.1.0-alpha.1
