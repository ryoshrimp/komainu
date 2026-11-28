# Changelog

All notable changes to komainu are documented in this file. All crates in the workspace share
one version number.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the version is `0.x`,
a breaking change bumps the minor version.

## [Unreleased]

### Added

- Authorization server metadata ([RFC 8414](https://www.rfc-editor.org/rfc/rfc8414)) at
  `GET /.well-known/oauth-authorization-server`, built from `server.public_base_url` and the
  configuration.
- `ServerCapabilities` (with `ResponseType` and `ResponseMode`) in `komainu-application`, which
  lists what the server supports, and `TokenService::server_capabilities`.
- `AuthorizationServerMetadata` in `komainu-http`, the document served by the endpoint, and
  `AppState::metadata`.
- `Komainu::metadata`, which returns the same document for library users.
- PKCE ([RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)) with the `S256` method. The
  authorization endpoint takes `code_challenge` and `code_challenge_method`, and the token
  endpoint takes `code_verifier` for the `authorization_code` grant.
- Migration `0003` (applied automatically by `migrate`) adds the `code_challenge` and
  `code_challenge_method` columns to `authorization_requests` and `authorization_codes`.
- `private_key_jwt` client authentication
  ([RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) §2.2, [RFC 7521](https://www.rfc-editor.org/rfc/rfc7521)
  §4.2) at `/token` and `/revoke`. A client registers a JWK Set (`--jwks-file`) or a `jwks_uri`
  (`--jwks-uri`, `https` only) and signs the assertion with RS256 or ES256. `client_assertion`
  and `client_assertion_type` are new parameters of both endpoints.
- The JWT bearer authorization grant `urn:ietf:params:oauth:grant-type:jwt-bearer`
  ([RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) §2.1, [RFC 7521](https://www.rfc-editor.org/rfc/rfc7521)
  §4.1) at `/token`. A confidential client exchanges an assertion signed by a trusted issuer for
  an access token. No refresh token is issued. The `sub` of the assertion is mapped to a user
  through a table managed with `komainu issuer map-subject`, and can be mapped differently by
  replacing `AssertionSubjectResolver`.
- A request that sends `client_assertion` together with a Basic header or `client_secret`, or
  only one of `client_assertion` and `client_assertion_type`, is answered with `invalid_request`.
  In the jwt-bearer grant, an omitted `scope` becomes the default scopes of the client; a client
  without default scopes must send `scope`.
- An assertion may be valid for at most 300 seconds, is accepted once (its `jti` is remembered
  until it expires, plus the clock skew, even when the request then fails), and must have the issuer URL or the token endpoint URL as `aud`; 60 seconds
  of clock skew are tolerated. The limit applies to the assertion only, not to the access token.
- `komainu issuer` commands to manage trusted external issuers: `create`, `list`, `show`,
  `update`, `disable`, `enable`, `map-subject`, `unmap-subject` and `list-subjects`.
  `komainu client create` and `update` take `--jwks-file` and `--jwks-uri`, and `--auth-method`
  and `--grant-type` accept `private_key_jwt` and the jwt-bearer URN.
- Audit events `issuer.registered`, `issuer.updated`, `issuer.disabled`, `issuer.enabled`,
  `issuer.subject_mapped`, `issuer.subject_unmapped` and `assertion.rejected`. A failed
  `private_key_jwt` authentication is recorded as `client_authentication.failed` with a
  `reason`. The cleanup job deletes expired assertion records
  (`komainu_cleanup_deleted_total{kind="used_assertions"}`).
- The new crate `komainu-adapter-http` with `ReqwestJwksFetcher`, which fetches `jwks_uri`
  documents (public addresses only, no redirects, 5 seconds, 64 KiB). The `komainu` facade enables
  it with the new `jwks-uri` feature (on by default), and `KomainuBuilder::jwks_fetcher` and
  `KomainuBuilder::subject_resolver` replace the fetcher and the subject resolver.
- Migration `0004` (applied automatically by `migrate`) allows the `private_key_jwt` auth method
  and the `jwt_bearer` grant origin, adds the `jwks` and `jwks_uri` columns to `clients`, and
  creates the `trusted_issuers`, `trusted_issuer_clients`, `issuer_subjects` and `used_assertions`
  tables. It does not delete rows.

### Changed

- PKCE is now required for every client, confidential or public. An authorization request without
  `code_challenge`, or with a `code_challenge_method` other than `S256`, is answered with
  `invalid_request`, and a code exchange without a matching `code_verifier` is refused. Clients
  must send the PKCE parameters; there is no setting to turn this off.
- Migration `0003` deletes all rows of `authorization_requests` and `authorization_codes`, because
  they carry no challenge. Users in the middle of a sign-in start again.
- `NewAuthorizationRequest`, `AuthorizationRequestRecord` and `AuthorizationCodeRecord` have a new
  `pkce: PkceChallenge` field, and `AuthorizeParams` and `TokenRequest` have new fields for the
  PKCE parameters. Code that builds them with a struct literal must set the new fields.
- `AuthorizationCode::redeem` takes a new `code_verifier: &CodeVerifier` argument, and
  `RedeemCodeError` has a new variant `PkceMismatch`. It is exhaustive, so a `match` without a
  wildcard arm no longer compiles.
- A store adapter outside this repository must save and read `pkce` for authorization requests and
  codes. The `authorization_flow_records_roundtrip` case of `komainu-testkit` checks this.
- The `komainu` facade with the `http` feature sets `ApplicationConfig::issuer` from
  `server.public_base_url` when it is unset. So the metadata now lists `private_key_jwt` in
  `token_endpoint_auth_methods_supported` and `revocation_endpoint_auth_methods_supported`, the
  jwt-bearer URN in `grant_types_supported`, and `RS256` and `ES256` in
  `token_endpoint_auth_signing_alg_values_supported` and
  `revocation_endpoint_auth_signing_alg_values_supported`. There is no setting to turn this off.
  Use `ApplicationConfig::with_issuer` when you build the use cases yourself.
- `ClientAuthentication` has a new variant `Assertion`, `TokenEndpointAuthMethod` has
  `PrivateKeyJwt`, `GrantType` has `JwtBearer` and `GrantOrigin` has `JwtBearer`. They are
  exhaustive, so a `match` without a wildcard arm no longer compiles.
- `PurgeCounts` has a new field `used_assertions`. Code that builds it with a struct literal must
  set the new field.
- `ServerCapabilities` has the new fields `token_endpoint_auth_signing_algs` and
  `revocation_endpoint_auth_signing_algs`, and its `grant_types` and auth method lists include
  `JwtBearer` and `PrivateKeyJwt` when `ApplicationConfig::issuer` is set. The struct is
  `#[non_exhaustive]`, so only code that compares the lists is affected.
- `AdminError` has new variants `InvalidJwks` and `UnknownClient`. The CLI exits with 2 for both.
  It is exhaustive, so a `match` without a wildcard arm no longer compiles.
- `TokenRequest` has a new field `assertion` for the jwt-bearer grant. Code that builds it with a
  struct literal must set the new field.
- `AuditKind` has new variants for the `issuer.*` events, `issuer.subject_mapped`,
  `issuer.subject_unmapped` and `assertion.rejected`. It is exhaustive, so a `match` without a
  wildcard arm no longer compiles.
- `UnitOfWork` has new methods `trusted_issuers`, `subject_mappings` and `used_assertions`, and
  `Dependencies` has new fields `jwks` and `subject_resolver`. The client registration and update
  types and the client records have a new `keys` field. A store adapter outside this repository
  must implement the new repositories and save the keys. The `komainu-testkit` conformance suite
  checks this.

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
