# komainu

komainu is an OAuth 2.0 authorization server written in Rust. It implements the core of
[RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) and ships both as a standalone binary and as a
set of library crates you can embed in your own axum application.

Status: early development. The goal is to learn OAuth by building it, and to publish it as open source.

## What is supported

Grants and endpoints:

- Authorization endpoint (`GET`/`POST /authorize`, `response_type=code` only) with a login page,
  a consent page and logout
- Token endpoint (`POST /token`) with the `authorization_code`, `client_credentials`,
  `refresh_token` and `urn:ietf:params:oauth:grant-type:jwt-bearer` grants
- Token revocation endpoint (`POST /revoke`, RFC 7009). Revoking either token revokes the whole
  grant
- Authorization server metadata (`GET /.well-known/oauth-authorization-server`, RFC 8414), which
  also advertises `private_key_jwt`, the jwt-bearer grant and the signing algorithms
- Client authentication with `client_secret_basic` (always) and `client_secret_post`
  (per client); public clients are off by default (`clients.allow_public`)
- Client authentication with `private_key_jwt`
  ([RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) §2.2): the client signs a JWT assertion
  (RS256 or ES256) with its private key, and komainu verifies it with the public keys registered
  for the client, either as an inline JWK Set (`--jwks-file`) or as a `jwks_uri` that komainu
  fetches and caches (`--jwks-uri`). Used on `/token` and `/revoke`
- JWT bearer authorization grant ([RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) §2.1,
  [RFC 7521](https://www.rfc-editor.org/rfc/rfc7521)): a client exchanges an assertion signed by a
  trusted external issuer (`komainu issuer`) for an access token. The assertion's `sub` is mapped
  to a komainu user. No refresh token is issued, and only confidential clients can use it
- An assertion is accepted once (`jti` replay protection), may be valid for at most 300 seconds
  (60 seconds of clock skew is tolerated), and must name the issuer URL or the token endpoint
  as `aud`. This limit is about the assertion only; access token lifetimes follow `[oauth]`
- Refresh token rotation. Reusing a rotated refresh token revokes the whole token series
- PKCE ([RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)), required for every client; only the
  `S256` method is supported
- Reusing an authorization code revokes the tokens issued from it
- Remembered consent, and a per-client `skip_consent` option
- A library API to verify access tokens (`TokenService::verify_access_token`)

Operations:

- Admin CLI for clients and users, plus database migrations
- Structured logs (`tracing`), audit events stored in the database, Prometheus metrics,
  `/healthz` and `/readyz`, periodic deletion of expired data, graceful shutdown
- PostgreSQL 16 or later is the only supported database

Secrets (tokens, codes, client secrets, session IDs) are stored only as SHA-256 hashes, passwords
are stored with Argon2id, and none of these values is written to the logs.

Not supported (yet): OpenID Connect, JWT access tokens, the token introspection endpoint, dynamic
client registration, the `iss` parameter of authorization responses (RFC 9207), signed metadata,
the implicit and password grants, external identity providers, rate limiting of logins, TLS
termination (use a reverse proxy), translations of the built-in screens (they are English only;
see [Embedding](#embedding-as-a-library) to replace them), and a REST/UI for administration.

## Quick start

You need Rust 1.100 and a PostgreSQL 16+ database (for example
`docker run -d -e POSTGRES_USER=komainu -e POSTGRES_PASSWORD=komainu -e POSTGRES_DB=komainu -p 5432:5432 postgres:16-alpine`).

```sh
cargo build --release
export PATH="$PWD/target/release:$PATH"

cat > komainu.toml <<'TOML'
[server]
listen = "127.0.0.1:8080"
public_base_url = "http://localhost:8080"
allow_insecure_http = true   # local development only

[database]
url = "postgres://komainu:komainu@localhost:5432/komainu"

[session]
cookie_secure = false        # local development only

[[scopes]]
name = "read"
description = "Read your data"
TOML

komainu migrate
komainu client create --name demo --grant-type client_credentials --scope read
komainu serve
```

`client create` prints `client_id` and `client_secret`. The secret is shown only once. In another
terminal, put the two values in `CLIENT_ID` and `CLIENT_SECRET`:

```sh
curl -u "$CLIENT_ID:$CLIENT_SECRET" -d grant_type=client_credentials -d scope=read \
  http://localhost:8080/token
```

[docs/getting-started.md](docs/getting-started.md) walks through the whole flow, including the
authorization code grant and refresh tokens.

## Configuration

komainu reads a TOML file given by `--config <PATH>`, or `./komainu.toml` when it exists.
Environment variables override the file: `KOMAINU_<SECTION>__<KEY>`, for example
`KOMAINU_DATABASE__URL`. `[[scopes]]` can only be set in the file.
[config/komainu.example.toml](config/komainu.example.toml) lists every item with its default.

| Section | Items |
|---|---|
| `[server]` | `listen`, `public_base_url` (required), `allow_insecure_http`, `content_security_policy`, `shutdown_timeout_secs` |
| `[ops]` | `listen` for `/healthz`, `/readyz` and `/metrics` |
| `[database]` | `url` (required), `max_connections`, `acquire_timeout_secs` |
| `[session]` | `cookie_secure`, `ttl_secs` |
| `[oauth]` | lifetimes of codes, access tokens, refresh tokens and authorization requests, `require_state` |
| `[clients]` | `allow_public` |
| `[[scopes]]` | `name` and `description` of every scope clients may use |
| `[cleanup]` | `enabled`, `interval_secs`, `grace_secs`, `audit_retention_days` |
| `[log]` | `format` (`json` or `pretty`), `filter` (`RUST_LOG` takes precedence) |

`public_base_url` must be `https` unless `server.allow_insecure_http = true`. Run komainu behind a
reverse proxy that terminates TLS. The ops listener has no authentication; keep it on a private
address.

`server.content_security_policy` sets the `Content-Security-Policy` of the HTML screens (the
default allows only inline styles). `frame-ancestors 'none'` is always added, so a value that
contains `frame-ancestors` is rejected.

## Command line

```
komainu [--config PATH] <COMMAND>

komainu serve [--migrate]
komainu migrate
komainu client create --name NAME [--type confidential|public] [--auth-method M]
                      [--redirect-uri URI]... [--grant-type G]... [--scope "a b"]
                      [--default-scope "a"] [--skip-consent] [--output text|json]
komainu client create --name NAME --auth-method private_key_jwt --grant-type client_credentials
                      (--jwks-file PATH | --jwks-uri URL) [--scope "a b"]
komainu client list | show | update | rotate-secret | disable | enable
komainu issuer create --issuer ID --jwks-file PATH --client CLIENT_ID...
komainu issuer list | show | update | disable | enable
komainu issuer map-subject ID --subject SUB --username NAME
komainu issuer unmap-subject ID --subject SUB
komainu issuer list-subjects ID
komainu user create USERNAME     # the password is the first line of standard input
komainu user set-password | list | show | disable | enable
```

`private_key_jwt` clients have no secret, so `client create` prints none and `rotate-secret`
refuses them. A trusted issuer can be used only by the clients listed with `--client`, and such a client needs
`--grant-type urn:ietf:params:oauth:grant-type:jwt-bearer`.

Run `komainu --help` or `komainu client create --help` for all options. Exit codes: 0 success,
1 runtime error, 2 usage or configuration error, 3 not found, 4 already exists. Disabling a client
makes every access token it received invalid.

## Embedding as a library

The `komainu` crate re-exports the library crates behind features and assembles them with
`Komainu::builder()`: you give it a store, optionally your own authenticator
(`ResourceOwnerAuthenticator`) and your own screens (`ScreenRenderer`), and get the use case
services and an axum `Router` to merge into your app. A screen renderer only returns the HTML;
komainu keeps the status codes, headers, cookies and CSRF checks. Examples:

```sh
cargo run -p komainu --example minimal          # PostgreSQL (DATABASE_URL) and the default screens
cargo run -p komainu --example custom_screens   # in-memory store and a Japanese login screen
```

The `komainu-testkit` crate has in-memory adapters and a conformance suite
(`komainu_testkit::conformance`) to check your own store implementation.

## Crates

| Crate | Role |
|---|---|
| `komainu` | facade: re-exports and `Komainu::builder()` |
| `komainu-testkit` | in-memory adapters and store conformance tests |
| `komainu-domain` | aggregates, value objects, domain events |
| `komainu-application` | use cases and the ports (traits) they need |
| `komainu-adapter-postgres` | PostgreSQL implementation of the ports, with migrations |
| `komainu-adapter-std` | clock, CSPRNG and Argon2 password hasher |
| `komainu-http` | axum router and screens |
| `komainu-server` | the `komainu` binary |
| `komainu-adapter-http` | `ReqwestJwksFetcher`, which fetches client `jwks_uri` documents |
| `komainu-jose` | JWS, JWK and JWT with RS256 and ES256 |

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --features pg-tests -- -D warnings
cargo test --workspace
cargo test --workspace --features pg-tests   # needs Docker (PostgreSQL via testcontainers)
```

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
