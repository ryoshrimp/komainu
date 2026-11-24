# Getting started

This guide starts komainu on your machine, gets a token with the client credentials grant, and then
runs the authorization code flow with a refresh token. It is for local development only: it uses
plain HTTP.

## Requirements

- Rust 1.100 (`rust-toolchain.toml` selects it)
- PostgreSQL 16 or later. For example, with Docker:

  ```sh
  docker run -d --name komainu-pg -e POSTGRES_USER=komainu -e POSTGRES_PASSWORD=komainu \
    -e POSTGRES_DB=komainu -p 5432:5432 postgres:16-alpine
  ```

## 1. Build

```sh
cargo build --release
export PATH="$PWD/target/release:$PATH"
```

## 2. Configure

Create `komainu.toml` in the current directory:

```toml
[server]
listen = "127.0.0.1:8080"
public_base_url = "http://localhost:8080"
allow_insecure_http = true      # local development only

[database]
url = "postgres://komainu:komainu@localhost:5432/komainu"

[session]
cookie_secure = false           # local development only

[[scopes]]
name = "read"
description = "Read your data"

[[scopes]]
name = "write"
description = "Modify your data"
```

All other items have defaults; see [config/komainu.example.toml](../config/komainu.example.toml).

## 3. Migrate and register clients

```sh
komainu migrate

komainu client create --name service --grant-type client_credentials --scope read
komainu client create --name web \
  --redirect-uri http://localhost:3000/callback \
  --grant-type authorization_code --grant-type refresh_token --scope "read write"
echo 'a-long-enough-password' | komainu user create alice
```

Each `client create` prints `client_id` and `client_secret`. Copy the secret now; it cannot be
shown again (`komainu client rotate-secret` issues a new one).

## 4. Run

```sh
komainu serve          # or: komainu serve --migrate
curl -i http://127.0.0.1:9090/readyz     # ops listener: 200 when the database is reachable
```

## 5. Client credentials

```sh
curl -u "$SERVICE_ID:$SERVICE_SECRET" -d grant_type=client_credentials -d scope=read \
  http://localhost:8080/token
```

The response is JSON with `access_token`, `token_type` (`Bearer`), `expires_in` and `scope`. There
is no refresh token for this grant.

## 6. Authorization code

PKCE is required for every client. Make a random `code_verifier` and its S256 `code_challenge`:

```sh
VERIFIER=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
CHALLENGE=$(printf %s "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
echo "$CHALLENGE"
```

Open this URL in a browser (replace `WEB_ID` and `CHALLENGE`):

```
http://localhost:8080/authorize?response_type=code&client_id=WEB_ID&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=read&state=xyz&code_challenge=CHALLENGE&code_challenge_method=S256
```

Sign in as `alice` and allow the access. The browser is redirected to
`http://localhost:3000/callback?code=...&state=xyz` (nothing needs to listen there; copy the
`code` from the address bar). The code is valid for 60 seconds and can be used once:

```sh
curl -u "$WEB_ID:$WEB_SECRET" -d grant_type=authorization_code -d code=CODE -d code_verifier="$VERIFIER" \
  --data-urlencode redirect_uri=http://localhost:3000/callback http://localhost:8080/token
```

Use the returned `refresh_token` to get a new pair. The old refresh token stops working, and
presenting it again revokes the whole series:

```sh
curl -u "$WEB_ID:$WEB_SECRET" -d grant_type=refresh_token -d refresh_token=REFRESH_TOKEN \
  http://localhost:8080/token
```

## Operations notes

- `GET /metrics` on the ops listener serves Prometheus metrics.
- Audit events (code issued, token issued, replay detected, logins, client authentication failures,
  admin operations) are rows of the `audit_events` table. They never contain secrets.
- `SIGTERM` stops accepting connections and waits up to `server.shutdown_timeout_secs` for requests in
  flight.
- In production, set `server.public_base_url` to an `https` URL, keep `session.cookie_secure = true`,
  and terminate TLS in a reverse proxy.
