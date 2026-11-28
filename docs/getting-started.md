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

## 7. Enable signing keys (optional)

Signing is off until you set a key encryption key. komainu then creates the authorization server's
signing keys, stores their private parts encrypted with that key, and publishes the public parts at
`GET /jwks`. The authorization server metadata gets a `jwks_uri` too.

Generate a key encryption key (32 random bytes in standard base64). The command needs no
configuration file or database:

```sh
export KOMAINU_SIGNING__ENCRYPTION_KEY=$(komainu key generate-encryption-key)
```

Prefer the environment variable to writing the key into `komainu.toml`, and keep it in a secret
store. If you lose the key encryption key, the stored keys can no longer be decrypted. While an
undecryptable `pending` or `active` key remains, signing and `/jwks` fail. To recover:

1. Stop every server instance.
2. Set a new key encryption key.
3. Run `komainu key list` to see the existing keys.
4. Revoke the `pending`, `retired` and `expired` keys first, then the `active` keys. Revoking an
   active key makes a replacement active at once (for an algorithm in `signing.algorithms`),
   encrypted with the new key.
5. Start the server with the new key encryption key.

Tokens issued with the old keys can no longer be verified.

The other items are under `[signing]` and have defaults:

```toml
[signing]
algorithms = ["ES256"]        # "ES256", "RS256"; one active key is kept per algorithm
active_days = 90              # how long a key signs
prepublish_days = 7           # a successor is published this many days before it takes over
retire_overlap_days = 7       # a retired key stays in /jwks this long
rotation_interval_secs = 3600 # how often the server checks for keys to create or delete
```

Constraints: `prepublish_days` is at least 1 and less than `active_days`;
`retire_overlap_days` x 86400 must be at least `oauth.access_token_ttl_secs`;
`rotation_interval_secs` is at least 60 and less than `prepublish_days` x 86400.

`komainu serve` rotates keys on start and then every `rotation_interval_secs`. Check the result and
manage keys by hand with `komainu key`:

```sh
komainu key list                  # one line per key: kid, algorithm, status, activates/retires/deletes times
komainu key rotate --alg ES256    # the current keys retire now and a new one is active at once
komainu key revoke KID            # delete a key; a replacement is made active if none would be left
curl http://localhost:8080/jwks
```

`list`, `rotate` and `revoke` take `--format json`. The status is `pending`, `active`, `retired` or
`expired`. `komainu key list|rotate|revoke` exit with code 2 when signing is off, when `rotate --alg`
names an algorithm that is not in `signing.algorithms`, and when the `KID` is malformed. An unknown
`KID` exits with code 3.

## Operations notes

- `GET /.well-known/oauth-authorization-server` serves the authorization server metadata
  (RFC 8414). The `issuer` and every endpoint URL are built from `server.public_base_url`.
  komainu always serves the document at the path `/.well-known/oauth-authorization-server`,
  relative to its router. If `server.public_base_url` has no path, this is the URL RFC 8414
  defines. If it has a path (for example `https://example.com/auth`), RFC 8414 section 3.1 puts
  the document at `/.well-known/oauth-authorization-server/auth`, so the reverse proxy must
  forward that URL to the backend's `/.well-known/oauth-authorization-server`. This assumes the
  proxy strips `/auth` before passing requests to the backend. With nginx:

  ```nginx
  location = /.well-known/oauth-authorization-server/auth {
      proxy_pass http://127.0.0.1:8080/.well-known/oauth-authorization-server;
  }
  location /auth/ {
      proxy_pass http://127.0.0.1:8080/;
  }
  ```
- `oauth.disabled_grant_types` and `oauth.disabled_auth_methods` (arrays, empty by default) turn off
  grants and client authentication methods. Grants: `client_credentials`, `refresh_token`,
  `urn:ietf:params:oauth:grant-type:jwt-bearer` (`authorization_code` cannot be disabled). Methods:
  `client_secret_basic`, `client_secret_post`, `private_key_jwt`, `none`. For example,
  `disabled_grant_types = ["client_credentials"]` removes that grant from the metadata and from
  `/token`. `komainu client create` and update refuse (exit code 2) a client that uses a disabled
  grant or method. If no authentication method is left (for example, `client_secret_basic`,
  `client_secret_post` and `private_key_jwt` are all disabled and public clients are not allowed),
  every command except `komainu key generate-encryption-key` then fails with a configuration error
  (exit code 2).
- `GET /metrics` on the ops listener serves Prometheus metrics.
- Audit events (code issued, token issued, replay detected, logins, client authentication failures,
  admin operations) are rows of the `audit_events` table. They never contain secrets.
- `SIGTERM` stops accepting connections and waits up to `server.shutdown_timeout_secs` for requests in
  flight.
- In production, set `server.public_base_url` to an `https` URL, keep `session.cookie_secure = true`,
  and terminate TLS in a reverse proxy.
