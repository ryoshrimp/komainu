-- JWT assertions: private_key_jwt client keys, jwt_bearer grants, trusted issuers,
-- subject mappings and the replay table.

ALTER TABLE clients DROP CONSTRAINT clients_auth_method_check;
ALTER TABLE clients ADD CONSTRAINT clients_auth_method_check
    CHECK (auth_method IN ('client_secret_basic', 'client_secret_post', 'none', 'private_key_jwt'));
ALTER TABLE clients
    ADD COLUMN jwks text CHECK (jwks IS NULL OR octet_length(jwks) BETWEEN 1 AND 65536),
    ADD COLUMN jwks_uri text CHECK (jwks_uri IS NULL OR octet_length(jwks_uri) BETWEEN 1 AND 2048),
    ADD CONSTRAINT clients_keys_check CHECK (
        (auth_method = 'private_key_jwt') = (jwks IS NOT NULL OR jwks_uri IS NOT NULL)
        AND NOT (jwks IS NOT NULL AND jwks_uri IS NOT NULL)
    );

ALTER TABLE grants DROP CONSTRAINT grants_origin_check;
ALTER TABLE grants ADD CONSTRAINT grants_origin_check
    CHECK (origin IN ('authorization_code', 'client_credentials', 'jwt_bearer'));

CREATE TABLE trusted_issuers (
    id text PRIMARY KEY CHECK (octet_length(id) BETWEEN 1 AND 255),
    jwks text NOT NULL CHECK (octet_length(jwks) BETWEEN 1 AND 65536),
    status text NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE trusted_issuer_clients (
    issuer_id text NOT NULL REFERENCES trusted_issuers (id) ON DELETE CASCADE,
    client_id text NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    PRIMARY KEY (issuer_id, client_id)
);

CREATE TABLE issuer_subjects (
    issuer_id text NOT NULL REFERENCES trusted_issuers (id) ON DELETE CASCADE,
    subject text NOT NULL CHECK (octet_length(subject) BETWEEN 1 AND 255),
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (issuer_id, subject)
);

CREATE TABLE used_assertions (
    kind text NOT NULL CHECK (kind IN ('client_authentication', 'authorization_grant')),
    issuer text NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 255),
    jti text NOT NULL CHECK (octet_length(jti) BETWEEN 1 AND 255),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (kind, issuer, jti)
);

CREATE INDEX used_assertions_expires_at_idx ON used_assertions (expires_at);
