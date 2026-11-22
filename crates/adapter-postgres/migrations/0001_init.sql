-- komainu initial schema. Timestamps are timestamptz, token hashes are 32-byte bytea.

CREATE TABLE clients (
    id text PRIMARY KEY,
    name text NOT NULL,
    client_type text NOT NULL CHECK (client_type IN ('confidential', 'public')),
    auth_method text NOT NULL CHECK (auth_method IN ('client_secret_basic', 'client_secret_post', 'none')),
    secret_hash bytea CHECK (secret_hash IS NULL OR octet_length(secret_hash) = 32),
    redirect_uris text[] NOT NULL,
    grant_types text[] NOT NULL,
    allowed_scopes text[] NOT NULL,
    default_scopes text[] NOT NULL,
    skip_consent boolean NOT NULL,
    status text NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE users (
    id uuid PRIMARY KEY,
    username text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    status text NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE login_sessions (
    id bytea PRIMARY KEY CHECK (octet_length(id) = 32),
    subject text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX login_sessions_subject_idx ON login_sessions (subject);
CREATE INDEX login_sessions_expires_at_idx ON login_sessions (expires_at);

CREATE TABLE authorization_requests (
    id uuid PRIMARY KEY,
    client_id text NOT NULL REFERENCES clients (id),
    redirect_uri text NOT NULL,
    redirect_uri_provided boolean NOT NULL,
    scope text[] NOT NULL,
    state text,
    csrf_token_hash bytea NOT NULL CHECK (octet_length(csrf_token_hash) = 32),
    status text NOT NULL CHECK (status IN ('pending', 'approved', 'denied')),
    subject text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX authorization_requests_expires_at_idx ON authorization_requests (expires_at);

CREATE TABLE consents (
    subject text NOT NULL,
    client_id text NOT NULL REFERENCES clients (id),
    scope text[] NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (subject, client_id)
);

CREATE TABLE grants (
    id uuid PRIMARY KEY,
    client_id text NOT NULL REFERENCES clients (id),
    subject text,
    scope text[] NOT NULL,
    origin text NOT NULL CHECK (origin IN ('authorization_code', 'client_credentials')),
    -- Hash of the code that created the grant. Deliberately no foreign key: codes are purged earlier.
    origin_code_hash bytea CHECK (origin_code_hash IS NULL OR octet_length(origin_code_hash) = 32),
    status text NOT NULL CHECK (status IN ('active', 'revoked')),
    revoked_at timestamptz,
    revocation_reason text CHECK (revocation_reason IN ('code_replay', 'refresh_token_replay', 'client_disabled', 'user_disabled')),
    created_at timestamptz NOT NULL,
    CHECK (origin <> 'authorization_code' OR origin_code_hash IS NOT NULL)
);
CREATE INDEX grants_active_client_idx ON grants (client_id) WHERE status = 'active';
CREATE INDEX grants_active_subject_idx ON grants (subject) WHERE status = 'active';

CREATE TABLE authorization_codes (
    id bytea PRIMARY KEY CHECK (octet_length(id) = 32),
    client_id text NOT NULL REFERENCES clients (id),
    subject text NOT NULL,
    redirect_uri text NOT NULL,
    redirect_uri_provided boolean NOT NULL,
    scope text[] NOT NULL,
    status text NOT NULL CHECK (status IN ('issued', 'redeemed')),
    grant_id uuid REFERENCES grants (id),
    redeemed_at timestamptz,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CHECK (status <> 'redeemed' OR (grant_id IS NOT NULL AND redeemed_at IS NOT NULL))
);
CREATE INDEX authorization_codes_expires_at_idx ON authorization_codes (expires_at);
-- Not in the design: serves the NOT EXISTS (authorization_codes.grant_id) probe of the grants purge.
CREATE INDEX authorization_codes_grant_id_idx ON authorization_codes (grant_id);

CREATE TABLE access_tokens (
    id bytea PRIMARY KEY CHECK (octet_length(id) = 32),
    grant_id uuid NOT NULL REFERENCES grants (id),
    client_id text NOT NULL,
    subject text,
    scope text[] NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX access_tokens_grant_id_idx ON access_tokens (grant_id);
CREATE INDEX access_tokens_expires_at_idx ON access_tokens (expires_at);

CREATE TABLE refresh_tokens (
    id bytea PRIMARY KEY CHECK (octet_length(id) = 32),
    grant_id uuid NOT NULL REFERENCES grants (id),
    client_id text NOT NULL,
    status text NOT NULL CHECK (status IN ('active', 'rotated')),
    rotated_at timestamptz,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX refresh_tokens_grant_id_idx ON refresh_tokens (grant_id);
CREATE INDEX refresh_tokens_expires_at_idx ON refresh_tokens (expires_at);

CREATE TABLE audit_events (
    id uuid PRIMARY KEY,
    occurred_at timestamptz NOT NULL,
    kind text NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('success', 'failure')),
    actor text NOT NULL,
    request_id text NOT NULL,
    client_ip inet,
    client_id text,
    subject text,
    details jsonb NOT NULL
);
CREATE INDEX audit_events_occurred_at_idx ON audit_events (occurred_at);
CREATE INDEX audit_events_client_idx ON audit_events (client_id, occurred_at);
CREATE INDEX audit_events_subject_idx ON audit_events (subject, occurred_at);
