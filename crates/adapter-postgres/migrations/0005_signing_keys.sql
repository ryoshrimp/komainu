-- Signing keys of the authorization server itself (private keys are stored sealed).

CREATE TABLE signing_keys (
    kid text PRIMARY KEY,
    alg text NOT NULL CHECK (alg IN ('ES256', 'RS256')),
    sealed_private_key bytea NOT NULL,
    public_jwk text NOT NULL,
    created_at timestamptz NOT NULL,
    activates_at timestamptz NOT NULL,
    retires_at timestamptz NOT NULL,
    deletes_at timestamptz NOT NULL,
    CHECK (created_at <= activates_at AND activates_at <= retires_at AND retires_at <= deletes_at)
);
