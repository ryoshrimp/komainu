//! Verification of JWT assertions (RFC 7521 / 7523) and the cache of `jwks_uri` keys.

pub(crate) mod jwks;
pub(crate) mod verify;

pub use jwks::JwksResolver;

/// The only accepted `client_assertion_type`.
pub const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/// The jwt-bearer `grant_type` (same as `GrantType::JwtBearer.as_str()`).
pub const GRANT_TYPE_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// Clock skew allowed for `exp`, `nbf` and `iat`.
pub const ASSERTION_LEEWAY: time::Duration = time::Duration::seconds(60);
/// The largest allowed `exp - now`.
pub const ASSERTION_MAX_LIFETIME: time::Duration = time::Duration::seconds(300);
/// The longest accepted assertion string, in bytes.
pub const ASSERTION_MAX_LEN: usize = 8192;
/// How long a fetched `jwks_uri` is cached.
pub const JWKS_CACHE_TTL: time::Duration = time::Duration::seconds(3600);
/// The shortest interval between fetches of the same `jwks_uri`.
pub const JWKS_MIN_REFETCH_INTERVAL: time::Duration = time::Duration::seconds(60);
