//! Grants, access tokens and refresh tokens.

mod access_token;
mod event;
mod grant;
mod refresh_token;

pub use access_token::{AccessToken, AccessTokenRecord};
pub use event::{AccessTokenEvent, GrantEvent, RefreshTokenEvent};
pub use grant::{Grant, GrantOrigin, GrantRecord, GrantStatus, RevocationReason};
pub use refresh_token::{
    RefreshToken, RefreshTokenRecord, RefreshTokenStatus, RotateRefreshTokenError,
};

#[cfg(test)]
mod test_support {
    use time::{Duration, OffsetDateTime};

    use crate::*;

    pub fn t0() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    pub fn gid(n: u128) -> GrantId {
        GrantId::new(uuid::Uuid::from_u128(n))
    }

    pub fn scopes(s: &str) -> ScopeSet {
        ScopeSet::parse(s).unwrap()
    }

    pub fn cid() -> ClientId {
        ClientId::try_new("c1".to_owned()).unwrap()
    }

    /// An active authorization-code grant with scope `read write`.
    pub fn code_grant() -> Grant {
        let mut request = AuthorizationRequest::create(
            NewAuthorizationRequest {
                id: AuthorizationRequestId::new(uuid::Uuid::from_u128(1)),
                client_id: cid(),
                redirect_uri: RedirectUri::try_new("https://a.example/cb".to_owned()).unwrap(),
                redirect_uri_provided: true,
                scope: scopes("read write"),
                state: None,
                csrf_token_hash: TokenHash::from_bytes([1; 32]),
            },
            t0(),
            Duration::seconds(600),
        );
        request
            .approve(Subject::try_new("u1".to_owned()).unwrap(), t0())
            .unwrap();
        let code = AuthorizationCode::issue(
            TokenHash::from_bytes([2; 32]),
            &request,
            t0(),
            Duration::seconds(60),
        )
        .unwrap();
        Grant::from_authorization_code(gid(1), &code, t0())
    }
}
