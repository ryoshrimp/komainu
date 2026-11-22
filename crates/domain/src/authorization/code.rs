use ddd_toolkit::{AggregateRoot, Entity};
use time::{Duration, OffsetDateTime};

use super::event::AuthorizationCodeEvent;
use super::request::{AuthorizationRequest, AuthorizationRequestStatus};
use crate::error::DomainError;
use crate::{ClientId, GrantId, RedirectUri, ScopeSet, Subject, TokenHash};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationCodeStatus {
    Issued,
    Redeemed {
        grant_id: GrantId,
        redeemed_at: OffsetDateTime,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedeemCodeError {
    /// Already redeemed: the caller must revoke this grant (§4.1.2).
    Replayed {
        grant_id: GrantId,
    },
    ClientMismatch,
    Expired,
    RedirectUriMismatch,
}

/// An authorization code. Its id is the SHA-256 of the code.
#[derive(Debug, Entity, AggregateRoot)]
pub struct AuthorizationCode {
    #[entity(id)]
    id: TokenHash,
    client_id: ClientId,
    subject: Subject,
    redirect_uri: RedirectUri,
    redirect_uri_provided: bool,
    scope: ScopeSet,
    status: AuthorizationCodeStatus,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    #[aggregate(events)]
    events: Vec<AuthorizationCodeEvent>,
}

/// Persistence form of [`AuthorizationCode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCodeRecord {
    pub id: TokenHash,
    pub client_id: ClientId,
    pub subject: Subject,
    pub redirect_uri: RedirectUri,
    pub redirect_uri_provided: bool,
    pub scope: ScopeSet,
    pub status: AuthorizationCodeStatus,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl AuthorizationCode {
    /// Requires `request.status() == Approved`; otherwise `InvalidState`.
    pub fn issue(
        code_hash: TokenHash,
        request: &AuthorizationRequest,
        now: OffsetDateTime,
        ttl: Duration,
    ) -> Result<AuthorizationCode, DomainError> {
        let (AuthorizationRequestStatus::Approved, Some(subject)) =
            (request.status(), request.subject())
        else {
            return Err(DomainError::InvalidState(
                "authorization request is not approved",
            ));
        };
        let mut code = AuthorizationCode {
            id: code_hash,
            client_id: request.client_id().clone(),
            subject: subject.clone(),
            redirect_uri: request.redirect_uri().clone(),
            redirect_uri_provided: request.redirect_uri_provided(),
            scope: request.scope().clone(),
            status: AuthorizationCodeStatus::Issued,
            issued_at: now,
            expires_at: now + ttl,
            events: Vec::new(),
        };
        let (client_id, subject) = (code.client_id.clone(), code.subject.clone());
        code.record_event(AuthorizationCodeEvent::Issued {
            client_id,
            subject,
            occurred_at: now,
        });
        Ok(code)
    }

    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    pub fn subject(&self) -> &Subject {
        &self.subject
    }

    pub fn scope(&self) -> &ScopeSet {
        &self.scope
    }

    pub fn status(&self) -> &AuthorizationCodeStatus {
        &self.status
    }

    pub fn redeem(
        &mut self,
        client_id: &ClientId,
        redirect_uri: Option<&RedirectUri>,
        grant_id: GrantId,
        now: OffsetDateTime,
    ) -> Result<(), RedeemCodeError> {
        if let AuthorizationCodeStatus::Redeemed {
            grant_id: first, ..
        } = self.status
        {
            let (client_id, subject) = (self.client_id.clone(), self.subject.clone());
            self.record_event(AuthorizationCodeEvent::ReplayDetected {
                client_id,
                subject,
                grant_id: first,
                occurred_at: now,
            });
            return Err(RedeemCodeError::Replayed { grant_id: first });
        }
        if *client_id != self.client_id {
            return Err(RedeemCodeError::ClientMismatch);
        }
        if now >= self.expires_at {
            return Err(RedeemCodeError::Expired);
        }
        let uri_ok = match (self.redirect_uri_provided, redirect_uri) {
            (true, Some(presented)) | (false, Some(presented)) => *presented == self.redirect_uri,
            (true, None) => false,
            (false, None) => true,
        };
        if !uri_ok {
            return Err(RedeemCodeError::RedirectUriMismatch);
        }
        self.status = AuthorizationCodeStatus::Redeemed {
            grant_id,
            redeemed_at: now,
        };
        let (client_id, subject) = (self.client_id.clone(), self.subject.clone());
        self.record_event(AuthorizationCodeEvent::Redeemed {
            client_id,
            subject,
            grant_id,
            occurred_at: now,
        });
        Ok(())
    }

    pub fn to_record(&self) -> AuthorizationCodeRecord {
        AuthorizationCodeRecord {
            id: self.id,
            client_id: self.client_id.clone(),
            subject: self.subject.clone(),
            redirect_uri: self.redirect_uri.clone(),
            redirect_uri_provided: self.redirect_uri_provided,
            scope: self.scope.clone(),
            status: self.status,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        }
    }

    /// Restores a code from storage. Queues no events and does not validate.
    pub fn from_record(record: AuthorizationCodeRecord) -> Self {
        AuthorizationCode {
            id: record.id,
            client_id: record.client_id,
            subject: record.subject,
            redirect_uri: record.redirect_uri,
            redirect_uri_provided: record.redirect_uri_provided,
            scope: record.scope,
            status: record.status,
            issued_at: record.issued_at,
            expires_at: record.expires_at,
            events: Vec::new(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::request::tests::{request, subject, t0};
    use super::*;

    pub fn issued_code(provided: bool) -> AuthorizationCode {
        let mut req = request(provided);
        req.approve(subject(), t0()).unwrap();
        AuthorizationCode::issue(
            TokenHash::from_bytes([7; 32]),
            &req,
            t0(),
            Duration::seconds(60),
        )
        .unwrap()
    }

    fn gid(n: u128) -> GrantId {
        GrantId::new(uuid::Uuid::from_u128(n))
    }

    fn cid() -> ClientId {
        ClientId::try_new("c1".to_owned()).unwrap()
    }

    fn cb() -> RedirectUri {
        RedirectUri::try_new("https://a.example/cb".to_owned()).unwrap()
    }

    #[test]
    fn issue_requires_approved_request() {
        let pending = request(true);
        let result = AuthorizationCode::issue(
            TokenHash::from_bytes([1; 32]),
            &pending,
            t0(),
            Duration::seconds(60),
        );
        assert!(matches!(result, Err(DomainError::InvalidState(_))));
        let mut denied = request(true);
        denied.deny(subject(), t0()).unwrap();
        let result = AuthorizationCode::issue(
            TokenHash::from_bytes([1; 32]),
            &denied,
            t0(),
            Duration::seconds(60),
        );
        assert!(matches!(result, Err(DomainError::InvalidState(_))));
    }

    #[test]
    fn expiry_boundary() {
        let mut ok = issued_code(true);
        assert_eq!(
            ok.redeem(&cid(), Some(&cb()), gid(1), t0() + Duration::seconds(59)),
            Ok(())
        );
        let mut late = issued_code(true);
        assert_eq!(
            late.redeem(&cid(), Some(&cb()), gid(1), t0() + Duration::seconds(60)),
            Err(RedeemCodeError::Expired)
        );
    }

    #[test]
    fn replay_returns_first_grant_id() {
        let mut code = issued_code(true);
        code.pull_events();
        code.redeem(&cid(), Some(&cb()), gid(1), t0()).unwrap();
        assert!(
            matches!(code.status(), AuthorizationCodeStatus::Redeemed { grant_id, .. } if *grant_id == gid(1))
        );
        assert_eq!(
            code.redeem(&cid(), Some(&cb()), gid(2), t0()),
            Err(RedeemCodeError::Replayed { grant_id: gid(1) })
        );
        assert!(matches!(
            code.pull_events().as_slice(),
            [AuthorizationCodeEvent::Redeemed { .. }, AuthorizationCodeEvent::ReplayDetected { grant_id, .. }]
                if *grant_id == gid(1)
        ));
    }

    #[test]
    fn client_and_redirect_uri_checks() {
        let other = ClientId::try_new("c2".to_owned()).unwrap();
        let mut code = issued_code(true);
        assert_eq!(
            code.redeem(&other, Some(&cb()), gid(1), t0()),
            Err(RedeemCodeError::ClientMismatch)
        );
        assert_eq!(
            code.redeem(&cid(), None, gid(1), t0()),
            Err(RedeemCodeError::RedirectUriMismatch)
        );
        let diff = RedirectUri::try_new("https://a.example/cb2".to_owned()).unwrap();
        assert_eq!(
            code.redeem(&cid(), Some(&diff), gid(1), t0()),
            Err(RedeemCodeError::RedirectUriMismatch)
        );
        assert_eq!(code.status(), &AuthorizationCodeStatus::Issued);

        // redirect_uri_provided = false: omitted is fine, a differing one is not.
        let mut code = issued_code(false);
        assert_eq!(
            code.redeem(&cid(), Some(&diff), gid(1), t0()),
            Err(RedeemCodeError::RedirectUriMismatch)
        );
        assert_eq!(code.redeem(&cid(), None, gid(1), t0()), Ok(()));
        let mut code = issued_code(false);
        assert_eq!(code.redeem(&cid(), Some(&cb()), gid(1), t0()), Ok(()));
    }

    #[test]
    fn check_order_client_before_expiry() {
        let other = ClientId::try_new("c2".to_owned()).unwrap();
        let mut code = issued_code(true);
        assert_eq!(
            code.redeem(&other, None, gid(1), t0() + Duration::seconds(120)),
            Err(RedeemCodeError::ClientMismatch)
        );
    }

    #[test]
    fn events_do_not_leak_code_hash() {
        let mut code = issued_code(true);
        code.redeem(&cid(), Some(&cb()), gid(1), t0()).unwrap();
        assert!(matches!(
            code.pull_events().as_slice(),
            [
                AuthorizationCodeEvent::Issued { .. },
                AuthorizationCodeEvent::Redeemed { .. }
            ]
        ));
        let restored = AuthorizationCode::from_record(code.to_record());
        assert_eq!(restored.to_record(), code.to_record());
    }
}
