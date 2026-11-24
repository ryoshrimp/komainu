//! The token endpoint use cases and access token verification.

mod error;
mod request;

use komainu_domain::{
    AccessToken, Client, ClientId, CodeVerifier, Grant, GrantId, GrantType, OpaqueToken,
    RedeemCodeError, RedirectUri, RefreshToken, RevocationReason, RotateRefreshTokenError,
    ScopeSet, Secret, TokenEndpointAuthMethod,
};

pub use error::{RevocationError, TokenError};
pub use request::{
    AccessTokenInfo, ClientAuthentication, RevocationRequest, TokenRequest, TokenResponse,
    TokenTypeHint,
};

use crate::audit::{AuditActor, AuditEvent, AuditKind, AuditOutcome};
use crate::context::RequestContext;
use crate::deps::Dependencies;
use crate::ids::{new_opaque_token, new_uuid_v7};
use crate::port::{StoreError, UnitOfWork};
use crate::support::{
    AuditEventExt, append_all, audit_event, code_events, grant_events, refresh_events,
    truncate_chars,
};
use komainu_domain::{ClientType, TokenHash};

#[derive(Clone)]
pub struct TokenService {
    deps: Dependencies,
}

fn domain_failure(error: komainu_domain::DomainError) -> TokenError {
    TokenError::Server(StoreError::Other(error.to_string()))
}

/// Parses a presented token string. `None` when it cannot be a token.
fn parse_token(raw: &str) -> Option<OpaqueToken> {
    OpaqueToken::try_new(Secret::new(raw.to_owned())).ok()
}

impl TokenService {
    pub fn new(deps: Dependencies) -> Self {
        Self { deps }
    }

    /// Handles `POST /token`.
    pub async fn exchange(
        &self,
        ctx: &RequestContext,
        auth: ClientAuthentication,
        request: TokenRequest,
    ) -> Result<TokenResponse, TokenError> {
        if !request.duplicated.is_empty() {
            return Err(TokenError::InvalidRequest);
        }
        let grant_type = match request.grant_type.as_deref() {
            None => return Err(TokenError::InvalidRequest),
            Some("authorization_code") => GrantType::AuthorizationCode,
            Some("client_credentials") => GrantType::ClientCredentials,
            Some("refresh_token") => GrantType::RefreshToken,
            Some(_) => return Err(TokenError::UnsupportedGrantType),
        };
        let uow = self.deps.store.begin().await?;
        let (mut uow, client) = self.authenticate_client(ctx, uow, &auth).await?;
        if !client.supports_grant(grant_type) {
            return Err(TokenError::UnauthorizedClient);
        }
        let step = match grant_type {
            GrantType::AuthorizationCode => {
                self.authorization_code(ctx, uow.as_mut(), &client, &request)
                    .await?
            }
            GrantType::ClientCredentials => {
                self.client_credentials(ctx, uow.as_mut(), &client, &request)
                    .await?
            }
            GrantType::RefreshToken => {
                self.refresh_token(ctx, uow.as_mut(), &client, &request)
                    .await?
            }
        };
        let (response, grant_id, audit) = match step {
            Step::Issued {
                response,
                grant_id,
                audit,
            } => (response, grant_id, *audit),
            Step::Replay {
                events,
                grant_id,
                reason,
            } => return Err(self.finish_replay(ctx, uow, events, grant_id, reason).await),
        };
        let event = audit
            .detail("grant_type", grant_type.as_str())
            .detail("grant_id", grant_id.as_inner().to_string())
            .detail("scope", response.scope.to_string())
            .detail(
                "refresh_token_issued",
                response.refresh_token.is_some().to_string(),
            );
        append_all(uow.as_mut(), vec![event]).await?;
        uow.commit().await?;
        Ok(response)
    }

    /// Handles `POST /revoke` (RFC 7009). Revoking either token revokes its whole grant.
    /// `Ok(())` means revoked, not found, or already revoked.
    pub async fn revoke(
        &self,
        ctx: &RequestContext,
        auth: ClientAuthentication,
        request: RevocationRequest,
    ) -> Result<(), RevocationError> {
        let deps = &self.deps;
        if !request.duplicated.is_empty() {
            return Err(RevocationError::InvalidRequest);
        }
        let raw = request.token.ok_or(RevocationError::InvalidRequest)?;
        let uow = deps.store.begin().await?;
        let (mut uow, client) = match self.authenticate_client(ctx, uow, &auth).await {
            Ok(authenticated) => authenticated,
            Err(TokenError::InvalidClient { basic_attempted }) => {
                return Err(RevocationError::InvalidClient { basic_attempted });
            }
            Err(TokenError::Server(e)) => return Err(RevocationError::Server(e)),
            Err(_) => {
                return Err(RevocationError::Server(StoreError::Other(
                    "unexpected client authentication error".to_owned(),
                )));
            }
        };
        let Some(token) = parse_token(&raw) else {
            return Ok(());
        };
        let hash = token.hash();
        let refresh_first = request
            .token_type_hint
            .as_deref()
            .and_then(TokenTypeHint::parse)
            == Some(TokenTypeHint::RefreshToken);
        let found = if refresh_first {
            match find_refresh_token(uow.as_mut(), &hash).await? {
                Some(found) => Some(found),
                None => find_access_token(uow.as_mut(), &hash).await?,
            }
        } else {
            match find_access_token(uow.as_mut(), &hash).await? {
                Some(found) => Some(found),
                None => find_refresh_token(uow.as_mut(), &hash).await?,
            }
        };
        let Some((token_type, token_client, grant_id)) = found else {
            return Ok(());
        };
        if &token_client != client.id() {
            let event = audit_event(
                deps,
                ctx,
                AuditKind::TokenRevocationClientMismatch,
                AuditOutcome::Failure,
                AuditActor::Client,
            )
            .client(client.id())
            .detail("token_type", token_type)
            .detail("grant_id", grant_id.as_inner().to_string());
            append_all(uow.as_mut(), vec![event]).await?;
            uow.commit().await?;
            return Err(RevocationError::InvalidGrant);
        }
        let mut grant = uow
            .grants()
            .find_for_update(grant_id)
            .await?
            .ok_or_else(|| {
                RevocationError::Server(StoreError::Other("grant not found for token".to_owned()))
            })?;
        if !grant.is_active() {
            return Ok(());
        }
        grant.revoke(RevocationReason::ClientRequest, deps.clock.now());
        uow.grants().update(&grant).await?;
        let events = grant_events(deps, ctx, &mut grant, AuditActor::Client);
        append_all(uow.as_mut(), events).await?;
        uow.commit().await?;
        Ok(())
    }

    /// Returns what the token stands for, or `None` for unknown, malformed, expired or
    /// revoked tokens and for disabled clients. Reads only.
    pub async fn verify_access_token(
        &self,
        token: &str,
    ) -> Result<Option<AccessTokenInfo>, StoreError> {
        let Some(token) = parse_token(token) else {
            return Ok(None);
        };
        let now = self.deps.clock.now();
        let mut uow = self.deps.store.begin().await?;
        let Some(access) = uow.access_tokens().find(&token.hash()).await? else {
            return Ok(None);
        };
        if !access.is_valid_at(now) {
            return Ok(None);
        }
        let grant = uow.grants().find(access.grant_id()).await?;
        if !grant.is_some_and(|g| g.is_active()) {
            return Ok(None);
        }
        let client = uow.clients().find(access.client_id()).await?;
        if !client.is_some_and(|c| c.is_active()) {
            return Ok(None);
        }
        Ok(Some(AccessTokenInfo {
            grant_id: access.grant_id(),
            client_id: access.client_id().clone(),
            subject: access.subject().cloned(),
            scope: access.scope().clone(),
            issued_at: access.issued_at(),
            expires_at: access.expires_at(),
        }))
    }

    /// Step 3. On failure the unit of work is dropped and the failure is audited in a new one.
    async fn authenticate_client(
        &self,
        ctx: &RequestContext,
        mut uow: Box<dyn UnitOfWork>,
        auth: &ClientAuthentication,
    ) -> Result<(Box<dyn UnitOfWork>, Client), TokenError> {
        let deps = &self.deps;
        let (method, presented, secret, basic) = match auth {
            ClientAuthentication::Basic { client_id, secret } => {
                ("client_secret_basic", Some(client_id), Some(secret), true)
            }
            ClientAuthentication::Post { client_id, secret } => {
                ("client_secret_post", Some(client_id), Some(secret), false)
            }
            ClientAuthentication::PublicId { client_id } => ("none", Some(client_id), None, false),
            ClientAuthentication::None => ("missing", None, None, false),
        };
        let client = match presented {
            Some(raw) => match ClientId::try_new(raw.clone()) {
                Ok(id) => uow.clients().find(&id).await?,
                Err(_) => None,
            },
            None => None,
        };
        let verified = client.filter(|client| {
            if !client.is_active() {
                return false;
            }
            match (auth, secret) {
                (ClientAuthentication::PublicId { .. }, _) => {
                    client.client_type() == ClientType::Public && deps.config.allow_public_clients
                }
                (_, Some(secret)) => {
                    let wanted = if basic {
                        TokenEndpointAuthMethod::ClientSecretBasic
                    } else {
                        TokenEndpointAuthMethod::ClientSecretPost
                    };
                    client.auth_method() == wanted
                        && parse_token(secret.expose_secret_ref())
                            .is_some_and(|presented| client.verify_secret(&presented))
                }
                _ => false,
            }
        });
        if let Some(client) = verified {
            return Ok((uow, client));
        }
        drop(uow);
        let event = audit_event(
            deps,
            ctx,
            AuditKind::ClientAuthenticationFailed,
            AuditOutcome::Failure,
            AuditActor::Client,
        )
        .detail("method", method)
        .detail(
            "client_id_presented",
            presented.map_or_else(|| "null".to_owned(), |id| truncate_chars(id, 64)),
        );
        let mut audit_uow = deps.store.begin().await?;
        append_all(audit_uow.as_mut(), vec![event]).await?;
        audit_uow.commit().await?;
        Err(TokenError::InvalidClient {
            basic_attempted: basic,
        })
    }

    fn expires_in(&self) -> u64 {
        u64::try_from(self.deps.config.access_token_ttl.whole_seconds()).unwrap_or(0)
    }

    /// A `token.issued` event without the grant-specific details.
    fn issued_event(&self, ctx: &RequestContext, client: &Client, grant: &Grant) -> AuditEvent {
        let mut event = audit_event(
            &self.deps,
            ctx,
            AuditKind::TokenIssued,
            AuditOutcome::Success,
            AuditActor::Client,
        )
        .client(client.id());
        if let Some(subject) = grant.subject() {
            event = event.subject(subject);
        }
        event
    }

    /// Commits the replay audit and the revocation of the grant, then returns the error.
    async fn finish_replay(
        &self,
        ctx: &RequestContext,
        mut uow: Box<dyn UnitOfWork>,
        replay: Vec<AuditEvent>,
        grant_id: GrantId,
        reason: RevocationReason,
    ) -> TokenError {
        let result: Result<(), StoreError> = async {
            let deps = &self.deps;
            let mut events = replay;
            if let Some(mut grant) = uow.grants().find_for_update(grant_id).await? {
                grant.revoke(reason, deps.clock.now());
                let revoked = grant_events(deps, ctx, &mut grant, AuditActor::Client);
                if !revoked.is_empty() {
                    uow.grants().update(&grant).await?;
                    events.extend(revoked);
                }
            }
            append_all(uow.as_mut(), events).await?;
            uow.commit().await
        }
        .await;
        match result {
            Ok(()) => TokenError::InvalidGrant,
            Err(e) => TokenError::Server(e),
        }
    }

    async fn authorization_code(
        &self,
        ctx: &RequestContext,
        uow: &mut dyn UnitOfWork,
        client: &Client,
        request: &TokenRequest,
    ) -> Result<Step, TokenError> {
        let deps = &self.deps;
        let now = deps.clock.now();
        let raw = request.code.as_deref().ok_or(TokenError::InvalidRequest)?;
        let raw_verifier = request
            .code_verifier
            .as_deref()
            .ok_or(TokenError::InvalidRequest)?;
        let code_token = parse_token(raw).ok_or(TokenError::InvalidGrant)?;
        let code_verifier = CodeVerifier::try_new(Secret::new(raw_verifier.to_owned()))
            .map_err(|_| TokenError::InvalidGrant)?;
        let mut code = uow
            .authorization_codes()
            .find_for_update(&code_token.hash())
            .await?
            .ok_or(TokenError::InvalidGrant)?;
        let redirect_uri = match request.redirect_uri.as_deref() {
            Some(raw) => {
                Some(RedirectUri::try_new(raw.to_owned()).map_err(|_| TokenError::InvalidGrant)?)
            }
            None => None,
        };
        let grant_id = GrantId::new(new_uuid_v7(deps.clock.as_ref(), deps.random.as_ref()));
        match code.redeem(
            client.id(),
            redirect_uri.as_ref(),
            &code_verifier,
            grant_id,
            now,
        ) {
            Ok(()) => {}
            Err(RedeemCodeError::Replayed { grant_id }) => {
                return Ok(Step::Replay {
                    events: code_events(deps, ctx, &mut code),
                    grant_id,
                    reason: RevocationReason::CodeReplay,
                });
            }
            Err(_) => return Err(TokenError::InvalidGrant),
        }
        let grant = Grant::from_authorization_code(grant_id, &code, now);
        // The grant goes first: tokens and the code reference it.
        uow.grants().insert(&grant).await?;
        uow.authorization_codes().update(&code).await?;
        let response = self
            .issue_tokens(uow, client, &grant, grant.scope().clone(), true, now)
            .await?;
        Ok(self.issued(ctx, client, &grant, response))
    }

    async fn client_credentials(
        &self,
        ctx: &RequestContext,
        uow: &mut dyn UnitOfWork,
        client: &Client,
        request: &TokenRequest,
    ) -> Result<Step, TokenError> {
        let deps = &self.deps;
        let now = deps.clock.now();
        let requested = match request.scope.as_deref() {
            Some(raw) => Some(ScopeSet::parse(raw).map_err(|_| TokenError::InvalidScope)?),
            None => None,
        };
        let scope = client
            .resolve_scope(requested.as_ref())
            .map_err(|_| TokenError::InvalidScope)?;
        let grant_id = GrantId::new(new_uuid_v7(deps.clock.as_ref(), deps.random.as_ref()));
        let grant =
            Grant::for_client_credentials(grant_id, client.id().clone(), scope.clone(), now);
        uow.grants().insert(&grant).await?;
        let response = self
            .issue_tokens(uow, client, &grant, scope, false, now)
            .await?;
        Ok(self.issued(ctx, client, &grant, response))
    }

    async fn refresh_token(
        &self,
        ctx: &RequestContext,
        uow: &mut dyn UnitOfWork,
        client: &Client,
        request: &TokenRequest,
    ) -> Result<Step, TokenError> {
        let deps = &self.deps;
        let now = deps.clock.now();
        let raw = request
            .refresh_token
            .as_deref()
            .ok_or(TokenError::InvalidRequest)?;
        let presented = parse_token(raw).ok_or(TokenError::InvalidGrant)?;
        let mut old = uow
            .refresh_tokens()
            .find_for_update(&presented.hash())
            .await?
            .ok_or(TokenError::InvalidGrant)?;
        match old.rotate(client.id(), now) {
            Ok(()) => {}
            Err(RotateRefreshTokenError::Replayed { grant_id }) => {
                return Ok(Step::Replay {
                    events: refresh_events(deps, ctx, &mut old),
                    grant_id,
                    reason: RevocationReason::RefreshTokenReplay,
                });
            }
            Err(_) => return Err(TokenError::InvalidGrant),
        }
        let grant = uow
            .grants()
            .find_for_update(old.grant_id())
            .await?
            .filter(Grant::is_active)
            .ok_or(TokenError::InvalidGrant)?;
        let scope = match request.scope.as_deref() {
            None => grant.scope().clone(),
            Some(raw) => {
                let scope = ScopeSet::parse(raw).map_err(|_| TokenError::InvalidScope)?;
                if !scope.is_subset(grant.scope()) {
                    return Err(TokenError::InvalidScope);
                }
                scope
            }
        };
        let response = self
            .issue_tokens(uow, client, &grant, scope, true, now)
            .await?;
        uow.refresh_tokens().update(&old).await?;
        Ok(self.issued(ctx, client, &grant, response))
    }

    /// Creates and stores the access token (and the refresh token when `refresh` and the
    /// client may use it).
    async fn issue_tokens(
        &self,
        uow: &mut dyn UnitOfWork,
        client: &Client,
        grant: &Grant,
        scope: ScopeSet,
        refresh: bool,
        now: time::OffsetDateTime,
    ) -> Result<TokenResponse, TokenError> {
        let deps = &self.deps;
        let access = new_opaque_token(deps.random.as_ref());
        let record = AccessToken::issue(
            access.hash(),
            grant,
            scope.clone(),
            now,
            deps.config.access_token_ttl,
        )
        .map_err(domain_failure)?;
        uow.access_tokens().insert(&record).await?;
        let mut refresh_token = None;
        if refresh && client.supports_grant(GrantType::RefreshToken) {
            let token = new_opaque_token(deps.random.as_ref());
            let record =
                RefreshToken::issue(token.hash(), grant, now, deps.config.refresh_token_ttl)
                    .map_err(domain_failure)?;
            uow.refresh_tokens().insert(&record).await?;
            refresh_token = Some(token);
        }
        Ok(TokenResponse {
            access_token: access,
            token_type: "Bearer",
            expires_in: self.expires_in(),
            refresh_token,
            scope,
        })
    }

    fn issued(
        &self,
        ctx: &RequestContext,
        client: &Client,
        grant: &Grant,
        response: TokenResponse,
    ) -> Step {
        Step::Issued {
            audit: Box::new(self.issued_event(ctx, client, grant)),
            grant_id: *grant.id(),
            response,
        }
    }
}

/// Result of a per-grant step.
enum Step {
    Issued {
        response: TokenResponse,
        grant_id: GrantId,
        audit: Box<AuditEvent>,
    },
    /// Replay detected: revoke the grant and commit `events`, then fail.
    Replay {
        events: Vec<AuditEvent>,
        grant_id: GrantId,
        reason: RevocationReason,
    },
}

/// `(token_type, client_id, grant_id)` of a token presented to the revocation endpoint.
type FoundToken = (&'static str, ClientId, GrantId);

async fn find_refresh_token(
    uow: &mut dyn UnitOfWork,
    hash: &TokenHash,
) -> Result<Option<FoundToken>, StoreError> {
    Ok(uow
        .refresh_tokens()
        .find_for_update(hash)
        .await?
        .map(|t| ("refresh_token", t.client_id().clone(), t.grant_id())))
}

async fn find_access_token(
    uow: &mut dyn UnitOfWork,
    hash: &TokenHash,
) -> Result<Option<FoundToken>, StoreError> {
    Ok(uow
        .access_tokens()
        .find(hash)
        .await?
        .map(|t| ("access_token", t.client_id().clone(), t.grant_id())))
}
