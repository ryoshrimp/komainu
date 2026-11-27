//! The token endpoint use cases and access token verification.

mod error;
mod request;

use komainu_domain::{
    AccessToken, Client, ClientId, ClientKeys, CodeVerifier, Grant, GrantId, GrantType,
    OpaqueToken, RedeemCodeError, RedirectUri, RefreshToken, RevocationReason,
    RotateRefreshTokenError, ScopeSet, Secret, TokenEndpointAuthMethod,
};
use komainu_jose::{JwkSet, jwt};

pub use error::{RevocationError, TokenError};
pub use request::{
    AccessTokenInfo, ClientAuthentication, RevocationRequest, TokenRequest, TokenResponse,
    TokenTypeHint,
};

use crate::assertion::jwks::{Freshness, KeyResolveError};
use crate::assertion::verify::{AssertionError, Expected, verify_assertion};
use crate::assertion::{ASSERTION_LEEWAY, ASSERTION_MAX_LEN};
use crate::audit::{AuditActor, AuditEvent, AuditKind, AuditOutcome};
use crate::context::RequestContext;
use crate::deps::Dependencies;
use crate::ids::{new_opaque_token, new_uuid_v7};
use crate::port::{AssertionKind, RecordOutcome, StoreError, UnitOfWork, UsedAssertion};
use crate::support::{
    AuditEventExt, append_all, audit_event, code_events, grant_events, refresh_events,
    truncate_chars,
};
use komainu_domain::{ClientType, TokenHash};

#[derive(Clone)]
pub struct TokenService {
    deps: Dependencies,
}

/// Why `authenticate_assertion` did not accept.
enum AssertionRejected {
    /// `client_id` and the assertion's `iss` differ (400, not audited).
    Request,
    /// 401 `invalid_client`, audited with this reason.
    Reason(&'static str),
    Store(StoreError),
}

impl From<&'static str> for AssertionRejected {
    fn from(reason: &'static str) -> Self {
        Self::Reason(reason)
    }
}

impl From<StoreError> for AssertionRejected {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// The audit reason of a failed `jwks_uri` resolution.
fn key_failure(error: KeyResolveError) -> AssertionRejected {
    match error {
        KeyResolveError::InvalidJwks => "invalid_jwks".into(),
        KeyResolveError::Fetch(_) | KeyResolveError::RefetchTooSoon => "key_fetch_failed".into(),
    }
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

    /// What this server supports. Equivalent to `ServerCapabilities::from_config` of the
    /// configuration this service was built with.
    pub fn server_capabilities(&self) -> crate::ServerCapabilities {
        crate::ServerCapabilities::from_config(&self.deps.config)
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
            // Placeholder: the wire value is not parsed above. T7 replaces this with the
            // jwt-bearer grant.
            GrantType::JwtBearer => return Err(TokenError::UnsupportedGrantType),
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
            Err(TokenError::InvalidRequest) => return Err(RevocationError::InvalidRequest),
            Err(TokenError::Server(e)) => return Err(RevocationError::Server(e)),
            Err(_) => {
                return Err(RevocationError::Server(StoreError::Other(
                    "unexpected client authentication error".to_owned(),
                )));
            }
        };
        // An assertion's `jti` is recorded in this unit of work, so every success path of
        // this method must commit it (D-3). Otherwise the assertion could be replayed.
        let keep_jti = matches!(auth, ClientAuthentication::Assertion { .. });
        let Some(token) = parse_token(&raw) else {
            return Self::finish_revoke_noop(uow, keep_jti).await;
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
            return Self::finish_revoke_noop(uow, keep_jti).await;
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
            return Self::finish_revoke_noop(uow, keep_jti).await;
        }
        grant.revoke(RevocationReason::ClientRequest, deps.clock.now());
        uow.grants().update(&grant).await?;
        let events = grant_events(deps, ctx, &mut grant, AuditActor::Client);
        append_all(uow.as_mut(), events).await?;
        uow.commit().await?;
        Ok(())
    }

    /// Ends a `revoke` that changed nothing. Commits only to keep an assertion's `jti`.
    async fn finish_revoke_noop(
        uow: Box<dyn UnitOfWork>,
        keep_jti: bool,
    ) -> Result<(), RevocationError> {
        if keep_jti {
            uow.commit().await?;
        }
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
            ClientAuthentication::Assertion {
                client_id,
                assertion,
            } => {
                return self
                    .authenticate_assertion(ctx, uow, client_id.as_deref(), assertion)
                    .await;
            }
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
        self.fail_authentication(ctx, method, presented.map(String::as_str), None)
            .await?;
        Err(TokenError::InvalidClient {
            basic_attempted: basic,
        })
    }

    /// Audits a failed client authentication in a new unit of work.
    async fn fail_authentication(
        &self,
        ctx: &RequestContext,
        method: &'static str,
        presented: Option<&str>,
        reason: Option<&'static str>,
    ) -> Result<(), StoreError> {
        let deps = &self.deps;
        let mut event = audit_event(
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
        if let Some(reason) = reason {
            event = event.detail("reason", reason);
        }
        let mut audit_uow = deps.store.begin().await?;
        append_all(audit_uow.as_mut(), vec![event]).await?;
        audit_uow.commit().await
    }

    /// `private_key_jwt` (RFC 7523 §2.2). On rejection the unit of work is dropped (the `jti`
    /// record with it) and the failure is audited in a new one.
    async fn authenticate_assertion(
        &self,
        ctx: &RequestContext,
        mut uow: Box<dyn UnitOfWork>,
        client_id: Option<&str>,
        assertion: &Secret<String>,
    ) -> Result<(Box<dyn UnitOfWork>, Client), TokenError> {
        let mut presented = client_id.map(str::to_owned);
        match self
            .verify_client_assertion(
                uow.as_mut(),
                client_id,
                assertion.expose_secret_ref(),
                &mut presented,
            )
            .await
        {
            Ok(client) => Ok((uow, client)),
            Err(AssertionRejected::Request) => Err(TokenError::InvalidRequest),
            Err(AssertionRejected::Store(e)) => Err(TokenError::Server(e)),
            Err(AssertionRejected::Reason(reason)) => {
                drop(uow);
                self.fail_authentication(
                    ctx,
                    "private_key_jwt",
                    presented.as_deref(),
                    Some(reason),
                )
                .await?;
                Err(TokenError::InvalidClient {
                    basic_attempted: false,
                })
            }
        }
    }

    /// Steps 1 to 7 of the client assertion check. `presented` is updated with the `iss`
    /// once it has been read.
    async fn verify_client_assertion(
        &self,
        uow: &mut dyn UnitOfWork,
        client_id: Option<&str>,
        assertion: &str,
        presented: &mut Option<String>,
    ) -> Result<Client, AssertionRejected> {
        let deps = &self.deps;
        let Some(issuer) = deps.config.issuer.as_deref() else {
            return Err("not_configured".into());
        };
        let claims = jwt::peek_unverified(assertion, ASSERTION_MAX_LEN)
            .map_err(|_| AssertionRejected::from("malformed"))?;
        let (Some(iss), Some(sub)) = (claims.iss, claims.sub) else {
            return Err("malformed".into());
        };
        *presented = Some(iss.clone());
        if iss != sub {
            return Err("subject_mismatch".into());
        }
        if client_id.is_some_and(|given| given != iss) {
            return Err(AssertionRejected::Request);
        }
        let client = match ClientId::try_new(iss.clone()) {
            Ok(id) => uow.clients().find(&id).await?,
            Err(_) => None,
        };
        let Some(client) = client else {
            return Err("unknown_client".into());
        };
        if !client.is_active() {
            return Err("client_disabled".into());
        }
        if client.auth_method() != TokenEndpointAuthMethod::PrivateKeyJwt {
            return Err("method_not_allowed".into());
        }
        let uri = match client.keys() {
            Some(ClientKeys::JwksUri(uri)) => Some(uri),
            _ => None,
        };
        let keys: std::sync::Arc<JwkSet> = match client.keys() {
            Some(ClientKeys::Jwks(doc)) => std::sync::Arc::new(
                JwkSet::from_json(doc.as_str())
                    .map_err(|_| AssertionRejected::from("invalid_jwks"))?,
            ),
            Some(ClientKeys::JwksUri(uri)) => deps
                .jwks
                .keys(uri, Freshness::Cached)
                .await
                .map_err(key_failure)?,
            None => return Err("invalid_jwks".into()),
        };
        let now = deps.clock.now();
        let token_endpoint = format!("{issuer}/token");
        let expected = Expected {
            issuer: &iss,
            subject: Some(&iss),
            audiences: [issuer, &token_endpoint],
        };
        let verified = match verify_assertion(assertion, keys.keys(), &expected, now) {
            Err(AssertionError::KeyNotFound) if let Some(uri) = uri => {
                // An unknown `kid` may be a rotated key: refetch (at most once a minute).
                let keys = match deps.jwks.keys(uri, Freshness::Refresh).await {
                    Err(KeyResolveError::RefetchTooSoon) => {
                        return Err(AssertionError::KeyNotFound.reason().into());
                    }
                    other => other.map_err(key_failure)?,
                };
                verify_assertion(assertion, keys.keys(), &expected, now)
            }
            other => other,
        }
        .map_err(|e| AssertionRejected::from(e.reason()))?;
        let used = UsedAssertion {
            kind: AssertionKind::ClientAuthentication,
            issuer: iss,
            jti: verified.jti,
            expires_at: verified.exp + ASSERTION_LEEWAY,
        };
        match uow.used_assertions().record(&used).await? {
            RecordOutcome::Recorded => Ok(client),
            RecordOutcome::Replayed => Err("replay".into()),
        }
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
