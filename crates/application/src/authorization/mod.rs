//! The authorization endpoint use cases: start, login, consent and logout.

mod error;
mod params;

use komainu_domain::{
    AuthorizationCode, AuthorizationRequest, AuthorizationRequestId, AuthorizationRequestStatus,
    Client, ClientId, Consent, GrantType, LoginSession, NewAuthorizationRequest, OpaqueToken,
    RedirectUri, ScopeSet, State, Subject,
};
use time::OffsetDateTime;

pub use error::{AuthorizeError, AuthorizeErrorCode, LoginError, NonRedirectableError};
pub use params::AuthorizeParams;

use crate::audit::{AuditActor, AuditKind, AuditOutcome};
use crate::context::RequestContext;
use crate::deps::Dependencies;
use crate::ids::{new_opaque_token, new_uuid_v7};
use crate::port::{AuthenticationOutcome, LoginCredentials, StoreError, UnitOfWork};
use crate::support::{
    AuditEventExt, append_all, audit_event, code_events, consent_events, request_events,
    truncate_chars,
};
use komainu_domain::ClientType;

/// A scope shown on the consent screen.
#[derive(Debug, Clone)]
pub struct ScopeView {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct ConsentPrompt {
    pub client_name: String,
    /// Requested scopes, sorted by name. `description` is "" for scopes not in config.
    pub scopes: Vec<ScopeView>,
}

#[derive(Debug, Clone)]
pub enum AuthorizeOutcome {
    /// Show the login form for this request.
    LoginRequired { request_id: AuthorizationRequestId },
    /// Show the consent screen.
    ConsentRequired {
        request_id: AuthorizationRequestId,
        prompt: ConsentPrompt,
    },
    /// 302 to this absolute URI (code or error response to the client).
    Redirect { location: String },
}

#[derive(Debug)]
pub struct StartResult {
    pub outcome: AuthorizeOutcome,
    /// Set when a new pending request was created and the outcome is not a redirect.
    pub csrf_token: Option<OpaqueToken>,
}

#[derive(Debug, Clone)]
pub struct LoginFormView {
    pub client_name: String,
}

#[derive(Debug)]
pub struct LoggedIn {
    pub session_token: OpaqueToken,
    pub expires_at: OffsetDateTime,
    /// Equals `ApplicationConfig::login_session_ttl`; used for the cookie Max-Age.
    pub max_age: time::Duration,
}

#[derive(Clone)]
pub struct AuthorizationService {
    deps: Dependencies,
}

fn non_redirectable(error: NonRedirectableError) -> AuthorizeError {
    AuthorizeError::NonRedirectable(error)
}

/// Builds the error redirect location. `state` is echoed only when valid.
fn error_location(
    redirect_uri: &RedirectUri,
    code: AuthorizeErrorCode,
    description: &str,
    state: Option<&State>,
) -> String {
    let mut params = vec![("error", code.as_str()), ("error_description", description)];
    if let Some(state) = state {
        params.push(("state", state.as_inner()));
    }
    redirect_uri.with_query_params(&params)
}

/// Builds an error redirect to the client.
fn redirect_error(
    redirect_uri: &RedirectUri,
    code: AuthorizeErrorCode,
    description: &str,
    state: Option<&State>,
) -> AuthorizeError {
    AuthorizeError::Redirect {
        location: error_location(redirect_uri, code, description, state),
        error: code,
    }
}

impl AuthorizationService {
    pub fn new(deps: Dependencies) -> Self {
        Self { deps }
    }

    /// Handles `GET /authorize`.
    pub async fn start(
        &self,
        ctx: &RequestContext,
        params: AuthorizeParams,
        session: Option<&OpaqueToken>,
    ) -> Result<StartResult, AuthorizeError> {
        let deps = &self.deps;
        let now = deps.clock.now();
        let has = |name: &str| params.duplicated.contains(&name);

        // 1-3: errors that must not redirect.
        if has("client_id") || has("redirect_uri") {
            return Err(non_redirectable(NonRedirectableError::DuplicateParameter));
        }
        let Some(raw_client_id) = params.client_id.as_deref() else {
            return Err(non_redirectable(NonRedirectableError::MissingClientId));
        };
        let unknown = || non_redirectable(NonRedirectableError::UnknownClient);
        let client_id = ClientId::try_new(raw_client_id.to_owned()).map_err(|_| unknown())?;
        let mut uow = deps.store.begin().await?;
        let client = uow
            .clients()
            .find(&client_id)
            .await?
            .filter(Client::is_active)
            .ok_or_else(unknown)?;
        let presented = match params.redirect_uri.as_deref() {
            Some(raw) => Some(
                RedirectUri::try_new(raw.to_owned())
                    .map_err(|_| non_redirectable(NonRedirectableError::InvalidRedirectUri))?,
            ),
            None => None,
        };
        let redirect_uri =
            client
                .resolve_redirect_uri(presented.as_ref())
                .map_err(|e| match e {
                    komainu_domain::RedirectUriError::NotRegistered => {
                        non_redirectable(NonRedirectableError::RedirectUriMismatch)
                    }
                    komainu_domain::RedirectUriError::Missing => {
                        non_redirectable(NonRedirectableError::MissingRedirectUri)
                    }
                })?;

        // 4: state must be valid before it can be echoed.
        let state = match params.state.as_deref() {
            Some(raw) => Some(State::try_new(raw.to_owned()).map_err(|_| {
                redirect_error(
                    &redirect_uri,
                    AuthorizeErrorCode::InvalidRequest,
                    "state is malformed",
                    None,
                )
            })?),
            None => None,
        };
        let echo = if has("state") { None } else { state.as_ref() };
        let fail = |code, description: &str| redirect_error(&redirect_uri, code, description, echo);

        // 5-9: errors reported to the client.
        if !params.duplicated.is_empty() {
            return Err(fail(
                AuthorizeErrorCode::InvalidRequest,
                "a parameter appears more than once",
            ));
        }
        match params.response_type.as_deref() {
            None => {
                return Err(fail(
                    AuthorizeErrorCode::InvalidRequest,
                    "response_type is missing",
                ));
            }
            Some("code") => {}
            Some(_) => {
                return Err(fail(
                    AuthorizeErrorCode::UnsupportedResponseType,
                    "response_type must be code",
                ));
            }
        }
        if !client.supports_grant(GrantType::AuthorizationCode)
            || (client.client_type() == ClientType::Public && !deps.config.allow_public_clients)
        {
            return Err(fail(
                AuthorizeErrorCode::UnauthorizedClient,
                "the client is not allowed to use this flow",
            ));
        }
        if state.is_none() && deps.config.require_state {
            return Err(fail(AuthorizeErrorCode::InvalidRequest, "state is missing"));
        }
        let requested = match params.scope.as_deref() {
            Some(raw) => Some(
                ScopeSet::parse(raw)
                    .map_err(|_| fail(AuthorizeErrorCode::InvalidScope, "scope is malformed"))?,
            ),
            None => None,
        };
        let scope = client
            .resolve_scope(requested.as_ref())
            .map_err(|_| fail(AuthorizeErrorCode::InvalidScope, "scope is not allowed"))?;

        // 10: the pending request.
        let csrf = new_opaque_token(deps.random.as_ref());
        let request = AuthorizationRequest::create(
            NewAuthorizationRequest {
                id: AuthorizationRequestId::new(new_uuid_v7(
                    deps.clock.as_ref(),
                    deps.random.as_ref(),
                )),
                client_id,
                redirect_uri,
                redirect_uri_provided: presented.is_some(),
                scope,
                state,
                csrf_token_hash: csrf.hash(),
            },
            now,
            deps.config.authorization_request_ttl,
        );

        // 11
        let subject = self.session_subject(uow.as_mut(), session, now).await?;
        let outcome = self
            .proceed(ctx, uow, &client, request, subject, true)
            .await?;
        let csrf_token = (!matches!(outcome, AuthorizeOutcome::Redirect { .. })).then_some(csrf);
        Ok(StartResult {
            outcome,
            csrf_token,
        })
    }

    /// Returns the data for the login form of a pending request.
    pub async fn login_form(
        &self,
        _ctx: &RequestContext,
        request_id: AuthorizationRequestId,
    ) -> Result<LoginFormView, AuthorizeError> {
        let mut uow = self.deps.store.begin().await?;
        let (_, client) = self
            .load_pending(uow.as_mut(), request_id, self.deps.clock.now())
            .await?;
        Ok(LoginFormView {
            client_name: client.name().as_inner().to_string(),
        })
    }

    /// Authenticates the user and starts a login session.
    pub async fn login(
        &self,
        ctx: &RequestContext,
        request_id: AuthorizationRequestId,
        csrf: &OpaqueToken,
        credentials: LoginCredentials,
    ) -> Result<LoggedIn, LoginError> {
        let deps = &self.deps;
        let now = deps.clock.now();
        let mut uow = deps.store.begin().await?;
        let request = uow
            .authorization_requests()
            .find_for_update(request_id)
            .await?
            .filter(|r| r.status() == AuthorizationRequestStatus::Pending && !r.is_expired(now))
            .ok_or(non_redirectable(NonRedirectableError::RequestNotFound))?;
        if !request.verify_csrf(csrf) {
            return Err(non_redirectable(NonRedirectableError::CsrfMismatch).into());
        }
        let outcome = deps
            .authenticator
            .authenticate(uow.as_mut(), &credentials)
            .await?;
        let subject = match outcome {
            AuthenticationOutcome::Authenticated(subject) => subject,
            failed => {
                drop(uow);
                let reason = match failed {
                    AuthenticationOutcome::Disabled => "disabled",
                    _ => "invalid_credentials",
                };
                let event = audit_event(
                    deps,
                    ctx,
                    AuditKind::LoginFailed,
                    AuditOutcome::Failure,
                    AuditActor::User,
                )
                .client(request.client_id())
                .detail("reason", reason)
                .detail("username", truncate_chars(&credentials.username, 64));
                let mut audit_uow = deps.store.begin().await?;
                append_all(audit_uow.as_mut(), vec![event]).await?;
                audit_uow.commit().await?;
                return Err(LoginError::InvalidCredentials);
            }
        };
        let token = new_opaque_token(deps.random.as_ref());
        let session = LoginSession::start(
            token.hash(),
            subject.clone(),
            now,
            deps.config.login_session_ttl,
        );
        uow.login_sessions().insert(&session).await?;
        let event = audit_event(
            deps,
            ctx,
            AuditKind::LoginSucceeded,
            AuditOutcome::Success,
            AuditActor::User,
        )
        .client(request.client_id())
        .subject(&subject);
        append_all(uow.as_mut(), vec![event]).await?;
        uow.commit().await?;
        Ok(LoggedIn {
            session_token: token,
            expires_at: now + deps.config.login_session_ttl,
            max_age: deps.config.login_session_ttl,
        })
    }

    /// Continues a stored request after login (same decision as the end of `start`).
    pub async fn resume(
        &self,
        ctx: &RequestContext,
        request_id: AuthorizationRequestId,
        session: Option<&OpaqueToken>,
    ) -> Result<AuthorizeOutcome, AuthorizeError> {
        let now = self.deps.clock.now();
        let mut uow = self.deps.store.begin().await?;
        let (request, client) = self.load_pending(uow.as_mut(), request_id, now).await?;
        let subject = self.session_subject(uow.as_mut(), session, now).await?;
        self.proceed(ctx, uow, &client, request, subject, false)
            .await
    }

    /// Records the user's consent decision and returns the redirect target.
    pub async fn decide(
        &self,
        ctx: &RequestContext,
        request_id: AuthorizationRequestId,
        csrf: &OpaqueToken,
        session: Option<&OpaqueToken>,
        approve: bool,
    ) -> Result<String, AuthorizeError> {
        let deps = &self.deps;
        let now = deps.clock.now();
        let mut uow = deps.store.begin().await?;
        let (mut request, _client) = self.load_pending(uow.as_mut(), request_id, now).await?;
        if !request.verify_csrf(csrf) {
            return Err(non_redirectable(NonRedirectableError::CsrfMismatch));
        }
        let Some(subject) = self.session_subject(uow.as_mut(), session, now).await? else {
            return Err(non_redirectable(NonRedirectableError::LoginRequired));
        };
        let not_found = |_| non_redirectable(NonRedirectableError::RequestNotFound);
        let mut events = Vec::new();
        let location = if approve {
            let scope = request.scope().clone();
            let mut consent = match uow.consents().find(&subject, request.client_id()).await? {
                Some(mut existing) => {
                    existing.extend(&scope, now);
                    existing
                }
                None => Consent::grant(subject.clone(), request.client_id().clone(), scope, now),
            };
            uow.consents().upsert(&consent).await?;
            events.extend(consent_events(deps, ctx, &mut consent));
            request.approve(subject, now).map_err(not_found)?;
            let (mut code, location) = self.issue_code(&request, now)?;
            uow.authorization_requests().update(&request).await?;
            uow.authorization_codes().insert(&code).await?;
            events.extend(request_events(deps, ctx, &mut request));
            events.extend(code_events(deps, ctx, &mut code));
            location
        } else {
            request.deny(subject, now).map_err(not_found)?;
            uow.authorization_requests().update(&request).await?;
            events.extend(request_events(deps, ctx, &mut request));
            error_location(
                request.redirect_uri(),
                AuthorizeErrorCode::AccessDenied,
                "the resource owner denied the request",
                request.state(),
            )
        };
        append_all(uow.as_mut(), events).await?;
        uow.commit().await?;
        Ok(location)
    }

    /// Deletes the login session, if there is one.
    pub async fn logout(
        &self,
        ctx: &RequestContext,
        session: &OpaqueToken,
    ) -> Result<(), StoreError> {
        let deps = &self.deps;
        let id = session.hash();
        let mut uow = deps.store.begin().await?;
        let Some(found) = uow.login_sessions().find(&id).await? else {
            return Ok(());
        };
        uow.login_sessions().delete(&id).await?;
        let event = audit_event(
            deps,
            ctx,
            AuditKind::Logout,
            AuditOutcome::Success,
            AuditActor::User,
        )
        .subject(found.subject());
        append_all(uow.as_mut(), vec![event]).await?;
        uow.commit().await
    }

    /// The pending, unexpired request and its (active) client.
    async fn load_pending(
        &self,
        uow: &mut dyn UnitOfWork,
        request_id: AuthorizationRequestId,
        now: OffsetDateTime,
    ) -> Result<(AuthorizationRequest, Client), AuthorizeError> {
        let not_found = || non_redirectable(NonRedirectableError::RequestNotFound);
        let request = uow
            .authorization_requests()
            .find_for_update(request_id)
            .await?
            .filter(|r| r.status() == AuthorizationRequestStatus::Pending && !r.is_expired(now))
            .ok_or_else(not_found)?;
        let client = uow
            .clients()
            .find(request.client_id())
            .await?
            .filter(Client::is_active)
            .ok_or_else(not_found)?;
        Ok((request, client))
    }

    /// The subject of a valid login session of an active user.
    async fn session_subject(
        &self,
        uow: &mut dyn UnitOfWork,
        session: Option<&OpaqueToken>,
        now: OffsetDateTime,
    ) -> Result<Option<Subject>, StoreError> {
        let Some(session) = session else {
            return Ok(None);
        };
        let Some(found) = uow.login_sessions().find(&session.hash()).await? else {
            return Ok(None);
        };
        if !found.is_valid_at(now) {
            return Ok(None);
        }
        let subject = found.subject().clone();
        if !self.deps.authenticator.is_active(uow, &subject).await? {
            return Ok(None);
        }
        Ok(Some(subject))
    }

    /// Issues a code for an approved request and builds the redirect URI carrying it.
    fn issue_code(
        &self,
        request: &AuthorizationRequest,
        now: OffsetDateTime,
    ) -> Result<(AuthorizationCode, String), AuthorizeError> {
        let deps = &self.deps;
        let token = new_opaque_token(deps.random.as_ref());
        let code = AuthorizationCode::issue(
            token.hash(),
            request,
            now,
            deps.config.authorization_code_ttl,
        )
        .map_err(|e| AuthorizeError::Store(StoreError::Other(e.to_string())))?;
        let mut params = vec![("code", token.expose())];
        if let Some(state) = request.state() {
            params.push(("state", state.as_inner()));
        }
        let location = request.redirect_uri().with_query_params(&params);
        Ok((code, location))
    }

    /// Step 11 of `start`: decides login / consent / code issuance and commits.
    async fn proceed(
        &self,
        ctx: &RequestContext,
        mut uow: Box<dyn UnitOfWork>,
        client: &Client,
        mut request: AuthorizationRequest,
        subject: Option<Subject>,
        is_new: bool,
    ) -> Result<AuthorizeOutcome, AuthorizeError> {
        let deps = &self.deps;
        let now = deps.clock.now();
        let request_id = *request.id();
        let Some(subject) = subject else {
            if is_new {
                uow.authorization_requests().insert(&request).await?;
            }
            uow.commit().await?;
            return Ok(AuthorizeOutcome::LoginRequired { request_id });
        };
        let covered = match uow.consents().find(&subject, client.id()).await? {
            Some(consent) => consent.covers(request.scope()),
            None => false,
        };
        if client.skip_consent() || covered {
            request
                .approve(subject, now)
                .map_err(|_| non_redirectable(NonRedirectableError::RequestNotFound))?;
            let (mut code, location) = self.issue_code(&request, now)?;
            if is_new {
                uow.authorization_requests().insert(&request).await?;
            } else {
                uow.authorization_requests().update(&request).await?;
            }
            uow.authorization_codes().insert(&code).await?;
            let mut events = request_events(deps, ctx, &mut request);
            events.extend(code_events(deps, ctx, &mut code));
            append_all(uow.as_mut(), events).await?;
            uow.commit().await?;
            return Ok(AuthorizeOutcome::Redirect { location });
        }
        if is_new {
            uow.authorization_requests().insert(&request).await?;
            uow.commit().await?;
        }
        let scopes = request
            .scope()
            .iter()
            .map(|name| ScopeView {
                name: name.as_str().to_owned(),
                description: deps
                    .config
                    .scopes
                    .iter()
                    .find(|d| d.name == *name)
                    .map(|d| d.description.clone())
                    .unwrap_or_default(),
            })
            .collect();
        Ok(AuthorizeOutcome::ConsentRequired {
            request_id,
            prompt: ConsentPrompt {
                client_name: client.name().as_inner().to_string(),
                scopes,
            },
        })
    }
}
