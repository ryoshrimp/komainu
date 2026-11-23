//! Helpers shared by the use cases: audit event construction and the mapping from
//! domain events to audit events (see the audit table in the design document).

use std::collections::BTreeMap;

use komainu_domain::{
    AggregateRoot, AuthorizationCode, AuthorizationCodeEvent, AuthorizationRequest,
    AuthorizationRequestEvent, Client, ClientEvent, ClientId, Consent, ConsentEvent, Grant,
    GrantEvent, RefreshToken, RefreshTokenEvent, RevocationReason, Subject, User, UserEvent,
};

use crate::audit::{AuditActor, AuditEvent, AuditKind, AuditOutcome};
use crate::context::RequestContext;
use crate::deps::Dependencies;
use crate::ids::new_uuid_v7;
use crate::port::{StoreError, UnitOfWork};

/// Creates an audit event stamped with the current time and the request context.
pub(crate) fn audit_event(
    deps: &Dependencies,
    ctx: &RequestContext,
    kind: AuditKind,
    outcome: AuditOutcome,
    actor: AuditActor,
) -> AuditEvent {
    AuditEvent {
        id: new_uuid_v7(deps.clock.as_ref(), deps.random.as_ref()),
        occurred_at: deps.clock.now(),
        kind,
        outcome,
        actor,
        request_id: ctx.request_id.clone(),
        client_ip: ctx.client_ip,
        client_id: None,
        subject: None,
        details: BTreeMap::new(),
    }
}

/// Builder-style setters for [`AuditEvent`].
pub(crate) trait AuditEventExt: Sized {
    fn client(self, id: &ClientId) -> Self;
    fn subject(self, subject: &Subject) -> Self;
    fn detail(self, key: &'static str, value: impl Into<String>) -> Self;
}

impl AuditEventExt for AuditEvent {
    fn client(mut self, id: &ClientId) -> Self {
        self.client_id = Some(id.clone());
        self
    }

    fn subject(mut self, subject: &Subject) -> Self {
        self.subject = Some(subject.clone());
        self
    }

    fn detail(mut self, key: &'static str, value: impl Into<String>) -> Self {
        self.details.insert(key, value.into());
        self
    }
}

/// Appends the events in the unit of work.
pub(crate) async fn append_all(
    uow: &mut dyn UnitOfWork,
    events: Vec<AuditEvent>,
) -> Result<(), StoreError> {
    for event in &events {
        uow.audit_log().append(event).await?;
    }
    Ok(())
}

/// Truncates to at most `max` characters.
pub(crate) fn truncate_chars(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

fn reason_str(reason: RevocationReason) -> &'static str {
    match reason {
        RevocationReason::CodeReplay => "code_replay",
        RevocationReason::RefreshTokenReplay => "refresh_token_replay",
        RevocationReason::ClientDisabled => "client_disabled",
        RevocationReason::UserDisabled => "user_disabled",
        RevocationReason::ClientRequest => "client_request",
    }
}

pub(crate) fn client_events(
    deps: &Dependencies,
    ctx: &RequestContext,
    client: &mut Client,
) -> Vec<AuditEvent> {
    let client_type = client.client_type().as_str();
    client
        .pull_events()
        .into_iter()
        .map(|event| {
            let (kind, id) = match &event {
                ClientEvent::Registered { client_id, .. } => {
                    (AuditKind::ClientRegistered, client_id)
                }
                ClientEvent::Updated { client_id, .. } => (AuditKind::ClientUpdated, client_id),
                ClientEvent::SecretRotated { client_id, .. } => {
                    (AuditKind::ClientSecretRotated, client_id)
                }
                ClientEvent::Disabled { client_id, .. } => (AuditKind::ClientDisabled, client_id),
                ClientEvent::Enabled { client_id, .. } => (AuditKind::ClientEnabled, client_id),
            };
            let mut out =
                audit_event(deps, ctx, kind, AuditOutcome::Success, AuditActor::Admin).client(id);
            if matches!(event, ClientEvent::Registered { .. }) {
                out = out.detail("client_type", client_type);
            }
            out
        })
        .collect()
}

pub(crate) fn user_events(
    deps: &Dependencies,
    ctx: &RequestContext,
    user: &mut User,
) -> Vec<AuditEvent> {
    let username = user.username().as_str().to_owned();
    user.pull_events()
        .into_iter()
        .map(|event| {
            let (kind, id) = match &event {
                UserEvent::Created { user_id, .. } => (AuditKind::UserCreated, user_id),
                UserEvent::PasswordChanged { user_id, .. } => {
                    (AuditKind::UserPasswordChanged, user_id)
                }
                UserEvent::Disabled { user_id, .. } => (AuditKind::UserDisabled, user_id),
                UserEvent::Enabled { user_id, .. } => (AuditKind::UserEnabled, user_id),
            };
            let mut out = audit_event(deps, ctx, kind, AuditOutcome::Success, AuditActor::Admin)
                .subject(&Subject::from(*id));
            if matches!(event, UserEvent::Created { .. }) {
                out = out.detail("username", username.clone());
            }
            out
        })
        .collect()
}

/// Only `Revoked` is audited; `Created` is folded into `token.issued`.
pub(crate) fn grant_events(
    deps: &Dependencies,
    ctx: &RequestContext,
    grant: &mut Grant,
    actor: AuditActor,
) -> Vec<AuditEvent> {
    let client_id = grant.client_id().clone();
    let subject = grant.subject().cloned();
    grant
        .pull_events()
        .into_iter()
        .filter_map(|event| match event {
            GrantEvent::Revoked { grant_id, reason } => {
                let mut out = audit_event(
                    deps,
                    ctx,
                    AuditKind::GrantRevoked,
                    AuditOutcome::Success,
                    actor,
                )
                .client(&client_id)
                .detail("grant_id", grant_id.as_inner().to_string())
                .detail("reason", reason_str(reason));
                if let Some(subject) = &subject {
                    out = out.subject(subject);
                }
                Some(out)
            }
            GrantEvent::Created { .. } => None,
        })
        .collect()
}

pub(crate) fn request_events(
    deps: &Dependencies,
    ctx: &RequestContext,
    request: &mut AuthorizationRequest,
) -> Vec<AuditEvent> {
    request
        .pull_events()
        .into_iter()
        .map(|event| {
            let (kind, outcome, client_id, subject, scope) = match event {
                AuthorizationRequestEvent::Approved {
                    client_id,
                    subject,
                    scope,
                    ..
                } => (
                    AuditKind::AuthorizationApproved,
                    AuditOutcome::Success,
                    client_id,
                    subject,
                    scope,
                ),
                AuthorizationRequestEvent::Denied {
                    client_id,
                    subject,
                    scope,
                    ..
                } => (
                    AuditKind::AuthorizationDenied,
                    AuditOutcome::Failure,
                    client_id,
                    subject,
                    scope,
                ),
            };
            audit_event(deps, ctx, kind, outcome, AuditActor::User)
                .client(&client_id)
                .subject(&subject)
                .detail("scope", scope.to_string())
        })
        .collect()
}

/// `Issued` and `ReplayDetected` are audited; `Redeemed` is folded into `token.issued`.
pub(crate) fn code_events(
    deps: &Dependencies,
    ctx: &RequestContext,
    code: &mut AuthorizationCode,
) -> Vec<AuditEvent> {
    code.pull_events()
        .into_iter()
        .filter_map(|event| match event {
            AuthorizationCodeEvent::Issued {
                client_id, subject, ..
            } => Some(
                audit_event(
                    deps,
                    ctx,
                    AuditKind::AuthorizationCodeIssued,
                    AuditOutcome::Success,
                    AuditActor::User,
                )
                .client(&client_id)
                .subject(&subject),
            ),
            AuthorizationCodeEvent::ReplayDetected {
                client_id,
                subject,
                grant_id,
                ..
            } => Some(
                audit_event(
                    deps,
                    ctx,
                    AuditKind::AuthorizationCodeReplayDetected,
                    AuditOutcome::Failure,
                    AuditActor::Client,
                )
                .client(&client_id)
                .subject(&subject)
                .detail("grant_id", grant_id.as_inner().to_string()),
            ),
            AuthorizationCodeEvent::Redeemed { .. } => None,
        })
        .collect()
}

pub(crate) fn consent_events(
    deps: &Dependencies,
    ctx: &RequestContext,
    consent: &mut Consent,
) -> Vec<AuditEvent> {
    consent
        .pull_events()
        .into_iter()
        .map(|event| {
            let ConsentEvent::Granted {
                subject,
                client_id,
                scope,
                ..
            } = event;
            audit_event(
                deps,
                ctx,
                AuditKind::ConsentGranted,
                AuditOutcome::Success,
                AuditActor::User,
            )
            .client(&client_id)
            .subject(&subject)
            .detail("scope", scope.to_string())
        })
        .collect()
}

/// Only `ReplayDetected` is audited; `Issued` and `Rotated` are folded into `token.issued`.
pub(crate) fn refresh_events(
    deps: &Dependencies,
    ctx: &RequestContext,
    token: &mut RefreshToken,
) -> Vec<AuditEvent> {
    token
        .pull_events()
        .into_iter()
        .filter_map(|event| match event {
            RefreshTokenEvent::ReplayDetected {
                grant_id,
                client_id,
                ..
            } => Some(
                audit_event(
                    deps,
                    ctx,
                    AuditKind::RefreshTokenReplayDetected,
                    AuditOutcome::Failure,
                    AuditActor::Client,
                )
                .client(&client_id)
                .detail("grant_id", grant_id.as_inner().to_string()),
            ),
            RefreshTokenEvent::Issued { .. } | RefreshTokenEvent::Rotated { .. } => None,
        })
        .collect()
}

/// Splits `pairs` for the parameters in `names`. Empty values are absent; a name that
/// occurs more than once is reported in the second element. Unknown names are ignored.
pub(crate) fn collect_params<const N: usize>(
    pairs: impl IntoIterator<Item = (String, String)>,
    names: [&'static str; N],
) -> ([Option<String>; N], Vec<&'static str>) {
    let mut values: [Option<String>; N] = std::array::from_fn(|_| None);
    let mut seen = [0usize; N];
    for (key, value) in pairs {
        let Some(i) = names.iter().position(|n| *n == key) else {
            continue;
        };
        seen[i] += 1;
        if values[i].is_none() && !value.is_empty() {
            values[i] = Some(value);
        }
    }
    let duplicated = names
        .iter()
        .zip(seen)
        .filter(|(_, n)| *n > 1)
        .map(|(name, _)| *name)
        .collect();
    (values, duplicated)
}
