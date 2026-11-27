//! Administration of trusted external issuers and their subject mappings.

use std::collections::BTreeSet;

use komainu_domain::{
    ClientId, ExternalSubject, IssuerId, IssuerStatus, JwksDocument, NewTrustedIssuer,
    SubjectMapping, TrustedIssuer, TrustedIssuerUpdate, UserId, Username,
};
use time::OffsetDateTime;

use super::{AdminError, AdminService};
use crate::audit::{AuditActor, AuditKind, AuditOutcome};
use crate::context::RequestContext;
use crate::port::{ListPage, UnitOfWork};
use crate::support::{AuditEventExt, append_all, audit_event, issuer_events, truncate_chars};

/// Input of [`AdminService::register_issuer`].
#[derive(Debug, Clone)]
pub struct RegisterIssuer {
    pub id: IssuerId,
    pub jwks: JwksDocument,
    pub allowed_clients: BTreeSet<ClientId>,
}

/// Read model of a trusted issuer.
#[derive(Debug, Clone)]
pub struct IssuerView {
    pub id: IssuerId,
    pub jwks: JwksDocument,
    pub allowed_clients: BTreeSet<ClientId>,
    pub status: IssuerStatus,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl IssuerView {
    fn of(issuer: &TrustedIssuer) -> Self {
        Self {
            id: issuer.id().clone(),
            jwks: issuer.jwks().clone(),
            allowed_clients: issuer.allowed_clients().clone(),
            status: issuer.status(),
            created_at: issuer.created_at(),
            updated_at: issuer.updated_at(),
        }
    }
}

/// Read model of a subject mapping, with the mapped user's name.
#[derive(Debug, Clone)]
pub struct SubjectMappingView {
    pub issuer_id: IssuerId,
    pub subject: ExternalSubject,
    pub user_id: UserId,
    pub username: Username,
    pub updated_at: OffsetDateTime,
}

impl AdminService {
    async fn load_issuer(
        uow: &mut dyn UnitOfWork,
        id: &IssuerId,
    ) -> Result<TrustedIssuer, AdminError> {
        uow.trusted_issuers()
            .find_for_update(id)
            .await?
            .ok_or(AdminError::NotFound)
    }

    /// Every client of `allowed` must exist (the first missing one is reported).
    async fn check_allowed_clients(
        uow: &mut dyn UnitOfWork,
        allowed: &BTreeSet<ClientId>,
    ) -> Result<(), AdminError> {
        for id in allowed {
            if uow.clients().find(id).await?.is_none() {
                return Err(AdminError::UnknownClient(id.clone()));
            }
        }
        Ok(())
    }

    pub async fn register_issuer(
        &self,
        ctx: &RequestContext,
        input: RegisterIssuer,
    ) -> Result<IssuerView, AdminError> {
        let deps = &self.deps;
        let mut issuer = TrustedIssuer::register(
            NewTrustedIssuer {
                id: input.id,
                jwks: input.jwks,
                allowed_clients: input.allowed_clients,
            },
            deps.clock.now(),
        )?;
        Self::check_jwks(issuer.jwks())?;
        let mut uow = deps.store.begin().await?;
        Self::check_allowed_clients(uow.as_mut(), issuer.allowed_clients()).await?;
        uow.trusted_issuers().insert(&issuer).await?;
        append_all(uow.as_mut(), issuer_events(deps, ctx, &mut issuer)).await?;
        uow.commit().await?;
        Ok(IssuerView::of(&issuer))
    }

    pub async fn update_issuer(
        &self,
        ctx: &RequestContext,
        id: &IssuerId,
        update: TrustedIssuerUpdate,
    ) -> Result<IssuerView, AdminError> {
        let deps = &self.deps;
        let mut uow = deps.store.begin().await?;
        let mut issuer = Self::load_issuer(uow.as_mut(), id).await?;
        let allowed = update.allowed_clients.clone();
        let doc = update.jwks.clone();
        issuer.update(update, deps.clock.now())?;
        if let Some(doc) = &doc {
            Self::check_jwks(doc)?;
        }
        if let Some(allowed) = &allowed {
            Self::check_allowed_clients(uow.as_mut(), allowed).await?;
        }
        uow.trusted_issuers().update(&issuer).await?;
        append_all(uow.as_mut(), issuer_events(deps, ctx, &mut issuer)).await?;
        uow.commit().await?;
        Ok(IssuerView::of(&issuer))
    }

    pub async fn disable_issuer(
        &self,
        ctx: &RequestContext,
        id: &IssuerId,
    ) -> Result<IssuerView, AdminError> {
        let deps = &self.deps;
        let mut uow = deps.store.begin().await?;
        let mut issuer = Self::load_issuer(uow.as_mut(), id).await?;
        issuer.disable(deps.clock.now());
        uow.trusted_issuers().update(&issuer).await?;
        append_all(uow.as_mut(), issuer_events(deps, ctx, &mut issuer)).await?;
        uow.commit().await?;
        Ok(IssuerView::of(&issuer))
    }

    pub async fn enable_issuer(
        &self,
        ctx: &RequestContext,
        id: &IssuerId,
    ) -> Result<IssuerView, AdminError> {
        let deps = &self.deps;
        let mut uow = deps.store.begin().await?;
        let mut issuer = Self::load_issuer(uow.as_mut(), id).await?;
        issuer.enable(deps.clock.now());
        uow.trusted_issuers().update(&issuer).await?;
        append_all(uow.as_mut(), issuer_events(deps, ctx, &mut issuer)).await?;
        uow.commit().await?;
        Ok(IssuerView::of(&issuer))
    }

    pub async fn get_issuer(
        &self,
        _ctx: &RequestContext,
        id: &IssuerId,
    ) -> Result<IssuerView, AdminError> {
        let mut uow = self.deps.store.begin().await?;
        let issuer = uow
            .trusted_issuers()
            .find(id)
            .await?
            .ok_or(AdminError::NotFound)?;
        Ok(IssuerView::of(&issuer))
    }

    pub async fn list_issuers(
        &self,
        _ctx: &RequestContext,
        page: ListPage<IssuerId>,
    ) -> Result<Vec<IssuerView>, AdminError> {
        let page = ListPage {
            limit: page.limit.clamp(1, 1000),
            ..page
        };
        let mut uow = self.deps.store.begin().await?;
        let issuers = uow.trusted_issuers().list(&page).await?;
        Ok(issuers.iter().map(IssuerView::of).collect())
    }

    /// Maps `subject` of the issuer to a local user, overwriting an existing mapping.
    /// A disabled user may be mapped (the grant rejects it later).
    pub async fn map_subject(
        &self,
        ctx: &RequestContext,
        issuer: &IssuerId,
        subject: ExternalSubject,
        username: &Username,
    ) -> Result<SubjectMappingView, AdminError> {
        let deps = &self.deps;
        let mut uow = deps.store.begin().await?;
        uow.trusted_issuers()
            .find(issuer)
            .await?
            .ok_or(AdminError::NotFound)?;
        let user = uow
            .users()
            .find_by_username(username)
            .await?
            .ok_or(AdminError::NotFound)?;
        let mapping = SubjectMapping {
            issuer_id: issuer.clone(),
            subject,
            user_id: *user.id(),
            updated_at: deps.clock.now(),
        };
        uow.subject_mappings().upsert(&mapping).await?;
        let event = audit_event(
            deps,
            ctx,
            AuditKind::SubjectMapped,
            AuditOutcome::Success,
            AuditActor::Admin,
        )
        .detail("issuer", issuer.as_inner())
        .detail("subject", truncate_chars(mapping.subject.as_inner(), 64))
        .detail("user_id", mapping.user_id.as_inner().to_string());
        append_all(uow.as_mut(), vec![event]).await?;
        uow.commit().await?;
        Ok(SubjectMappingView {
            issuer_id: mapping.issuer_id,
            subject: mapping.subject,
            user_id: mapping.user_id,
            username: user.username().clone(),
            updated_at: mapping.updated_at,
        })
    }

    pub async fn unmap_subject(
        &self,
        ctx: &RequestContext,
        issuer: &IssuerId,
        subject: &ExternalSubject,
    ) -> Result<(), AdminError> {
        let deps = &self.deps;
        let mut uow = deps.store.begin().await?;
        if !uow.subject_mappings().delete(issuer, subject).await? {
            return Err(AdminError::NotFound);
        }
        let event = audit_event(
            deps,
            ctx,
            AuditKind::SubjectUnmapped,
            AuditOutcome::Success,
            AuditActor::Admin,
        )
        .detail("issuer", issuer.as_inner())
        .detail("subject", truncate_chars(subject.as_inner(), 64));
        append_all(uow.as_mut(), vec![event]).await?;
        uow.commit().await?;
        Ok(())
    }

    pub async fn list_subject_mappings(
        &self,
        _ctx: &RequestContext,
        issuer: &IssuerId,
        page: ListPage<ExternalSubject>,
    ) -> Result<Vec<SubjectMappingView>, AdminError> {
        let page = ListPage {
            limit: page.limit.clamp(1, 1000),
            ..page
        };
        let mut uow = self.deps.store.begin().await?;
        let mappings = uow.subject_mappings().list_by_issuer(issuer, &page).await?;
        let mut views = Vec::with_capacity(mappings.len());
        for mapping in mappings {
            // A mapped user is never deleted (users are only disabled), so this is a store
            // inconsistency if it is missing.
            let user = uow
                .users()
                .find(mapping.user_id)
                .await?
                .ok_or(AdminError::NotFound)?;
            views.push(SubjectMappingView {
                issuer_id: mapping.issuer_id,
                subject: mapping.subject,
                user_id: mapping.user_id,
                username: user.username().clone(),
                updated_at: mapping.updated_at,
            });
        }
        Ok(views)
    }
}
