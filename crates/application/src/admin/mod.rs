//! Administration use cases for clients and users (used by the CLI).

mod error;
mod issuer;

use std::collections::BTreeSet;

use komainu_domain::{
    Client, ClientId, ClientKeys, ClientName, ClientType, ClientUpdate, GrantType, JwksDocument,
    NewClient, NewPassword, OpaqueToken, RedirectUri, RevocationReason, ScopeSet,
    TokenEndpointAuthMethod, User, UserId, Username,
};
use komainu_jose::JwkSet;
use time::OffsetDateTime;

pub use error::AdminError;
pub use issuer::{IssuerView, RegisterIssuer, SubjectMappingView};

use crate::audit::AuditActor;
use crate::context::RequestContext;
use crate::deps::Dependencies;
use crate::ids::{new_opaque_token, new_uuid_v7};
use crate::port::{ListPage, UnitOfWork};
use crate::support::{append_all, client_events, grant_events, user_events};

/// Input of [`AdminService::register_client`].
#[derive(Debug, Clone)]
pub struct RegisterClient {
    pub name: ClientName,
    pub client_type: ClientType,
    pub auth_method: TokenEndpointAuthMethod,
    pub redirect_uris: Vec<RedirectUri>,
    pub grant_types: BTreeSet<GrantType>,
    pub allowed_scopes: ScopeSet,
    pub default_scopes: ScopeSet,
    pub skip_consent: bool,
    /// Required for `private_key_jwt`, forbidden otherwise.
    pub keys: Option<ClientKeys>,
}

/// Read model of a client. Never contains the secret hash.
#[derive(Debug, Clone)]
pub struct ClientView {
    pub id: ClientId,
    pub name: ClientName,
    pub client_type: ClientType,
    pub auth_method: TokenEndpointAuthMethod,
    pub redirect_uris: Vec<RedirectUri>,
    pub grant_types: BTreeSet<GrantType>,
    pub allowed_scopes: ScopeSet,
    pub default_scopes: ScopeSet,
    pub skip_consent: bool,
    pub keys: Option<ClientKeys>,
    pub active: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl ClientView {
    fn of(client: &Client) -> Self {
        Self {
            id: client.id().clone(),
            name: client.name().clone(),
            client_type: client.client_type(),
            auth_method: client.auth_method(),
            redirect_uris: client.redirect_uris().to_vec(),
            grant_types: client.grant_types().clone(),
            allowed_scopes: client.allowed_scopes().clone(),
            default_scopes: client.default_scopes().clone(),
            skip_consent: client.skip_consent(),
            keys: client.keys().cloned(),
            active: client.is_active(),
            created_at: client.created_at(),
            updated_at: client.updated_at(),
        }
    }
}

/// Result of [`AdminService::register_client`].
#[derive(Debug)]
pub struct RegisteredClient {
    pub client: ClientView,
    /// Some for confidential clients. Shown once; only the hash is stored.
    pub secret: Option<OpaqueToken>,
}

/// Read model of a user. Never contains the password hash.
#[derive(Debug, Clone)]
pub struct UserView {
    pub id: UserId,
    pub username: Username,
    pub active: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl UserView {
    fn of(user: &User) -> Self {
        Self {
            id: *user.id(),
            username: user.username().clone(),
            active: user.is_active(),
            created_at: user.created_at(),
            updated_at: user.updated_at(),
        }
    }
}

/// Client and user administration. Every audit event has actor `admin`.
#[derive(Clone)]
pub struct AdminService {
    deps: Dependencies,
}

impl AdminService {
    pub fn new(deps: Dependencies) -> Self {
        Self { deps }
    }

    fn check_scopes(&self, scopes: &ScopeSet) -> Result<(), AdminError> {
        for scope in scopes.iter() {
            if !self.deps.config.scopes.iter().any(|d| d.name == *scope) {
                return Err(AdminError::UnknownScope(scope.as_str().to_owned()));
            }
        }
        Ok(())
    }

    /// A `jwks` document must hold 1 to 10 usable public keys. `jwks_uri` is not fetched here.
    fn check_keys(&self, keys: Option<&ClientKeys>) -> Result<(), AdminError> {
        match keys {
            Some(ClientKeys::Jwks(doc)) => Self::check_jwks(doc)?,
            // Without a fetcher such a client could never authenticate.
            Some(ClientKeys::JwksUri(_)) if !self.deps.jwks.has_fetcher() => {
                return Err(AdminError::InvalidJwks(
                    "jwks_uri needs a JWKS fetcher, and none is configured".to_owned(),
                ));
            }
            _ => {}
        }
        Ok(())
    }

    fn check_jwks(doc: &JwksDocument) -> Result<(), AdminError> {
        let set =
            JwkSet::from_json(doc.as_str()).map_err(|e| AdminError::InvalidJwks(e.to_string()))?;
        let count = set.keys().len();
        if !(1..=10).contains(&count) {
            return Err(AdminError::InvalidJwks(format!(
                "expected 1 to 10 usable keys, found {count}"
            )));
        }
        Ok(())
    }

    async fn load_client(uow: &mut dyn UnitOfWork, id: &ClientId) -> Result<Client, AdminError> {
        uow.clients()
            .find_for_update(id)
            .await?
            .ok_or(AdminError::NotFound)
    }

    async fn load_user(uow: &mut dyn UnitOfWork, username: &Username) -> Result<User, AdminError> {
        let found = uow
            .users()
            .find_by_username(username)
            .await?
            .ok_or(AdminError::NotFound)?;
        uow.users()
            .find_for_update(*found.id())
            .await?
            .ok_or(AdminError::NotFound)
    }

    /// Registers a client. Confidential clients get a generated secret, returned once.
    pub async fn register_client(
        &self,
        ctx: &RequestContext,
        input: RegisterClient,
    ) -> Result<RegisteredClient, AdminError> {
        let deps = &self.deps;
        if input.client_type == ClientType::Public && !deps.config.allow_public_clients {
            return Err(AdminError::PublicClientsDisabled);
        }
        self.check_scopes(&input.allowed_scopes)?;
        self.check_keys(input.keys.as_ref())?;
        let secret = matches!(
            input.auth_method,
            TokenEndpointAuthMethod::ClientSecretBasic | TokenEndpointAuthMethod::ClientSecretPost
        )
        .then(|| new_opaque_token(deps.random.as_ref()));
        let id =
            ClientId::try_new(new_uuid_v7(deps.clock.as_ref(), deps.random.as_ref()).to_string())?;
        let mut client = Client::register(
            NewClient {
                id,
                name: input.name,
                client_type: input.client_type,
                auth_method: input.auth_method,
                redirect_uris: input.redirect_uris,
                grant_types: input.grant_types,
                allowed_scopes: input.allowed_scopes,
                default_scopes: input.default_scopes,
                skip_consent: input.skip_consent,
                keys: input.keys,
            },
            secret.as_ref().map(OpaqueToken::hash),
            deps.clock.now(),
        )?;
        let mut uow = deps.store.begin().await?;
        uow.clients().insert(&client).await?;
        append_all(uow.as_mut(), client_events(deps, ctx, &mut client)).await?;
        uow.commit().await?;
        Ok(RegisteredClient {
            client: ClientView::of(&client),
            secret,
        })
    }

    pub async fn update_client(
        &self,
        ctx: &RequestContext,
        id: &ClientId,
        update: ClientUpdate,
    ) -> Result<ClientView, AdminError> {
        let deps = &self.deps;
        if let Some(scopes) = &update.allowed_scopes {
            self.check_scopes(scopes)?;
        }
        self.check_keys(update.keys.as_ref())?;
        let mut uow = deps.store.begin().await?;
        let mut client = Self::load_client(uow.as_mut(), id).await?;
        client.update(update, deps.clock.now())?;
        uow.clients().update(&client).await?;
        append_all(uow.as_mut(), client_events(deps, ctx, &mut client)).await?;
        uow.commit().await?;
        Ok(ClientView::of(&client))
    }

    /// Replaces the secret. Returns the new secret, shown once.
    pub async fn rotate_client_secret(
        &self,
        ctx: &RequestContext,
        id: &ClientId,
    ) -> Result<OpaqueToken, AdminError> {
        let deps = &self.deps;
        let secret = new_opaque_token(deps.random.as_ref());
        let mut uow = deps.store.begin().await?;
        let mut client = Self::load_client(uow.as_mut(), id).await?;
        client.rotate_secret(secret.hash(), deps.clock.now())?;
        uow.clients().update(&client).await?;
        append_all(uow.as_mut(), client_events(deps, ctx, &mut client)).await?;
        uow.commit().await?;
        Ok(secret)
    }

    /// Disables the client and revokes all its active grants (reason `ClientDisabled`).
    pub async fn disable_client(
        &self,
        ctx: &RequestContext,
        id: &ClientId,
    ) -> Result<ClientView, AdminError> {
        let deps = &self.deps;
        let now = deps.clock.now();
        let mut uow = deps.store.begin().await?;
        let mut client = Self::load_client(uow.as_mut(), id).await?;
        client.disable(now);
        uow.clients().update(&client).await?;
        let mut events = client_events(deps, ctx, &mut client);
        for mut grant in uow.grants().list_active_by_client(id).await? {
            grant.revoke(RevocationReason::ClientDisabled, now);
            uow.grants().update(&grant).await?;
            events.extend(grant_events(deps, ctx, &mut grant, AuditActor::Admin));
        }
        append_all(uow.as_mut(), events).await?;
        uow.commit().await?;
        Ok(ClientView::of(&client))
    }

    pub async fn enable_client(
        &self,
        ctx: &RequestContext,
        id: &ClientId,
    ) -> Result<ClientView, AdminError> {
        let deps = &self.deps;
        let mut uow = deps.store.begin().await?;
        let mut client = Self::load_client(uow.as_mut(), id).await?;
        client.enable(deps.clock.now());
        uow.clients().update(&client).await?;
        append_all(uow.as_mut(), client_events(deps, ctx, &mut client)).await?;
        uow.commit().await?;
        Ok(ClientView::of(&client))
    }

    pub async fn get_client(
        &self,
        _ctx: &RequestContext,
        id: &ClientId,
    ) -> Result<ClientView, AdminError> {
        let mut uow = self.deps.store.begin().await?;
        let client = uow.clients().find(id).await?.ok_or(AdminError::NotFound)?;
        Ok(ClientView::of(&client))
    }

    pub async fn list_clients(
        &self,
        _ctx: &RequestContext,
        page: ListPage<ClientId>,
    ) -> Result<Vec<ClientView>, AdminError> {
        let page = ListPage {
            limit: page.limit.clamp(1, 1000),
            ..page
        };
        let mut uow = self.deps.store.begin().await?;
        let clients = uow.clients().list(&page).await?;
        Ok(clients.iter().map(ClientView::of).collect())
    }

    pub async fn create_user(
        &self,
        ctx: &RequestContext,
        username: Username,
        password: NewPassword,
    ) -> Result<UserView, AdminError> {
        let deps = &self.deps;
        let hash = deps
            .password_hasher
            .hash(password.as_password())
            .await
            .map_err(AdminError::PasswordHash)?;
        let id = UserId::new(new_uuid_v7(deps.clock.as_ref(), deps.random.as_ref()));
        let mut uow = deps.store.begin().await?;
        if uow.users().find_by_username(&username).await?.is_some() {
            return Err(AdminError::Conflict);
        }
        let mut user = User::create(id, username, hash, deps.clock.now());
        uow.users().insert(&user).await?;
        append_all(uow.as_mut(), user_events(deps, ctx, &mut user)).await?;
        uow.commit().await?;
        Ok(UserView::of(&user))
    }

    /// Does not revoke existing login sessions or grants.
    pub async fn set_user_password(
        &self,
        ctx: &RequestContext,
        username: &Username,
        password: NewPassword,
    ) -> Result<UserView, AdminError> {
        let deps = &self.deps;
        let hash = deps
            .password_hasher
            .hash(password.as_password())
            .await
            .map_err(AdminError::PasswordHash)?;
        let mut uow = deps.store.begin().await?;
        let mut user = Self::load_user(uow.as_mut(), username).await?;
        user.change_password(hash, deps.clock.now());
        uow.users().update(&user).await?;
        append_all(uow.as_mut(), user_events(deps, ctx, &mut user)).await?;
        uow.commit().await?;
        Ok(UserView::of(&user))
    }

    /// Disables the user, revokes their grants (reason `UserDisabled`) and deletes their
    /// login sessions.
    pub async fn disable_user(
        &self,
        ctx: &RequestContext,
        username: &Username,
    ) -> Result<UserView, AdminError> {
        let deps = &self.deps;
        let now = deps.clock.now();
        let mut uow = deps.store.begin().await?;
        let mut user = Self::load_user(uow.as_mut(), username).await?;
        user.disable(now);
        uow.users().update(&user).await?;
        let subject = user.subject();
        let mut events = user_events(deps, ctx, &mut user);
        for mut grant in uow.grants().list_active_by_subject(&subject).await? {
            grant.revoke(RevocationReason::UserDisabled, now);
            uow.grants().update(&grant).await?;
            events.extend(grant_events(deps, ctx, &mut grant, AuditActor::Admin));
        }
        uow.login_sessions().delete_by_subject(&subject).await?;
        append_all(uow.as_mut(), events).await?;
        uow.commit().await?;
        Ok(UserView::of(&user))
    }

    pub async fn enable_user(
        &self,
        ctx: &RequestContext,
        username: &Username,
    ) -> Result<UserView, AdminError> {
        let deps = &self.deps;
        let mut uow = deps.store.begin().await?;
        let mut user = Self::load_user(uow.as_mut(), username).await?;
        user.enable(deps.clock.now());
        uow.users().update(&user).await?;
        append_all(uow.as_mut(), user_events(deps, ctx, &mut user)).await?;
        uow.commit().await?;
        Ok(UserView::of(&user))
    }

    pub async fn get_user(
        &self,
        _ctx: &RequestContext,
        username: &Username,
    ) -> Result<UserView, AdminError> {
        let mut uow = self.deps.store.begin().await?;
        let user = uow
            .users()
            .find_by_username(username)
            .await?
            .ok_or(AdminError::NotFound)?;
        Ok(UserView::of(&user))
    }

    pub async fn list_users(
        &self,
        _ctx: &RequestContext,
        page: ListPage<Username>,
    ) -> Result<Vec<UserView>, AdminError> {
        let page = ListPage {
            limit: page.limit.clamp(1, 1000),
            ..page
        };
        let mut uow = self.deps.store.begin().await?;
        let users = uow.users().list(&page).await?;
        Ok(users.iter().map(UserView::of).collect())
    }
}
