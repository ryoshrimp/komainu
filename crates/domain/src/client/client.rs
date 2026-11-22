use std::collections::BTreeSet;
use std::str::FromStr;

use ddd_toolkit::{AggregateRoot, Entity};
use time::OffsetDateTime;

use super::event::ClientEvent;
use crate::error::DomainError;
use crate::{ClientId, ClientName, OpaqueToken, RedirectUri, ScopeSet, TokenHash};

/// Whether the client can keep a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ClientType {
    Confidential,
    Public,
}

impl ClientType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Confidential => "confidential",
            Self::Public => "public",
        }
    }
}

impl FromStr for ClientType {
    type Err = DomainError;
    fn from_str(s: &str) -> Result<Self, DomainError> {
        match s {
            "confidential" => Ok(Self::Confidential),
            "public" => Ok(Self::Public),
            _ => Err(DomainError::invalid("client_type", "unknown value")),
        }
    }
}

/// How the client authenticates at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TokenEndpointAuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
    None,
}

impl TokenEndpointAuthMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::None => "none",
        }
    }
}

impl FromStr for TokenEndpointAuthMethod {
    type Err = DomainError;
    fn from_str(s: &str) -> Result<Self, DomainError> {
        match s {
            "client_secret_basic" => Ok(Self::ClientSecretBasic),
            "client_secret_post" => Ok(Self::ClientSecretPost),
            "none" => Ok(Self::None),
            _ => Err(DomainError::invalid(
                "token_endpoint_auth_method",
                "unknown value",
            )),
        }
    }
}

/// A grant type the client may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GrantType {
    AuthorizationCode,
    ClientCredentials,
    RefreshToken,
}

impl GrantType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::ClientCredentials => "client_credentials",
            Self::RefreshToken => "refresh_token",
        }
    }
}

impl FromStr for GrantType {
    type Err = DomainError;
    fn from_str(s: &str) -> Result<Self, DomainError> {
        match s {
            "authorization_code" => Ok(Self::AuthorizationCode),
            "client_credentials" => Ok(Self::ClientCredentials),
            "refresh_token" => Ok(Self::RefreshToken),
            _ => Err(DomainError::invalid("grant_type", "unknown value")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ClientStatus {
    Active,
    Disabled,
}

impl ClientStatus {
    /// The string stored in databases and exchanged in wire formats.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
}

impl FromStr for ClientStatus {
    type Err = DomainError;
    fn from_str(s: &str) -> Result<Self, DomainError> {
        match s {
            "active" => Ok(Self::Active),
            "disabled" => Ok(Self::Disabled),
            _ => Err(DomainError::invalid("client_status", "unknown value")),
        }
    }
}

/// Input of [`Client::register`].
#[derive(Debug, Clone)]
pub struct NewClient {
    pub id: ClientId,
    pub name: ClientName,
    pub client_type: ClientType,
    pub auth_method: TokenEndpointAuthMethod,
    pub redirect_uris: Vec<RedirectUri>,
    pub grant_types: BTreeSet<GrantType>,
    pub allowed_scopes: ScopeSet,
    pub default_scopes: ScopeSet,
    pub skip_consent: bool,
}

/// Input of [`Client::update`]. `None` means "leave unchanged".
#[derive(Debug, Clone, Default)]
pub struct ClientUpdate {
    pub name: Option<ClientName>,
    pub redirect_uris: Option<Vec<RedirectUri>>,
    pub grant_types: Option<BTreeSet<GrantType>>,
    pub allowed_scopes: Option<ScopeSet>,
    pub default_scopes: Option<ScopeSet>,
    pub skip_consent: Option<bool>,
    pub auth_method: Option<TokenEndpointAuthMethod>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectUriError {
    NotRegistered,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeError {
    NotAllowed,
    NoDefault,
}

/// A registered OAuth 2.0 client.
#[derive(Debug, Entity, AggregateRoot)]
pub struct Client {
    #[entity(id)]
    id: ClientId,
    name: ClientName,
    client_type: ClientType,
    auth_method: TokenEndpointAuthMethod,
    secret_hash: Option<TokenHash>,
    redirect_uris: Vec<RedirectUri>,
    grant_types: BTreeSet<GrantType>,
    allowed_scopes: ScopeSet,
    default_scopes: ScopeSet,
    skip_consent: bool,
    status: ClientStatus,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    #[aggregate(events)]
    events: Vec<ClientEvent>,
}

/// Persistence form of [`Client`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRecord {
    pub id: ClientId,
    pub name: ClientName,
    pub client_type: ClientType,
    pub auth_method: TokenEndpointAuthMethod,
    pub secret_hash: Option<TokenHash>,
    pub redirect_uris: Vec<RedirectUri>,
    pub grant_types: BTreeSet<GrantType>,
    pub allowed_scopes: ScopeSet,
    pub default_scopes: ScopeSet,
    pub skip_consent: bool,
    pub status: ClientStatus,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Client {
    pub fn register(
        new: NewClient,
        secret_hash: Option<TokenHash>,
        now: OffsetDateTime,
    ) -> Result<Client, DomainError> {
        let mut client = Client {
            id: new.id,
            name: new.name,
            client_type: new.client_type,
            auth_method: new.auth_method,
            secret_hash,
            redirect_uris: new.redirect_uris,
            grant_types: new.grant_types,
            allowed_scopes: new.allowed_scopes,
            default_scopes: new.default_scopes,
            skip_consent: new.skip_consent,
            status: ClientStatus::Active,
            created_at: now,
            updated_at: now,
            events: Vec::new(),
        };
        client.check_invariants()?;
        let client_id = client.id.clone();
        client.record_event(ClientEvent::Registered {
            client_id,
            occurred_at: now,
        });
        Ok(client)
    }

    pub fn update(&mut self, update: ClientUpdate, now: OffsetDateTime) -> Result<(), DomainError> {
        let mut next = Client {
            id: self.id.clone(),
            name: update.name.unwrap_or_else(|| self.name.clone()),
            client_type: self.client_type,
            auth_method: update.auth_method.unwrap_or(self.auth_method),
            secret_hash: self.secret_hash,
            redirect_uris: update
                .redirect_uris
                .unwrap_or_else(|| self.redirect_uris.clone()),
            grant_types: update
                .grant_types
                .unwrap_or_else(|| self.grant_types.clone()),
            allowed_scopes: update
                .allowed_scopes
                .unwrap_or_else(|| self.allowed_scopes.clone()),
            default_scopes: update
                .default_scopes
                .unwrap_or_else(|| self.default_scopes.clone()),
            skip_consent: update.skip_consent.unwrap_or(self.skip_consent),
            status: self.status,
            created_at: self.created_at,
            updated_at: now,
            events: Vec::new(),
        };
        next.check_invariants()?;
        // Keep the queued events; only the validated fields replace the current ones.
        next.events = std::mem::take(&mut self.events);
        *self = next;
        let client_id = self.id.clone();
        self.record_event(ClientEvent::Updated {
            client_id,
            occurred_at: now,
        });
        Ok(())
    }

    pub fn rotate_secret(
        &mut self,
        new_hash: TokenHash,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        if self.client_type == ClientType::Public {
            return Err(DomainError::InvalidState("public clients have no secret"));
        }
        self.secret_hash = Some(new_hash);
        self.updated_at = now;
        let client_id = self.id.clone();
        self.record_event(ClientEvent::SecretRotated {
            client_id,
            occurred_at: now,
        });
        Ok(())
    }

    pub fn disable(&mut self, now: OffsetDateTime) {
        if self.status == ClientStatus::Disabled {
            return;
        }
        self.status = ClientStatus::Disabled;
        self.updated_at = now;
        let client_id = self.id.clone();
        self.record_event(ClientEvent::Disabled {
            client_id,
            occurred_at: now,
        });
    }

    pub fn enable(&mut self, now: OffsetDateTime) {
        if self.status == ClientStatus::Active {
            return;
        }
        self.status = ClientStatus::Active;
        self.updated_at = now;
        let client_id = self.id.clone();
        self.record_event(ClientEvent::Enabled {
            client_id,
            occurred_at: now,
        });
    }

    pub fn name(&self) -> &ClientName {
        &self.name
    }

    pub fn client_type(&self) -> ClientType {
        self.client_type
    }

    pub fn auth_method(&self) -> TokenEndpointAuthMethod {
        self.auth_method
    }

    pub fn is_active(&self) -> bool {
        self.status == ClientStatus::Active
    }

    pub fn skip_consent(&self) -> bool {
        self.skip_consent
    }

    pub fn supports_grant(&self, grant: GrantType) -> bool {
        self.grant_types.contains(&grant)
    }

    pub fn redirect_uris(&self) -> &[RedirectUri] {
        &self.redirect_uris
    }

    pub fn grant_types(&self) -> &BTreeSet<GrantType> {
        &self.grant_types
    }

    pub fn allowed_scopes(&self) -> &ScopeSet {
        &self.allowed_scopes
    }

    pub fn default_scopes(&self) -> &ScopeSet {
        &self.default_scopes
    }

    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Constant-time. Always false for public clients.
    pub fn verify_secret(&self, presented: &OpaqueToken) -> bool {
        match (self.client_type, &self.secret_hash) {
            (ClientType::Confidential, Some(hash)) => hash.ct_eq(&presented.hash()),
            _ => false,
        }
    }

    /// §3.1.2.3: requested must exactly match a registered URI;
    /// when omitted, succeeds only if exactly one URI is registered.
    pub fn resolve_redirect_uri(
        &self,
        requested: Option<&RedirectUri>,
    ) -> Result<RedirectUri, RedirectUriError> {
        match requested {
            Some(uri) => self
                .redirect_uris
                .iter()
                .find(|registered| *registered == uri)
                .cloned()
                .ok_or(RedirectUriError::NotRegistered),
            None => match self.redirect_uris.as_slice() {
                [only] => Ok(only.clone()),
                _ => Err(RedirectUriError::Missing),
            },
        }
    }

    /// §3.3: None -> default_scopes (error if empty); Some -> must be a subset of allowed_scopes.
    pub fn resolve_scope(&self, requested: Option<&ScopeSet>) -> Result<ScopeSet, ScopeError> {
        match requested {
            None if self.default_scopes.is_empty() => Err(ScopeError::NoDefault),
            None => Ok(self.default_scopes.clone()),
            Some(scope) if scope.is_subset(&self.allowed_scopes) => Ok(scope.clone()),
            Some(_) => Err(ScopeError::NotAllowed),
        }
    }

    pub fn to_record(&self) -> ClientRecord {
        ClientRecord {
            id: self.id.clone(),
            name: self.name.clone(),
            client_type: self.client_type,
            auth_method: self.auth_method,
            secret_hash: self.secret_hash,
            redirect_uris: self.redirect_uris.clone(),
            grant_types: self.grant_types.clone(),
            allowed_scopes: self.allowed_scopes.clone(),
            default_scopes: self.default_scopes.clone(),
            skip_consent: self.skip_consent,
            status: self.status,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }

    /// Restores a client from storage. Queues no events and does not validate.
    pub fn from_record(record: ClientRecord) -> Self {
        Client {
            id: record.id,
            name: record.name,
            client_type: record.client_type,
            auth_method: record.auth_method,
            secret_hash: record.secret_hash,
            redirect_uris: record.redirect_uris,
            grant_types: record.grant_types,
            allowed_scopes: record.allowed_scopes,
            default_scopes: record.default_scopes,
            skip_consent: record.skip_consent,
            status: record.status,
            created_at: record.created_at,
            updated_at: record.updated_at,
            events: Vec::new(),
        }
    }

    fn check_invariants(&self) -> Result<(), DomainError> {
        let violation = DomainError::ClientInvariant;
        if self.grant_types.is_empty() {
            return Err(violation("grant_types must not be empty"));
        }
        match self.client_type {
            ClientType::Confidential => {
                if self.secret_hash.is_none() {
                    return Err(violation("confidential client requires a secret"));
                }
                if self.auth_method == TokenEndpointAuthMethod::None {
                    return Err(violation("confidential client must authenticate"));
                }
            }
            ClientType::Public => {
                if self.secret_hash.is_some() {
                    return Err(violation("public client must not have a secret"));
                }
                if self.auth_method != TokenEndpointAuthMethod::None {
                    return Err(violation("public client must use auth method none"));
                }
                if self.supports_grant(GrantType::ClientCredentials) {
                    return Err(violation("public client cannot use client_credentials"));
                }
            }
        }
        if self.supports_grant(GrantType::AuthorizationCode) {
            let n = self.redirect_uris.len();
            if !(1..=10).contains(&n) {
                return Err(violation("redirect_uris must contain 1 to 10 entries"));
            }
            let unique: BTreeSet<&str> =
                self.redirect_uris.iter().map(RedirectUri::as_str).collect();
            if unique.len() != n {
                return Err(violation("redirect_uris must not contain duplicates"));
            }
        } else if !self.redirect_uris.is_empty() {
            return Err(violation(
                "redirect_uris requires the authorization_code grant",
            ));
        }
        if self.supports_grant(GrantType::RefreshToken)
            && !self.supports_grant(GrantType::AuthorizationCode)
        {
            return Err(violation(
                "refresh_token requires the authorization_code grant",
            ));
        }
        if !self.default_scopes.is_subset(&self.allowed_scopes) {
            return Err(violation(
                "default_scopes must be a subset of allowed_scopes",
            ));
        }
        for uri in &self.redirect_uris {
            let ok = match uri.scheme() {
                "https" => true,
                "http" => matches!(uri.host(), Some("localhost" | "127.0.0.1" | "[::1]")),
                _ => self.client_type == ClientType::Public,
            };
            if !ok {
                return Err(violation("redirect_uri scheme or host is not allowed"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    fn uri(s: &str) -> RedirectUri {
        RedirectUri::try_new(s.to_owned()).unwrap()
    }

    fn scopes(s: &str) -> ScopeSet {
        if s.is_empty() {
            ScopeSet::empty()
        } else {
            ScopeSet::parse(s).unwrap()
        }
    }

    fn secret(s: &str) -> OpaqueToken {
        OpaqueToken::try_new(crate::Secret::new(s.to_owned())).unwrap()
    }

    fn new_client(client_type: ClientType) -> NewClient {
        let confidential = client_type == ClientType::Confidential;
        NewClient {
            id: ClientId::try_new("c1".to_owned()).unwrap(),
            name: ClientName::try_new("App".to_owned()).unwrap(),
            client_type,
            auth_method: if confidential {
                TokenEndpointAuthMethod::ClientSecretBasic
            } else {
                TokenEndpointAuthMethod::None
            },
            redirect_uris: vec![uri("https://a.example/cb")],
            grant_types: [GrantType::AuthorizationCode, GrantType::RefreshToken].into(),
            allowed_scopes: scopes("read write"),
            default_scopes: scopes("read"),
            skip_consent: false,
        }
    }

    fn confidential() -> Client {
        Client::register(
            new_client(ClientType::Confidential),
            Some(secret("s3cret").hash()),
            now(),
        )
        .unwrap()
    }

    #[test]
    fn register_records_event() {
        let mut client = confidential();
        let events = client.pull_events();
        assert!(matches!(
            events.as_slice(),
            [ClientEvent::Registered { .. }]
        ));
        assert!(client.pull_events().is_empty());
    }

    #[test]
    fn confidential_without_secret_is_rejected() {
        let result = Client::register(new_client(ClientType::Confidential), None, now());
        assert!(matches!(result, Err(DomainError::ClientInvariant(_))));
    }

    #[test]
    fn redirect_uri_scheme_rules() {
        let mut new = new_client(ClientType::Confidential);
        new.redirect_uris = vec![uri("http://example.com/cb")];
        let hash = Some(secret("x").hash());
        assert!(matches!(
            Client::register(new.clone(), hash, now()),
            Err(DomainError::ClientInvariant(_))
        ));
        new.redirect_uris = vec![uri("http://127.0.0.1:8080/cb")];
        assert!(Client::register(new.clone(), hash, now()).is_ok());
        new.redirect_uris = vec![uri("com.example.app:/cb")];
        assert!(Client::register(new.clone(), hash, now()).is_err());
        for bad in [
            "http://evil.com\\@localhost/cb",
            "http://localhost@evil.com/cb",
            "http://localhost.evil.com/cb",
        ] {
            new.redirect_uris = vec![uri(bad)];
            assert!(Client::register(new.clone(), hash, now()).is_err(), "{bad}");
        }
        for ok in [
            "HTTP://LOCALHOST/cb",
            "http://[::1]:8080/cb",
            "http://user@127.0.0.1/cb",
        ] {
            new.redirect_uris = vec![uri(ok)];
            assert!(Client::register(new.clone(), hash, now()).is_ok(), "{ok}");
        }
        let mut public = new_client(ClientType::Public);
        public.redirect_uris = vec![uri("http://evil.com\\@localhost/cb")];
        assert!(Client::register(public, None, now()).is_err());
        let mut public = new_client(ClientType::Public);
        public.redirect_uris = vec![uri("com.example.app:/cb")];
        assert!(Client::register(public, None, now()).is_ok());
    }

    #[test]
    fn public_client_rules() {
        let mut new = new_client(ClientType::Public);
        new.grant_types.insert(GrantType::ClientCredentials);
        assert!(matches!(
            Client::register(new, None, now()),
            Err(DomainError::ClientInvariant(_))
        ));
        let mut public = Client::register(new_client(ClientType::Public), None, now()).unwrap();
        assert!(matches!(
            public.rotate_secret(secret("x").hash(), now()),
            Err(DomainError::InvalidState(_))
        ));
        assert!(!public.verify_secret(&secret("x")));
    }

    #[test]
    fn other_invariants() {
        let hash = Some(secret("x").hash());
        let mut new = new_client(ClientType::Confidential);
        new.grant_types.clear();
        assert!(Client::register(new, hash, now()).is_err());

        let mut new = new_client(ClientType::Confidential);
        new.grant_types = [GrantType::RefreshToken].into();
        assert!(Client::register(new, hash, now()).is_err());

        let mut new = new_client(ClientType::Confidential);
        new.default_scopes = scopes("admin");
        assert!(Client::register(new, hash, now()).is_err());

        let mut new = new_client(ClientType::Confidential);
        new.redirect_uris = vec![uri("https://a.example/cb"), uri("https://a.example/cb")];
        assert!(Client::register(new, hash, now()).is_err());

        let mut new = new_client(ClientType::Confidential);
        new.redirect_uris = (0..11)
            .map(|i| uri(&format!("https://a.example/{i}")))
            .collect();
        assert!(Client::register(new, hash, now()).is_err());

        let mut new = new_client(ClientType::Confidential);
        new.grant_types = [GrantType::ClientCredentials].into();
        assert!(
            Client::register(new, hash, now()).is_err(),
            "redirect_uris without authorization_code"
        );

        let mut new = new_client(ClientType::Confidential);
        new.auth_method = TokenEndpointAuthMethod::None;
        assert!(Client::register(new, hash, now()).is_err());
    }

    #[test]
    fn update_keeps_state_on_violation() {
        let mut client = confidential();
        client.pull_events();
        let before = client.to_record();
        let bad = ClientUpdate {
            grant_types: Some(BTreeSet::new()),
            ..Default::default()
        };
        assert!(matches!(
            client.update(bad, now()),
            Err(DomainError::ClientInvariant(_))
        ));
        assert_eq!(client.to_record(), before);
        assert!(client.pull_events().is_empty());

        let good = ClientUpdate {
            skip_consent: Some(true),
            ..Default::default()
        };
        client.update(good, now()).unwrap();
        assert!(client.skip_consent());
        assert!(matches!(
            client.pull_events().as_slice(),
            [ClientEvent::Updated { .. }]
        ));
    }

    #[test]
    fn verify_secret_is_exact() {
        let client = confidential();
        assert!(client.verify_secret(&secret("s3cret")));
        assert!(!client.verify_secret(&secret("s3cres")));
    }

    #[test]
    fn rotate_secret_replaces_hash() {
        let mut client = confidential();
        client.rotate_secret(secret("new").hash(), now()).unwrap();
        assert!(client.verify_secret(&secret("new")));
        assert!(!client.verify_secret(&secret("s3cret")));
    }

    #[test]
    fn disable_and_enable_are_idempotent() {
        let mut client = confidential();
        client.pull_events();
        client.enable(now());
        assert!(client.pull_events().is_empty());
        client.disable(now());
        client.disable(now());
        assert!(!client.is_active());
        assert_eq!(client.pull_events().len(), 1);
        client.enable(now());
        client.enable(now());
        assert!(client.is_active());
        assert_eq!(client.pull_events().len(), 1);
    }

    #[test]
    fn resolve_redirect_uri_rules() {
        let client = confidential();
        assert_eq!(
            client.resolve_redirect_uri(Some(&uri("https://a.example/cb/"))),
            Err(RedirectUriError::NotRegistered)
        );
        assert_eq!(
            client
                .resolve_redirect_uri(Some(&uri("https://a.example/cb")))
                .unwrap()
                .as_str(),
            "https://a.example/cb"
        );
        assert_eq!(
            client.resolve_redirect_uri(None).unwrap().as_str(),
            "https://a.example/cb"
        );

        let mut new = new_client(ClientType::Confidential);
        new.redirect_uris.push(uri("https://b.example/cb"));
        let two = Client::register(new, Some(secret("x").hash()), now()).unwrap();
        assert_eq!(
            two.resolve_redirect_uri(None),
            Err(RedirectUriError::Missing)
        );
    }

    #[test]
    fn resolve_scope_rules() {
        let mut new = new_client(ClientType::Confidential);
        new.default_scopes = ScopeSet::empty();
        let client = Client::register(new, Some(secret("x").hash()), now()).unwrap();
        assert_eq!(client.resolve_scope(None), Err(ScopeError::NoDefault));
        assert_eq!(
            client.resolve_scope(Some(&scopes("admin"))),
            Err(ScopeError::NotAllowed)
        );
        assert_eq!(
            client.resolve_scope(Some(&scopes("read"))),
            Ok(scopes("read"))
        );
        assert_eq!(confidential().resolve_scope(None), Ok(scopes("read")));
    }

    #[test]
    fn enums_round_trip_and_reject_unknown() {
        for g in [
            GrantType::AuthorizationCode,
            GrantType::ClientCredentials,
            GrantType::RefreshToken,
        ] {
            assert_eq!(g.as_str().parse::<GrantType>(), Ok(g));
        }
        for m in [
            TokenEndpointAuthMethod::ClientSecretBasic,
            TokenEndpointAuthMethod::ClientSecretPost,
            TokenEndpointAuthMethod::None,
        ] {
            assert_eq!(m.as_str().parse::<TokenEndpointAuthMethod>(), Ok(m));
        }
        for t in [ClientType::Confidential, ClientType::Public] {
            assert_eq!(t.as_str().parse::<ClientType>(), Ok(t));
        }
        assert_eq!(
            "x".parse::<ClientType>(),
            Err(DomainError::InvalidValue {
                field: "client_type",
                reason: "unknown value"
            })
        );
    }

    #[test]
    fn record_round_trip() {
        let client = confidential();
        let restored = Client::from_record(client.to_record());
        assert_eq!(restored.to_record(), client.to_record());
    }
}
