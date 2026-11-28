//! Fixed values written by the cases.

use std::collections::BTreeSet;

use komainu_domain::*;
use time::OffsetDateTime;

pub(super) fn t(secs: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000 + secs).unwrap()
}

pub(super) fn hash(n: u8) -> TokenHash {
    TokenHash::from_bytes([n; 32])
}

pub(super) fn cid(s: &str) -> ClientId {
    ClientId::try_new(s.to_owned()).unwrap()
}

pub(super) fn subject(s: &str) -> Subject {
    Subject::try_new(s.to_owned()).unwrap()
}

pub(super) fn scope(s: &str) -> ScopeSet {
    ScopeSet::parse(s).unwrap()
}

pub(super) fn code_verifier() -> CodeVerifier {
    CodeVerifier::try_new(Secret::new("a".repeat(43))).unwrap()
}

/// The S256 challenge of [`code_verifier`].
pub(super) fn pkce() -> PkceChallenge {
    PkceChallenge::new(
        CodeChallenge::try_new("ZtNPunH49FD35FWYhT5Tv8I7vRKQJ8uxMaL0_9eHjNA".to_owned()).unwrap(),
        CodeChallengeMethod::S256,
    )
}

pub(super) fn uri(s: &str) -> RedirectUri {
    RedirectUri::try_new(s.to_owned()).unwrap()
}

pub(super) fn client_record(id: &str) -> ClientRecord {
    ClientRecord {
        id: cid(id),
        name: ClientName::try_new(format!("Client {id}")).unwrap(),
        client_type: ClientType::Confidential,
        auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
        secret_hash: Some(hash(9)),
        redirect_uris: vec![uri("https://b.example/cb"), uri("https://a.example/cb")],
        grant_types: BTreeSet::from([GrantType::AuthorizationCode, GrantType::RefreshToken]),
        allowed_scopes: scope("read write"),
        default_scopes: scope("read"),
        skip_consent: true,
        keys: None,
        status: ClientStatus::Active,
        created_at: t(0),
        updated_at: t(1),
    }
}

pub(super) fn user_record(n: u128, name: &str) -> UserRecord {
    UserRecord {
        id: UserId::new(uuid::Uuid::from_u128(n)),
        username: Username::try_new(name.to_owned()).unwrap(),
        password_hash: PasswordHash::try_new("$argon2id$v=19$dummy".to_owned()).unwrap(),
        status: UserStatus::Active,
        created_at: t(0),
        updated_at: t(0),
    }
}

pub(super) fn gid(n: u128) -> GrantId {
    GrantId::new(uuid::Uuid::from_u128(n))
}

pub(super) fn grant_record(n: u128, client: &str) -> GrantRecord {
    GrantRecord {
        id: gid(n),
        client_id: cid(client),
        subject: Some(subject("alice")),
        scope: scope("read"),
        origin: GrantOrigin::AuthorizationCode { code_hash: hash(1) },
        status: GrantStatus::Active,
        created_at: t(0),
    }
}

pub(super) fn jwks_document() -> JwksDocument {
    JwksDocument::try_new(r#"{"keys":[]}"#.to_owned()).unwrap()
}

pub(super) fn issuer_id(s: &str) -> IssuerId {
    IssuerId::try_new(s.to_owned()).unwrap()
}

pub(super) fn external_subject(s: &str) -> ExternalSubject {
    ExternalSubject::try_new(s.to_owned()).unwrap()
}

pub(super) fn issuer_record(id: &str, clients: &[&str]) -> TrustedIssuerRecord {
    TrustedIssuerRecord {
        id: issuer_id(id),
        jwks: jwks_document(),
        allowed_clients: clients.iter().map(|c| cid(c)).collect(),
        status: IssuerStatus::Active,
        created_at: t(0),
        updated_at: t(1),
    }
}

pub(super) fn mapping(issuer: &str, sub: &str, user: u128, at: i64) -> SubjectMapping {
    SubjectMapping {
        issuer_id: issuer_id(issuer),
        subject: external_subject(sub),
        user_id: UserId::new(uuid::Uuid::from_u128(user)),
        updated_at: t(at),
    }
}

pub(super) fn signing_key(
    kid: &str,
    activates: i64,
    retires: i64,
    deletes: i64,
) -> ServerSigningKey {
    signing_key_with(SigningAlgorithm::Es256, kid, activates, retires, deletes)
}

pub(super) fn signing_key_with(
    algorithm: SigningAlgorithm,
    kid: &str,
    activates: i64,
    retires: i64,
    deletes: i64,
) -> ServerSigningKey {
    ServerSigningKey::from_record(ServerSigningKeyRecord {
        kid: SigningKeyId::try_new(kid.to_owned()).unwrap(),
        algorithm,
        sealed_private_key: SealedPrivateKey::new(vec![1, 2, 3, 4]).unwrap(),
        public_jwk: PublicJwk::try_new(format!(r#"{{"kid":"{kid}"}}"#)).unwrap(),
        created_at: t(0),
        activates_at: t(activates),
        retires_at: t(retires),
        deletes_at: t(deletes),
    })
}

pub(super) fn signing_key_id(s: &str) -> SigningKeyId {
    SigningKeyId::try_new(s.to_owned()).unwrap()
}
