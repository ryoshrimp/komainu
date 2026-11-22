use std::sync::Arc;

use komainu_application::{ApplicationConfig, BuiltinAuthenticator, Dependencies};
use time::{Date, Month};

use crate::{FixedClock, InMemoryUnitOfWorkFactory, PlainPasswordHasher, SequenceRandom};

/// Dependencies wired with the in-memory adapters, FixedClock at 2026-01-01T00:00:00Z,
/// SequenceRandom, PlainPasswordHasher and BuiltinAuthenticator.
pub struct TestEnv {
    pub deps: Dependencies,
    pub store: InMemoryUnitOfWorkFactory,
    pub clock: FixedClock,
}

impl TestEnv {
    pub fn new(config: ApplicationConfig) -> Self {
        let store = InMemoryUnitOfWorkFactory::new();
        let start = Date::from_calendar_date(2026, Month::January, 1)
            .expect("valid date")
            .midnight()
            .assume_utc();
        let clock = FixedClock::new(start);
        let hasher = Arc::new(PlainPasswordHasher);
        let deps = Dependencies {
            store: Arc::new(store.clone()),
            clock: Arc::new(clock.clone()),
            random: Arc::new(SequenceRandom::default()),
            password_hasher: hasher.clone(),
            authenticator: Arc::new(BuiltinAuthenticator::new(hasher)),
            config: Arc::new(config),
        };
        Self { deps, store, clock }
    }
}

#[cfg(test)]
mod tests {
    use komainu_application::{
        AuthenticationOutcome, LoginCredentials, new_opaque_token, new_uuid_v7,
    };
    use komainu_domain::{PasswordHash, Secret, User, UserId};

    use super::*;
    use crate::test_util::block_on;

    fn credentials(name: &str, password: &str) -> LoginCredentials {
        LoginCredentials {
            username: name.to_owned(),
            password: Secret::new(password.to_owned()),
        }
    }

    fn env_with_user() -> (TestEnv, User) {
        let env = TestEnv::new(ApplicationConfig::default());
        let user = User::create(
            UserId::new(uuid::Uuid::from_u128(7)),
            komainu_domain::Username::try_new("alice".to_owned()).unwrap(),
            PasswordHash::try_new("plain$pw".to_owned()).unwrap(),
            env.deps.clock.now(),
        );
        block_on(async {
            let mut uow = env.deps.store.begin().await.unwrap();
            uow.users().insert(&user).await.unwrap();
            uow.commit().await.unwrap();
        });
        (env, user)
    }

    #[test]
    fn wiring_uses_fixed_clock() {
        let env = TestEnv::new(ApplicationConfig::default());
        assert_eq!(env.deps.clock.now().unix_timestamp(), 1_767_225_600);
        env.clock.advance(time::Duration::seconds(5));
        assert_eq!(env.deps.clock.now().unix_timestamp(), 1_767_225_605);
    }

    #[test]
    fn uuid_v7_and_tokens_are_well_formed_and_distinct() {
        let env = TestEnv::new(ApplicationConfig::default());
        let (clock, random) = (env.deps.clock.as_ref(), env.deps.random.as_ref());
        let a = new_uuid_v7(clock, random);
        let b = new_uuid_v7(clock, random);
        assert_ne!(a, b);
        assert_eq!(a.get_version_num(), 7);
        let ts = a.get_timestamp().unwrap().to_unix();
        assert_eq!(ts.0, 1_767_225_600);

        let t = new_opaque_token(random);
        assert_eq!(t.expose().len(), 43);
        assert!(
            t.expose()
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
        assert_ne!(t.expose(), new_opaque_token(random).expose());
    }

    #[test]
    fn builtin_authenticator() {
        let (env, user) = env_with_user();
        let auth = &env.deps.authenticator;
        block_on(async {
            let mut uow = env.deps.store.begin().await.unwrap();
            let ok = auth
                .authenticate(uow.as_mut(), &credentials("Alice", "pw"))
                .await
                .unwrap();
            assert_eq!(ok, AuthenticationOutcome::Authenticated(user.subject()));
            for (name, pw) in [
                ("alice", "bad"),
                ("nobody", "pw"),
                ("a", "pw"),
                ("alice", ""),
                ("alice", &"x".repeat(129)[..]),
            ] {
                let out = auth
                    .authenticate(uow.as_mut(), &credentials(name, pw))
                    .await
                    .unwrap();
                assert_eq!(
                    out,
                    AuthenticationOutcome::InvalidCredentials,
                    "{name}/{pw}"
                );
            }
            assert!(auth.is_active(uow.as_mut(), &user.subject()).await.unwrap());
            let unknown = komainu_domain::Subject::from(UserId::new(uuid::Uuid::from_u128(8)));
            assert!(!auth.is_active(uow.as_mut(), &unknown).await.unwrap());
            let not_uuid = komainu_domain::Subject::try_new("alice".to_owned()).unwrap();
            assert!(!auth.is_active(uow.as_mut(), &not_uuid).await.unwrap());

            // Disabled: the correct password gives Disabled, and is_active is false.
            let mut disabled = uow.users().find(*user.id()).await.unwrap().unwrap();
            disabled.disable(env.deps.clock.now());
            uow.users().update(&disabled).await.unwrap();
            let out = auth
                .authenticate(uow.as_mut(), &credentials("alice", "pw"))
                .await
                .unwrap();
            assert_eq!(out, AuthenticationOutcome::Disabled);
            let out = auth
                .authenticate(uow.as_mut(), &credentials("alice", "bad"))
                .await
                .unwrap();
            assert_eq!(out, AuthenticationOutcome::InvalidCredentials);
            assert!(!auth.is_active(uow.as_mut(), &user.subject()).await.unwrap());
        });
    }
}
