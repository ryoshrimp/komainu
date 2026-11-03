use crate::time::DurationMillis;

/// **English:**<br>
/// Positive TTLs for codes, access tokens, refresh tokens, and interactions.
/// Defaults are 60 seconds, 15 minutes, 30 days, and 10 minutes, respectively.
/// [`Self::new`] takes the TTLs in that order as validated [`DurationMillis`]
/// values. Serde uses an object with `code_ttl`, `access_ttl`, `refresh_ttl`, and
/// `interaction_ttl` fields, each an integer in milliseconds. Deserialization
/// rejects zero or values above [`i64::MAX`]; it does not fill missing fields
/// from [`Default`].
///
/// **日本語:**<br>
/// コード、アクセストークン、リフレッシュトークン、対話の正のTTLを保持します。
/// デフォルトは順に60秒、15分、30日、10分です。
/// [`Self::new`] は検証済みの [`DurationMillis`] 値をこの順に受け取ります。
/// Serdeは `code_ttl`、`access_ttl`、`refresh_ttl`、`interaction_ttl` を
/// フィールドとするオブジェクトを使い、各値をミリ秒単位の整数で表現します。
/// デシリアライズ時にはゼロや [`i64::MAX`] を超える値を拒否し、欠けている
/// フィールドを [`Default`] から補完することはありません。
///
/// # Example / 使用例
/// ```rust
/// use komainu_domain::time::{DurationMillis, Lifetime, LifetimePolicy, Timestamp};
///
/// let defaults = LifetimePolicy::default();
/// assert_eq!(*defaults.code_ttl().as_inner(), 60_000);
/// assert_eq!(*defaults.access_ttl().as_inner(), 900_000);
/// assert_eq!(*defaults.refresh_ttl().as_inner(), 2_592_000_000);
/// assert_eq!(*defaults.interaction_ttl().as_inner(), 600_000);
///
/// let policy = LifetimePolicy::new(
///     DurationMillis::try_new(30_000).unwrap(),
///     *defaults.access_ttl(),
///     *defaults.refresh_ttl(),
///     *defaults.interaction_ttl(),
/// );
/// let issued_at = Timestamp::try_new(0).unwrap();
/// let code_lifetime = Lifetime::from_duration(issued_at, *policy.code_ttl()).unwrap();
/// assert_eq!(*code_lifetime.expires_at().as_inner(), 30_000);
///
/// let json = serde_json::to_string(&policy).unwrap();
/// assert_eq!(serde_json::from_str::<LifetimePolicy>(&json).unwrap(), policy);
/// assert!(serde_json::from_str::<LifetimePolicy>(r#"{}"#).is_err());
/// ```
#[derive(ddd_toolkit::ValueObject)]
#[value_object(serde)]
pub struct LifetimePolicy {
    code_ttl: crate::time::DurationMillis,
    access_ttl: crate::time::DurationMillis,
    refresh_ttl: crate::time::DurationMillis,
    interaction_ttl: crate::time::DurationMillis,
}

impl Default for LifetimePolicy {
    fn default() -> Self {
        LifetimePolicy::new(
            DurationMillis::try_new(60000).unwrap(),
            DurationMillis::try_new(900000).unwrap(),
            DurationMillis::try_new(2592000000).unwrap(),
            DurationMillis::try_new(600000).unwrap(),
        )
    }
}
