use time::OffsetDateTime;

use super::key::{KeyStatus, ServerSigningKey, SigningAlgorithm, SigningKeyId, current_key};
use super::policy::SigningPolicy;

/// A key the rotation wants created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyToCreate {
    pub algorithm: SigningAlgorithm,
    pub activates_at: OffsetDateTime,
    /// `activates_at + active_period`
    pub retires_at: OffsetDateTime,
    /// `retires_at + retire_overlap`
    pub deletes_at: OffsetDateTime,
}

/// What a periodic rotation has to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RotationPlan {
    /// In `algorithms` order, at most one per algorithm.
    pub create: Vec<KeyToCreate>,
    /// Pending keys to activate now, in `algorithms` order, at most one per algorithm.
    pub activate: Vec<SigningKeyId>,
    /// Sorted by kid.
    pub delete: Vec<SigningKeyId>,
}

fn key_to_create(
    algorithm: SigningAlgorithm,
    activates_at: OffsetDateTime,
    policy: &SigningPolicy,
) -> KeyToCreate {
    let retires_at = activates_at + policy.active_period();
    KeyToCreate {
        algorithm,
        activates_at,
        retires_at,
        deletes_at: retires_at + policy.retire_overlap(),
    }
}

/// Plans a periodic rotation.
pub fn plan_rotation(
    keys: &[ServerSigningKey],
    algorithms: &[SigningAlgorithm],
    now: OffsetDateTime,
    policy: &SigningPolicy,
) -> RotationPlan {
    let mut delete: Vec<SigningKeyId> = keys
        .iter()
        .filter(|k| k.status_at(now) == KeyStatus::Expired)
        .map(|k| k.kid().clone())
        .collect();
    delete.sort();
    let mut plan = RotationPlan {
        delete,
        ..RotationPlan::default()
    };

    for (i, &a) in algorithms.iter().enumerate() {
        if algorithms[..i].contains(&a) {
            continue;
        }
        let pending = || {
            keys.iter()
                .filter(|k| k.algorithm() == a && k.status_at(now) == KeyStatus::Pending)
        };
        match current_key(keys, a, now) {
            None => match pending().min_by(|x, y| {
                x.activates_at()
                    .cmp(&y.activates_at())
                    .then_with(|| x.kid().cmp(y.kid()))
            }) {
                Some(p) => plan.activate.push(p.kid().clone()),
                None => plan.create.push(key_to_create(a, now, policy)),
            },
            Some(cur) => {
                let next_exists = pending().any(|p| p.activates_at() >= cur.retires_at());
                if !next_exists && now >= cur.retires_at() - policy.prepublish() {
                    plan.create.push(key_to_create(a, cur.retires_at(), policy));
                }
            }
        }
    }
    plan
}

/// The key an immediate rotation creates: `activates_at = now`.
pub fn immediate_key(
    algorithm: SigningAlgorithm,
    now: OffsetDateTime,
    policy: &SigningPolicy,
) -> KeyToCreate {
    key_to_create(algorithm, now, policy)
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::super::key::tests::{key, t};
    use super::*;

    const E: SigningAlgorithm = SigningAlgorithm::Es256;
    const R: SigningAlgorithm = SigningAlgorithm::Rs256;
    const DAY: i64 = 86_400;

    fn policy() -> SigningPolicy {
        SigningPolicy::default()
    }

    fn kid(s: &str) -> SigningKeyId {
        SigningKeyId::try_new(s.to_owned()).unwrap()
    }

    #[test]
    fn no_keys_creates_one_per_algorithm() {
        let plan = plan_rotation(&[], &[R, E], t(1000), &policy());
        assert_eq!(plan.create.len(), 2);
        assert_eq!(plan.create[0].algorithm, R);
        assert_eq!(plan.create[1].algorithm, E);
        assert!(plan.create.iter().all(|c| c.activates_at == t(1000)));
        assert_eq!(plan.create[0].retires_at, t(1000) + Duration::days(90));
        assert_eq!(plan.create[0].deletes_at, t(1000) + Duration::days(97));
        assert!(plan.activate.is_empty() && plan.delete.is_empty());
    }

    #[test]
    fn duplicate_algorithms_are_planned_once() {
        let plan = plan_rotation(&[], &[E, E], t(1000), &policy());
        assert_eq!(plan.create.len(), 1);
    }

    #[test]
    fn prepublish_boundary() {
        let keys = [key("a", E, 0, 90 * DAY, 97 * DAY)];
        let at = 83 * DAY;
        assert_eq!(
            plan_rotation(&keys, &[E], t(at - 1), &policy()),
            RotationPlan::default()
        );
        let plan = plan_rotation(&keys, &[E], t(at), &policy());
        assert_eq!(plan.create.len(), 1);
        assert_eq!(plan.create[0].activates_at, t(90 * DAY));
        assert_eq!(plan.create[0].retires_at, t(180 * DAY));
        assert_eq!(plan.create[0].deletes_at, t(187 * DAY));
    }

    #[test]
    fn next_key_exists() {
        let keys = [
            key("a", E, 0, 90 * DAY, 97 * DAY),
            key("b", E, 90 * DAY, 180 * DAY, 187 * DAY),
        ];
        assert_eq!(
            plan_rotation(&keys, &[E], t(85 * DAY), &policy()),
            RotationPlan::default()
        );
    }

    #[test]
    fn expired_keys_deleted_and_removed_algorithm_not_created() {
        let keys = [
            key("z", E, 0, 10, 20),
            key("y", R, 0, 10, 20),
            key("x", R, 0, 100, 200),
        ];
        let plan = plan_rotation(&keys, &[E], t(20), &policy());
        assert_eq!(plan.delete, vec![kid("y"), kid("z")]);
        assert_eq!(plan.create.len(), 1);
        assert_eq!(plan.create[0].algorithm, E);
        assert!(plan.activate.is_empty());
    }

    #[test]
    fn pending_only_activates_earliest() {
        let keys = [
            key("b", E, 200, 300, 400),
            key("a", E, 100, 300, 400),
            key("c", E, 100, 300, 400),
        ];
        let plan = plan_rotation(&keys, &[E], t(10), &policy());
        assert!(plan.create.is_empty());
        assert_eq!(plan.activate, vec![kid("a")]);
    }
}
