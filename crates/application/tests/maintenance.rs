//! MaintenanceService acceptance tests (application.md).

mod common;

use common::*;
use komainu_application::AuditKind;
use time::Duration;

#[test]
fn purge_expired_respects_the_grace_period_boundary() {
    let fx = Fixture::new();
    let client = register(&fx, confidential(&ALL_GRANTS));
    // Tokens expire at t0+1h, t0+2h, t0+3h.
    for _ in 0..3 {
        exchange(
            &fx,
            client.basic(),
            grant_request("client_credentials", None),
        )
        .unwrap();
        fx.env.clock.advance(Duration::hours(1));
    }
    // Now t0+26h: the tokens expired 25h, 24h and 23h ago.
    fx.env.clock.advance(Duration::hours(23));
    assert_eq!(fx.env.store.state().access_tokens.len(), 3);
    assert_send(&fx.maintenance.purge_expired(&ctx()));
    let report = block_on(fx.maintenance.purge_expired(&ctx())).unwrap();
    assert_eq!(report.counts.access_tokens, 2);
    assert_eq!(fx.env.store.state().access_tokens.len(), 1);
    // Purging writes no audit event.
    let kinds: Vec<_> = fx.env.store.audit_events().iter().map(|e| e.kind).collect();
    assert!(!kinds.iter().any(|k| k.as_str().contains("purge")));
}

#[test]
fn purge_expired_removes_audit_events_older_than_retention() {
    let fx = Fixture::new();
    register(&fx, confidential(&ALL_GRANTS));
    fx.env.clock.advance(Duration::days(2));
    register(&fx, confidential(&ALL_GRANTS));
    // Now t0+91d: the first event is 91 days old, the second 89.
    fx.env.clock.advance(Duration::days(89));
    let report = block_on(fx.maintenance.purge_expired(&ctx())).unwrap();
    assert_eq!(report.audit_events, 1);
    let events = fx.env.store.audit_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, AuditKind::ClientRegistered);
    block_on(fx.maintenance.check_ready()).unwrap();
}
