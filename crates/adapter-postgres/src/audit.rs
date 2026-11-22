//! `audit_events` table (append only).

use komainu_application::{AuditEvent, AuditLogRepository, BoxFuture, StoreError};

use crate::error::map_sqlx;
use crate::uow::PgUnitOfWork;

impl AuditLogRepository for PgUnitOfWork {
    fn append(&mut self, event: &AuditEvent) -> BoxFuture<'_, Result<(), StoreError>> {
        let details: serde_json::Map<String, serde_json::Value> = event
            .details
            .iter()
            .map(|(k, v)| ((*k).to_owned(), serde_json::Value::String(v.clone())))
            .collect();
        let id = event.id;
        let occurred_at = event.occurred_at;
        let kind = event.kind.as_str();
        let outcome = event.outcome.as_str();
        let actor = event.actor.as_str();
        let request_id = event.request_id.clone();
        let client_ip = event.client_ip.map(|ip| ip.to_string());
        let client_id = event.client_id.as_ref().map(|c| c.as_inner().clone());
        let subject = event.subject.as_ref().map(|s| s.as_inner().clone());
        Box::pin(async move {
            // The address is bound as text and cast, because sqlx's `inet` support needs ipnetwork.
            sqlx::query(
                "INSERT INTO audit_events (id, occurred_at, kind, outcome, actor, request_id, \
                 client_ip, client_id, subject, details) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7::text::inet, $8, $9, $10)",
            )
            .bind(id)
            .bind(occurred_at)
            .bind(kind)
            .bind(outcome)
            .bind(actor)
            .bind(request_id)
            .bind(client_ip)
            .bind(client_id)
            .bind(subject)
            .bind(serde_json::Value::Object(details))
            .execute(&mut *self.tx)
            .await
            .map(|_| ())
            .map_err(map_sqlx)
        })
    }
}
