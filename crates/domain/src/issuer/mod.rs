//! Trusted external issuers and the mapping of their `sub` values to users.

#[allow(clippy::module_inception)]
mod issuer;
mod subject;

pub use issuer::{
    IssuerEvent, IssuerId, IssuerStatus, NewTrustedIssuer, TrustedIssuer, TrustedIssuerRecord,
    TrustedIssuerUpdate,
};
pub use subject::{ExternalSubject, SubjectMapping};
