//! The `Client` aggregate.

#[allow(clippy::module_inception)]
mod client;
mod event;

pub use client::{
    Client, ClientRecord, ClientStatus, ClientType, ClientUpdate, GrantType, NewClient,
    RedirectUriError, ScopeError, TokenEndpointAuthMethod,
};
pub use event::ClientEvent;
