use std::net::IpAddr;

/// Per-request information written into audit events.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// x-request-id (N-8). CLI uses a freshly generated UUIDv7 string.
    pub request_id: String,
    /// Peer address of the HTTP connection. None for CLI and jobs.
    pub client_ip: Option<IpAddr>,
}
