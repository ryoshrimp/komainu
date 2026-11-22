use crate::support::collect_params;

/// Query parameters of `GET /authorize`. Empty values are treated as absent.
#[derive(Debug, Clone, Default)]
pub struct AuthorizeParams {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    /// Names of the above parameters that appeared more than once.
    pub duplicated: Vec<&'static str>,
}

impl AuthorizeParams {
    /// Unknown parameters are ignored.
    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        let ([response_type, client_id, redirect_uri, scope, state], duplicated) = collect_params(
            pairs,
            [
                "response_type",
                "client_id",
                "redirect_uri",
                "scope",
                "state",
            ],
        );
        Self {
            response_type,
            client_id,
            redirect_uri,
            scope,
            state,
            duplicated,
        }
    }
}
