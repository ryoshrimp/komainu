use axum::body::Bytes;
use axum::http::HeaderMap;
use axum::http::header::CONTENT_TYPE;
use komainu_application::NonRedirectableError;
use komainu_domain::{AuthorizationRequestId, OpaqueToken, Secret};
use subtle::ConstantTimeEq;

use crate::client_auth::BodyCredentials;
use crate::cookies::{self, CSRF_COOKIE};

/// Splits a form body into `client_id`, `client_secret` and the other pairs.
///
/// The credentials are `None` when either of them occurs more than once. Empty values are
/// treated as absent.
pub(crate) fn split_client_credentials(
    body: &Bytes,
) -> (Option<BodyCredentials>, Vec<(String, String)>) {
    let mut client_id = Vec::new();
    let mut client_secret = Vec::new();
    let mut rest = Vec::new();
    for (key, value) in form_urlencoded::parse(body).into_owned() {
        match key.as_str() {
            "client_id" => client_id.push(value),
            // Wrapped immediately so the secret is never carried around as a plain String.
            "client_secret" => client_secret.push(Secret::new(value)),
            _ => rest.push((key, value)),
        }
    }
    if client_id.len() > 1 || client_secret.len() > 1 {
        return (None, rest);
    }
    let credentials = BodyCredentials {
        client_id: client_id.pop().filter(|value| !value.is_empty()),
        client_secret: client_secret
            .pop()
            .filter(|secret| !secret.expose_secret_ref().is_empty()),
    };
    (Some(credentials), rest)
}

/// Whether the `Content-Type` is `application/x-www-form-urlencoded` (parameters allowed).
pub(crate) fn is_form_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| {
            media_type
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

/// A parsed `application/x-www-form-urlencoded` body.
pub(crate) struct Form(Vec<(String, String)>);

impl Form {
    /// `None` when the content type is not a form.
    pub(crate) fn parse(headers: &HeaderMap, body: &Bytes) -> Option<Form> {
        is_form_content_type(headers)
            .then(|| Form(form_urlencoded::parse(body).into_owned().collect()))
    }

    /// The value of `name`. Absent and repeated fields both give `None`.
    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        let mut values = self.0.iter().filter(|(key, _)| key == name);
        let first = values.next()?;
        values.next().is_none().then_some(first.1.as_str())
    }
}

pub(crate) fn parse_request_id(raw: &str) -> Option<AuthorizationRequestId> {
    uuid::Uuid::parse_str(raw)
        .ok()
        .map(AuthorizationRequestId::new)
}

/// Checks that the form's `csrf_token` equals the `komainu_csrf` cookie (constant time) and
/// returns it for the use case, which compares it with the stored hash.
pub(crate) fn verified_csrf(
    form_value: &str,
    headers: &HeaderMap,
) -> Result<OpaqueToken, NonRedirectableError> {
    let mismatch = || NonRedirectableError::CsrfMismatch;
    let cookie = cookies::token(headers, CSRF_COOKIE).ok_or_else(mismatch)?;
    let presented =
        OpaqueToken::try_new(Secret::new(form_value.to_owned())).map_err(|_| mismatch())?;
    let equal: bool = cookie
        .expose()
        .as_bytes()
        .ct_eq(presented.expose().as_bytes())
        .into();
    if equal {
        Ok(presented)
    } else {
        Err(mismatch())
    }
}
