use axum::http::header::COOKIE;
use axum::http::{HeaderMap, HeaderValue};
use komainu_domain::{OpaqueToken, Secret};

pub(crate) const SESSION_COOKIE: &str = "komainu_session";
pub(crate) const CSRF_COOKIE: &str = "komainu_csrf";

/// The value of the first cookie called `name`.
fn read<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(cookie_name, _)| *cookie_name == name)
        .map(|(_, value)| value)
}

/// A cookie holding a token, or `None` when it is absent or malformed.
pub(crate) fn token(headers: &HeaderMap, name: &str) -> Option<OpaqueToken> {
    OpaqueToken::try_new(Secret::new(read(headers, name)?.to_owned())).ok()
}

/// `Set-Cookie` value. `max_age_secs == 0` with an empty value deletes the cookie.
pub(crate) fn set(name: &str, value: &str, max_age_secs: i64, secure: bool) -> HeaderValue {
    let secure = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{name}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age_secs}{secure}"
    ))
    // Tokens issued by the application are base64url, which is always a valid header value.
    .expect("cookie value is a valid header value")
}

pub(crate) fn delete(name: &str, secure: bool) -> HeaderValue {
    set(name, "", 0, secure)
}
