use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use komainu_application::{ClientAuthentication, TokenError};
use komainu_domain::Secret;

/// Decodes `application/x-www-form-urlencoded` text strictly: a malformed `%` escape or
/// invalid UTF-8 is an error.
fn form_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = bytes.get(i + 1..i + 3)?;
                let hex = std::str::from_utf8(hex).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 2;
            }
            other => out.push(other),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// `client_id` and `client_secret` from the body (empty values count as absent).
pub(crate) struct BodyCredentials {
    pub client_id: Option<String>,
    pub client_secret: Option<Secret<String>>,
}

fn basic_value(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("basic").then(|| rest.trim())
}

fn parse_basic(encoded: &str) -> Option<(String, Secret<String>)> {
    let decoded = STANDARD.decode(encoded).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    Some((form_decode(id)?, Secret::new(form_decode(secret)?)))
}

/// Decides the `ClientAuthentication` from the `Authorization` header and the body.
///
/// An `Err` is the response to return without calling `exchange`.
pub(crate) fn client_authentication(
    headers: &HeaderMap,
    body: BodyCredentials,
) -> Result<ClientAuthentication, TokenError> {
    let BodyCredentials {
        client_id,
        client_secret,
    } = body;
    match basic_value(headers) {
        Some(encoded) => {
            if client_secret.is_some() {
                return Err(TokenError::InvalidRequest);
            }
            let (id, secret) = parse_basic(encoded).ok_or(TokenError::InvalidClient {
                basic_attempted: true,
            })?;
            if client_id.is_some_and(|body_id| body_id != id) {
                return Err(TokenError::InvalidRequest);
            }
            Ok(ClientAuthentication::Basic {
                client_id: id,
                secret,
            })
        }
        None => match (client_id, client_secret) {
            (Some(client_id), Some(secret)) => Ok(ClientAuthentication::Post { client_id, secret }),
            (Some(client_id), None) => Ok(ClientAuthentication::PublicId { client_id }),
            (None, Some(_)) => Err(TokenError::InvalidRequest),
            (None, None) => Ok(ClientAuthentication::None),
        },
    }
}
