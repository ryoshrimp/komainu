//! Strict JSON object parsing: duplicate object keys are rejected at every depth.

use std::cell::Cell;
use std::fmt;

use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use crate::error::JoseError;

/// What is being parsed; selects the error reason strings.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Kind {
    Header,
    Claims,
    Jwk,
    Jwks,
}

impl Kind {
    fn reasons(self) -> [&'static str; 4] {
        match self {
            Self::Header => [
                "header: utf-8",
                "header: syntax",
                "header: not an object",
                "header: duplicate key",
            ],
            Self::Claims => [
                "claims: utf-8",
                "claims: syntax",
                "claims: not an object",
                "claims: duplicate key",
            ],
            Self::Jwk => [
                "jwk: utf-8",
                "jwk: syntax",
                "jwk: not an object",
                "jwk: duplicate key",
            ],
            Self::Jwks => [
                "jwks: utf-8",
                "jwks: syntax",
                "jwks: not an object",
                "jwks: duplicate key",
            ],
        }
    }
}

/// Parses a UTF-8 JSON text whose top level is an object without duplicate keys.
pub(crate) fn parse_object(input: &[u8], kind: Kind) -> Result<Map<String, Value>, JoseError> {
    let [utf8, syntax, not_object, duplicate] = kind.reasons();
    let text = std::str::from_utf8(input).map_err(|_| JoseError::Malformed(utf8))?;
    let duplicated = Cell::new(false);
    let mut de = serde_json::Deserializer::from_str(text);
    let parsed = Strict(&duplicated)
        .deserialize(&mut de)
        .and_then(|value| de.end().map(|()| value));
    match parsed {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err(JoseError::Malformed(not_object)),
        Err(_) if duplicated.get() => Err(JoseError::Malformed(duplicate)),
        Err(_) => Err(JoseError::Malformed(syntax)),
    }
}

/// Deserializes any JSON value, setting the flag when an object repeats a key.
#[derive(Clone, Copy)]
struct Strict<'a>(&'a Cell<bool>);

impl<'de> DeserializeSeed<'de> for Strict<'_> {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Strict<'_> {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(Number::from_f64(v).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(self)? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        let mut map = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if map.contains_key(&key) {
                self.0.set(true);
                return Err(serde::de::Error::custom("duplicate key"));
            }
            let value = access.next_value_seed(self)?;
            map.insert(key, value);
        }
        Ok(Value::Object(map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Map<String, Value>, JoseError> {
        parse_object(s.as_bytes(), Kind::Claims)
    }

    #[test]
    fn parses_objects_with_surrounding_whitespace() {
        let map = parse(" \n{\"a\":1,\"b\":[true,null,{\"c\":\"d\"}],\"e\":1.5}\t ").unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(map["a"], Value::from(1));
        assert_eq!(map["e"], Value::from(1.5));
        assert!(parse("{}").unwrap().is_empty());
    }

    #[test]
    fn rejects_duplicate_keys_at_every_depth() {
        let d = Err(JoseError::Malformed("claims: duplicate key"));
        assert_eq!(parse(r#"{"a":1,"a":2}"#), d);
        assert_eq!(parse(r#"{"a":{"b":1,"b":2}}"#), d);
        assert_eq!(parse(r#"{"a":[{"b":{"c":1,"c":1}}]}"#), d);
        // Same key in different objects is fine.
        assert!(parse(r#"{"a":{"b":1},"c":{"b":2}}"#).is_ok());
    }

    #[test]
    fn rejects_non_objects() {
        for s in ["[]", "1", "\"a\"", "null", "true"] {
            assert_eq!(parse(s), Err(JoseError::Malformed("claims: not an object")));
        }
    }

    #[test]
    fn rejects_syntax_errors_and_trailing_data() {
        for s in ["", "{", "{\"a\":}", "{} {}", "{}x", "{'a':1}", "{\"a\":1,}"] {
            assert_eq!(
                parse(s),
                Err(JoseError::Malformed("claims: syntax")),
                "{s:?}"
            );
        }
    }

    #[test]
    fn rejects_invalid_utf8() {
        assert_eq!(
            parse_object(b"{\"a\":\"\xff\"}", Kind::Jwk),
            Err(JoseError::Malformed("jwk: utf-8"))
        );
    }

    #[test]
    fn reasons_follow_the_kind() {
        assert_eq!(
            parse_object(b"[]", Kind::Header),
            Err(JoseError::Malformed("header: not an object"))
        );
        assert_eq!(
            parse_object(b"[]", Kind::Jwks),
            Err(JoseError::Malformed("jwks: not an object"))
        );
        assert_eq!(
            parse_object(b"{\"a\":1,\"a\":1}", Kind::Jwk),
            Err(JoseError::Malformed("jwk: duplicate key"))
        );
    }

    #[test]
    fn deep_nesting_is_an_error_not_a_crash() {
        let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
        let s = format!("{{\"a\":{deep}}}");
        assert_eq!(parse(&s), Err(JoseError::Malformed("claims: syntax")));
    }
}
