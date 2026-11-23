# komainu-jose

A small JOSE implementation for [komainu](https://github.com/ryoshrimp/komainu), an embeddable
OAuth 2.0 authorization server. It exists so that komainu can issue and verify JWT access tokens
and OpenID Connect ID tokens. It is published on its own and usable without komainu, but its scope
is whatever komainu needs, not a general-purpose JOSE library.

Cryptography is done by RustCrypto (`rsa`, `p256`, `sha2`); nothing is implemented by hand.

## What it does

- Algorithms: RS256 and ES256
- Keys: generation (ES256, RSA 2048/3072/4096), PKCS#8 (PEM/DER) private keys, SPKI (PEM/DER)
  public keys, public-key JWK and JWK Set, RFC 7638 thumbprints
- JWS Compact Serialization: sign and verify
- JWT: encode and decode with `iss`, `aud` and `exp` required, `nbf` and `iat` checked when
  present, optional `typ` requirement. The current time is passed in by the caller

The algorithm is bound to the key, not to the token: a token is only verified with a key of the
algorithm named in its header, and `alg: none` is never accepted. Duplicate JSON keys, padded or
non-canonical base64url, and `crit` headers are rejected.

```rust
use komainu_jose::{SigningKey, jws::{self, SignOptions, VerifyOptions}};

fn main() -> Result<(), komainu_jose::JoseError> {
    let key = SigningKey::generate_es256()?;
    let token = jws::sign(b"hello", &key, &SignOptions::new())?;
    let verified = jws::verify(&token, &[key.verifying_key()], &VerifyOptions::new())?;
    assert_eq!(verified.payload, b"hello");
    Ok(())
}
```

## What it does not do

- JWE (encryption)
- Other algorithms: EdDSA, RS384/RS512, PS256 and friends, ES384/ES512, HS256 and friends
  (`alg: none` is never supported)
- JWS JSON Serialization, unencoded payloads (RFC 7797), nested JWTs
- Private keys as JWK
- Fetching or trusting keys named by `jku`, `x5u`, `jwk` or `x5c` headers (they are ignored)
- Key storage, rotation, `jwks_uri` endpoints, HTTP access of any kind
- Reading headers before verification

## Fuzzing

Fuzz targets (`jws_verify`, `jwt_decode`, `jwk_parse`) live in `fuzz/` and need nightly Rust and
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz):

```sh
cd crates/jose
cargo +nightly fuzz run jws_verify
```

## License

Licensed under either of Apache License 2.0 or MIT at your option.
