//! RFC 7515, 7520 and 7638 test vectors.

use komainu_jose::jws::{self, SignOptions, VerifyOptions};
use komainu_jose::{JoseError, Secret, SigningKey, VerifyingKey};
use rsa::BoxedUint;
use rsa::pkcs8::EncodePrivateKey;

/// RFC 7515 A.2: RS256. The key is the JWK printed in the appendix.
const A2_JWK: &str = r#"{"kty":"RSA","n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ","e":"AQAB"}"#;
const A2_PRIVATE_JWK: &str = r#"{"kty":"RSA","n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ","e":"AQAB","d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ","p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc","q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc","dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0","dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU","qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"}"#;
const A2_TOKEN: &str = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
/// RFC 7515 A.3: ES256.
const A3_JWK: &str = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;
const A3_TOKEN: &str = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
/// RFC 7520 3.3 and 3.4: the cookbook RSA key.
const COOKBOOK_PUBLIC_JWK: &str = r#"{"kty":"RSA","kid":"bilbo.baggins@hobbiton.example","use":"sig","n":"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw","e":"AQAB"}"#;
const COOKBOOK_PRIVATE_JWK: &str = r#"{"kty":"RSA","kid":"bilbo.baggins@hobbiton.example","use":"sig","n":"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw","e":"AQAB","d":"bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ","p":"3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nRaO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmGpeNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0k","q":"uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc","dp":"B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX59ehik","dq":"CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pErAMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJKbi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdKT1cYF8","qi":"3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-NZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDhjJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpPz8aaI4"}"#;
/// RFC 7520 4.1: RS256 with a kid.
const COOKBOOK_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmKZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4JIwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8wW1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluPxUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_fcIe8u9ipH84ogoree7vjbU5y18kDquDg";
/// RFC 7638 3.1.
const THUMBPRINT_JWK: &str = r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}"#;
const THUMBPRINT: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

const A_PAYLOAD: &[u8] =
    b"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

fn keys(jwk: &str) -> Vec<VerifyingKey> {
    vec![VerifyingKey::from_jwk(jwk).unwrap()]
}

fn opts() -> VerifyOptions {
    VerifyOptions::new()
}

/// Builds a signing key from an RSA private JWK (a test helper; the crate reads no private JWKs).
fn signing_key_from_jwk(jwk: &str) -> SigningKey {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let jwk: serde_json::Value = serde_json::from_str(jwk).unwrap();
    let uint = |name: &str| {
        BoxedUint::from_be_slice_vartime(
            &URL_SAFE_NO_PAD.decode(jwk[name].as_str().unwrap()).unwrap(),
        )
    };
    let key = rsa::PrivateKey::from_components(
        uint("n"),
        uint("e"),
        uint("d"),
        vec![uint("p"), uint("q")],
    )
    .unwrap();
    let pem = key.to_pkcs8_pem(Default::default()).unwrap();
    SigningKey::from_pkcs8_pem(&Secret::new(pem.to_string())).unwrap()
}

#[test]
fn rfc7515_a2_rs256_verifies() {
    let verified = jws::verify(A2_TOKEN, &keys(A2_JWK), &opts()).unwrap();
    assert_eq!(verified.payload, A_PAYLOAD);
    assert_eq!(verified.header.algorithm().as_str(), "RS256");
    assert_eq!(verified.header.kid(), None);
    assert_eq!(verified.header.typ(), None);
}

#[test]
fn rfc7515_a2_rs256_signature_is_reproduced() {
    // RS256 (PKCS#1 v1.5) is deterministic, so signing gives the printed token.
    let key = signing_key_from_jwk(A2_PRIVATE_JWK);
    assert_eq!(
        jws::sign(A_PAYLOAD, &key, &SignOptions::new()).unwrap(),
        A2_TOKEN
    );
}

#[test]
fn rfc7515_a3_es256_verifies() {
    let verified = jws::verify(A3_TOKEN, &keys(A3_JWK), &opts()).unwrap();
    assert_eq!(verified.payload, A_PAYLOAD);
    assert_eq!(verified.header.algorithm().as_str(), "ES256");
}

#[test]
fn rfc7515_vectors_do_not_verify_with_the_wrong_key() {
    assert_eq!(
        jws::verify(A2_TOKEN, &keys(A3_JWK), &opts()).unwrap_err(),
        JoseError::KeyNotFound
    );
    assert_eq!(
        jws::verify(A3_TOKEN, &keys(A2_JWK), &opts()).unwrap_err(),
        JoseError::KeyNotFound
    );
    assert_eq!(
        jws::verify(A2_TOKEN, &keys(COOKBOOK_PUBLIC_JWK), &opts()).unwrap_err(),
        JoseError::InvalidSignature
    );
}

#[test]
fn rfc7515_vectors_reject_a_changed_payload() {
    for (token, jwk) in [(A2_TOKEN, A2_JWK), (A3_TOKEN, A3_JWK)] {
        let mut parts: Vec<&str> = token.split('.').collect();
        parts[1] = "e30";
        assert_eq!(
            jws::verify(&parts.join("."), &keys(jwk), &opts()).unwrap_err(),
            JoseError::InvalidSignature
        );
    }
}

#[test]
fn rfc7520_4_1_rs256_verifies_with_the_kid() {
    let verified = jws::verify(COOKBOOK_TOKEN, &keys(COOKBOOK_PUBLIC_JWK), &opts()).unwrap();
    assert_eq!(
        verified.header.kid().unwrap().as_inner(),
        "bilbo.baggins@hobbiton.example"
    );
    assert!(
        verified
            .payload
            .starts_with("It\u{2019}s a dangerous business".as_bytes())
    );
}

#[test]
fn rfc7520_4_1_rs256_signature_is_reproduced() {
    let key = signing_key_from_jwk(COOKBOOK_PRIVATE_JWK)
        .with_kid("bilbo.baggins@hobbiton.example".parse_kid());
    let payload = jws::verify(COOKBOOK_TOKEN, &keys(COOKBOOK_PUBLIC_JWK), &opts())
        .unwrap()
        .payload;
    assert_eq!(
        jws::sign(&payload, &key, &SignOptions::new()).unwrap(),
        COOKBOOK_TOKEN
    );
}

trait ParseKid {
    fn parse_kid(&self) -> komainu_jose::Kid;
}

impl ParseKid for str {
    fn parse_kid(&self) -> komainu_jose::Kid {
        komainu_jose::Kid::try_new(self.to_owned()).unwrap()
    }
}

#[test]
fn rfc7520_3_3_public_key_jwk_is_read() {
    let key = VerifyingKey::from_jwk(COOKBOOK_PUBLIC_JWK).unwrap();
    assert_eq!(
        key.kid().unwrap().as_inner(),
        "bilbo.baggins@hobbiton.example"
    );
    assert_eq!(
        key,
        signing_key_from_jwk(COOKBOOK_PRIVATE_JWK)
            .verifying_key()
            .with_kid(key.kid().unwrap().clone())
    );
}

#[test]
fn rfc7638_3_1_thumbprint() {
    let key = VerifyingKey::from_jwk(THUMBPRINT_JWK).unwrap();
    assert_eq!(key.thumbprint(), THUMBPRINT);
}

#[test]
fn rs256_signing_is_deterministic() {
    let key = signing_key_from_jwk(COOKBOOK_PRIVATE_JWK);
    let a = jws::sign(b"x", &key, &SignOptions::new()).unwrap();
    let b = jws::sign(b"x", &key, &SignOptions::new()).unwrap();
    assert_eq!(a, b);
}
