//! Signing and verifying keys.

use core::fmt;

use ddd_toolkit::secret::Secret;
use pkcs8::{
    AlgorithmIdentifierRef, DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey,
    LineEnding, ObjectIdentifier, PrivateKeyInfoRef, SubjectPublicKeyInfoRef,
};
use rsa::BoxedUint;
use rsa::traits::PublicKeyParts;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::algorithm::Algorithm;
use crate::error::JoseError;
use crate::kid::Kid;

const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// The size of a generated RSA key.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaKeySize {
    /// 2048 bits.
    Bits2048,
    /// 3072 bits.
    Bits3072,
    /// 4096 bits.
    Bits4096,
}

impl RsaKeySize {
    fn bits(self) -> usize {
        match self {
            Self::Bits2048 => 2048,
            Self::Bits3072 => 3072,
            Self::Bits4096 => 4096,
        }
    }
}

#[derive(Clone)]
pub(crate) enum SigningInner {
    Rsa(rsa::PrivateKey),
    Ec(p256::ecdsa::SigningKey),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerifyingInner {
    Rsa(rsa::PublicKey),
    Ec(p256::ecdsa::VerifyingKey),
}

/// A private key. The algorithm follows from the key type (RSA is RS256, P-256 is ES256).
#[derive(Clone)]
pub struct SigningKey {
    pub(crate) inner: SigningInner,
    pub(crate) kid: Option<Kid>,
}

/// A public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    pub(crate) inner: VerifyingInner,
    pub(crate) kid: Option<Kid>,
}

enum KeyKind {
    Rsa,
    Ec,
}

fn key_kind(algorithm: &AlgorithmIdentifierRef<'_>) -> Result<KeyKind, JoseError> {
    if algorithm.oid == RSA_ENCRYPTION {
        Ok(KeyKind::Rsa)
    } else if algorithm.oid == EC_PUBLIC_KEY && algorithm.parameters_oid().ok() == Some(PRIME256V1)
    {
        Ok(KeyKind::Ec)
    } else {
        Err(JoseError::InvalidKey("unsupported key type"))
    }
}

/// An RSA modulus must be 2048 to 4096 bits.
pub(crate) fn check_rsa_modulus(n: &BoxedUint) -> Result<(), JoseError> {
    if (2048..=4096).contains(&n.bit_width_vartime()) {
        Ok(())
    } else {
        Err(JoseError::InvalidKey("rsa modulus size"))
    }
}

/// An RSA public exponent must be odd and within 3 to 2^33-1.
pub(crate) fn check_rsa_exponent(e: &BoxedUint) -> Result<(), JoseError> {
    let bytes = e.to_be_bytes_trimmed_vartime();
    if bytes.len() > 5 {
        return Err(JoseError::InvalidKey("rsa e"));
    }
    let value = bytes.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
    if value < 3 || value % 2 == 0 || value > (1 << 33) - 1 {
        return Err(JoseError::InvalidKey("rsa e"));
    }
    Ok(())
}

fn check_rsa_public(key: &impl PublicKeyParts) -> Result<(), JoseError> {
    check_rsa_modulus(key.n())?;
    check_rsa_exponent(key.e())
}

/// Decodes a PEM block with the given label into DER, trimming surrounding whitespace.
fn pem_to_der(
    pem: &str,
    label: &str,
    wrong_label: &'static str,
) -> Result<Zeroizing<Vec<u8>>, JoseError> {
    let (found, der) = pkcs8::der::pem::decode_vec(pem.trim().as_bytes())
        .map_err(|_| JoseError::InvalidKey("pem"))?;
    let der = Zeroizing::new(der);
    if found == label {
        Ok(der)
    } else {
        Err(JoseError::InvalidKey(wrong_label))
    }
}

fn random_error<E>(_: E) -> JoseError {
    JoseError::KeyGeneration
}

impl SigningKey {
    /// Generates a P-256 key (ES256) with the OS random number generator.
    pub fn generate_es256() -> Result<Self, JoseError> {
        use p256::elliptic_curve::Generate;
        let key = p256::ecdsa::SigningKey::try_generate_from_rng(&mut rand::rngs::SysRng)
            .map_err(random_error)?;
        Ok(Self {
            inner: SigningInner::Ec(key),
            kid: None,
        })
    }

    /// Generates an RSA key (RS256) with public exponent 65537.
    pub fn generate_rsa(size: RsaKeySize) -> Result<Self, JoseError> {
        let key =
            rsa::PrivateKey::new(&mut rand::rngs::SysRng, size.bits()).map_err(random_error)?;
        Ok(Self {
            inner: SigningInner::Rsa(key),
            kid: None,
        })
    }

    /// Reads a PKCS#8 `PRIVATE KEY` PEM block (RSA 2048 to 4096 bits, or P-256).
    pub fn from_pkcs8_pem(pem: &Secret<String>) -> Result<Self, JoseError> {
        let der = pem_to_der(pem.expose_secret_ref(), "PRIVATE KEY", "expected pkcs8")?;
        Self::from_der_bytes(&der)
    }

    /// Reads a PKCS#8 DER private key (RSA 2048 to 4096 bits, or P-256).
    pub fn from_pkcs8_der(der: &Secret<Vec<u8>>) -> Result<Self, JoseError> {
        Self::from_der_bytes(der.expose_secret_ref())
    }

    fn from_der_bytes(der: &[u8]) -> Result<Self, JoseError> {
        let info = PrivateKeyInfoRef::try_from(der).map_err(|_| JoseError::InvalidKey("der"))?;
        let inner = match key_kind(&info.algorithm)? {
            KeyKind::Rsa => {
                let key = rsa::PrivateKey::from_pkcs8_der(der)
                    .map_err(|_| JoseError::InvalidKey("der"))?;
                check_rsa_public(&key)?;
                SigningInner::Rsa(key)
            }
            KeyKind::Ec => SigningInner::Ec(
                p256::ecdsa::SigningKey::from_pkcs8_der(der)
                    .map_err(|_| JoseError::InvalidKey("der"))?,
            ),
        };
        Ok(Self { inner, kid: None })
    }

    /// Writes the key as a PKCS#8 `PRIVATE KEY` PEM block.
    pub fn to_pkcs8_pem(&self) -> Result<Secret<String>, JoseError> {
        let result = match &self.inner {
            SigningInner::Rsa(k) => k.to_pkcs8_pem(LineEnding::LF),
            SigningInner::Ec(k) => k.to_pkcs8_pem(LineEnding::LF),
        };
        let mut pem = result.map_err(|_| JoseError::Encoding("pkcs8"))?;
        Ok(Secret::new(std::mem::take(&mut *pem)))
    }

    /// Writes the key as PKCS#8 DER.
    pub fn to_pkcs8_der(&self) -> Result<Secret<Vec<u8>>, JoseError> {
        let document = match &self.inner {
            SigningInner::Rsa(k) => k.to_pkcs8_der(),
            SigningInner::Ec(k) => k.to_pkcs8_der(),
        }
        .map_err(|_| JoseError::Encoding("pkcs8"))?;
        // `SecretDocument` only hands out a copy (`to_bytes`, zeroized on drop) and zeroizes its
        // own buffer on drop, so one copy is unavoidable; it is moved, not copied, into `Secret`.
        let mut bytes = document.to_bytes();
        Ok(Secret::new(std::mem::take(&mut *bytes)))
    }

    /// Sets the key ID.
    pub fn with_kid(mut self, kid: Kid) -> Self {
        self.kid = Some(kid);
        self
    }

    /// The key ID, if any.
    pub fn kid(&self) -> Option<&Kid> {
        self.kid.as_ref()
    }

    /// The signature algorithm of this key.
    pub fn algorithm(&self) -> Algorithm {
        match self.inner {
            SigningInner::Rsa(_) => Algorithm::Rs256,
            SigningInner::Ec(_) => Algorithm::Es256,
        }
    }

    /// The matching public key, with the same key ID.
    pub fn verifying_key(&self) -> VerifyingKey {
        let inner = match &self.inner {
            SigningInner::Rsa(k) => VerifyingInner::Rsa(k.to_public_key()),
            SigningInner::Ec(k) => VerifyingInner::Ec(*k.verifying_key()),
        };
        VerifyingKey {
            inner,
            kid: self.kid.clone(),
        }
    }

    /// Signs `message` (the JWS signing input) with the algorithm of the key.
    pub(crate) fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>, JoseError> {
        match &self.inner {
            SigningInner::Rsa(k) => k
                .pkcs1v15_sign::<Sha256>(message)
                .map_err(|_| JoseError::Encoding("signature")),
            SigningInner::Ec(k) => {
                use p256::ecdsa::signature::Signer;
                let signature: p256::ecdsa::Signature = k
                    .try_sign(message)
                    .map_err(|_| JoseError::Encoding("signature"))?;
                Ok(signature.to_bytes().to_vec())
            }
        }
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("alg", &format_args!("{}", self.algorithm()))
            .field("kid", &self.kid.as_ref().map(Kid::as_inner))
            .finish_non_exhaustive()
    }
}

impl VerifyingKey {
    /// Reads a SPKI `PUBLIC KEY` PEM block (RSA 2048 to 4096 bits, or P-256).
    pub fn from_spki_pem(pem: &str) -> Result<Self, JoseError> {
        let der = pem_to_der(pem, "PUBLIC KEY", "expected spki")?;
        Self::from_spki_der(&der)
    }

    /// Reads a SPKI DER public key (RSA 2048 to 4096 bits, or P-256).
    pub fn from_spki_der(der: &[u8]) -> Result<Self, JoseError> {
        let info =
            SubjectPublicKeyInfoRef::try_from(der).map_err(|_| JoseError::InvalidKey("der"))?;
        let inner = match key_kind(&info.algorithm)? {
            KeyKind::Rsa => {
                let key = rsa::PublicKey::from_public_key_der(der)
                    .map_err(|_| JoseError::InvalidKey("der"))?;
                check_rsa_public(&key)?;
                VerifyingInner::Rsa(key)
            }
            KeyKind::Ec => VerifyingInner::Ec(
                p256::ecdsa::VerifyingKey::from_public_key_der(der)
                    .map_err(|_| JoseError::InvalidKey("der"))?,
            ),
        };
        Ok(Self { inner, kid: None })
    }

    /// Writes the key as a SPKI `PUBLIC KEY` PEM block.
    pub fn to_spki_pem(&self) -> Result<String, JoseError> {
        match &self.inner {
            VerifyingInner::Rsa(k) => k.to_public_key_pem(LineEnding::LF),
            VerifyingInner::Ec(k) => k.to_public_key_pem(LineEnding::LF),
        }
        .map_err(|_| JoseError::Encoding("spki"))
    }

    /// Writes the key as SPKI DER.
    pub fn to_spki_der(&self) -> Result<Vec<u8>, JoseError> {
        let document = match &self.inner {
            VerifyingInner::Rsa(k) => k.to_public_key_der(),
            VerifyingInner::Ec(k) => k.to_public_key_der(),
        }
        .map_err(|_| JoseError::Encoding("spki"))?;
        Ok(document.as_bytes().to_vec())
    }

    /// Sets the key ID.
    pub fn with_kid(mut self, kid: Kid) -> Self {
        self.kid = Some(kid);
        self
    }

    /// The key ID, if any.
    pub fn kid(&self) -> Option<&Kid> {
        self.kid.as_ref()
    }

    /// The signature algorithm of this key.
    pub fn algorithm(&self) -> Algorithm {
        match self.inner {
            VerifyingInner::Rsa(_) => Algorithm::Rs256,
            VerifyingInner::Ec(_) => Algorithm::Es256,
        }
    }

    /// Verifies `signature` over `message` (the JWS signing input).
    pub(crate) fn verify_raw(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError> {
        match &self.inner {
            VerifyingInner::Rsa(k) => {
                if signature.len() != k.size() {
                    return Err(JoseError::InvalidSignature);
                }
                k.pkcs1v15_verify::<Sha256>(message, signature)
                    .map_err(|_| JoseError::InvalidSignature)
            }
            VerifyingInner::Ec(k) => {
                use p256::ecdsa::signature::Verifier;
                let signature = p256::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| JoseError::InvalidSignature)?;
                k.verify(message, &signature)
                    .map_err(|_| JoseError::InvalidSignature)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RSA_PEM: &str = include_str!("../tests/fixtures/rsa2048.pem");
    const RSA_PUB_PEM: &str = include_str!("../tests/fixtures/rsa2048.pub.pem");
    const ES_PEM: &str = include_str!("../tests/fixtures/es256.pem");
    const ES_PUB_PEM: &str = include_str!("../tests/fixtures/es256.pub.pem");

    fn secret(pem: &str) -> Secret<String> {
        Secret::new(pem.to_owned())
    }

    fn private(pem: &str) -> Result<SigningKey, JoseError> {
        SigningKey::from_pkcs8_pem(&secret(pem))
    }

    fn assert_signs(key: &SigningKey, public: &VerifyingKey) {
        let signature = key.sign_raw(b"message").unwrap();
        assert_eq!(public.verify_raw(b"message", &signature), Ok(()));
        assert_eq!(
            public.verify_raw(b"other", &signature),
            Err(JoseError::InvalidSignature)
        );
    }

    #[test]
    fn generates_es256() {
        let key = SigningKey::generate_es256().unwrap();
        assert_eq!(key.algorithm(), Algorithm::Es256);
        assert!(key.kid().is_none());
        assert_signs(&key, &key.verifying_key());
    }

    #[test]
    fn generates_rsa_2048() {
        let key = SigningKey::generate_rsa(RsaKeySize::Bits2048).unwrap();
        assert_eq!(key.algorithm(), Algorithm::Rs256);
        assert_signs(&key, &key.verifying_key());
    }

    #[test]
    #[ignore = "slow: generates RSA 3072 and 4096 bit keys"]
    fn generates_large_rsa() {
        for size in [RsaKeySize::Bits3072, RsaKeySize::Bits4096] {
            let key = SigningKey::generate_rsa(size).unwrap();
            let public = key.verifying_key();
            let VerifyingInner::Rsa(rsa_public) = &public.inner else {
                panic!("not rsa");
            };
            assert_eq!(rsa_public.n().bit_width_vartime() as usize, size.bits());
            assert_signs(&key, &public);
        }
    }

    #[test]
    fn pkcs8_and_spki_round_trip() {
        for key in [
            SigningKey::generate_es256().unwrap(),
            private(RSA_PEM).unwrap(),
        ] {
            let pem = key.to_pkcs8_pem().unwrap();
            assert!(
                pem.expose_secret_ref()
                    .starts_with("-----BEGIN PRIVATE KEY-----")
            );
            let from_pem = SigningKey::from_pkcs8_pem(&pem).unwrap();
            let from_der = SigningKey::from_pkcs8_der(&key.to_pkcs8_der().unwrap()).unwrap();

            let public = key.verifying_key();
            let spki_pem = public.to_spki_pem().unwrap();
            assert!(spki_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
            let public_from_pem = VerifyingKey::from_spki_pem(&spki_pem).unwrap();
            let public_from_der =
                VerifyingKey::from_spki_der(&public.to_spki_der().unwrap()).unwrap();
            assert_eq!(public_from_pem, public);
            assert_eq!(public_from_der, public);

            let signature = key.sign_raw(b"m").unwrap();
            assert_eq!(public_from_pem.verify_raw(b"m", &signature), Ok(()));
            assert_signs(&from_pem, &public_from_der);
            assert_signs(&from_der, &public_from_pem);
            assert_eq!(from_pem.algorithm(), key.algorithm());
        }
    }

    #[test]
    fn fixture_public_keys_match_private_keys() {
        for (private_pem, public_pem) in [(RSA_PEM, RSA_PUB_PEM), (ES_PEM, ES_PUB_PEM)] {
            let key = private(private_pem).unwrap();
            let public = VerifyingKey::from_spki_pem(public_pem).unwrap();
            assert_eq!(key.verifying_key(), public);
            assert_signs(&key, &public);
        }
    }

    #[test]
    fn pem_whitespace_is_trimmed() {
        assert!(private(&format!("\n  {RSA_PEM}\n\n")).is_ok());
        assert!(VerifyingKey::from_spki_pem(&format!(" \r\n{ES_PUB_PEM}\r\n ")).is_ok());
    }

    #[test]
    fn rejects_unreadable_pem_and_der() {
        assert_eq!(private("not pem").err(), Some(JoseError::InvalidKey("pem")));
        assert_eq!(private("").err(), Some(JoseError::InvalidKey("pem")));
        assert_eq!(
            VerifyingKey::from_spki_pem("not pem").err(),
            Some(JoseError::InvalidKey("pem"))
        );
        let bad_der = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        assert_eq!(private(bad_der).err(), Some(JoseError::InvalidKey("der")));
        let bad_spki = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n";
        assert_eq!(
            VerifyingKey::from_spki_pem(bad_spki).err(),
            Some(JoseError::InvalidKey("der"))
        );
        assert_eq!(
            SigningKey::from_pkcs8_der(&Secret::new(vec![1, 2, 3])).err(),
            Some(JoseError::InvalidKey("der"))
        );
        assert_eq!(
            VerifyingKey::from_spki_der(&[]).err(),
            Some(JoseError::InvalidKey("der"))
        );
    }

    #[test]
    fn rejects_other_pem_labels() {
        let pkcs8 = JoseError::InvalidKey("expected pkcs8");
        assert_eq!(
            private(include_str!("../tests/fixtures/rsa2048.pkcs1.pem")).err(),
            Some(pkcs8.clone())
        );
        assert_eq!(
            private(include_str!("../tests/fixtures/rsa2048.enc.pem")).err(),
            Some(pkcs8.clone())
        );
        // A public key is not a private key, and the other way around.
        assert_eq!(private(RSA_PUB_PEM).err(), Some(pkcs8));
        let spki = JoseError::InvalidKey("expected spki");
        assert_eq!(
            VerifyingKey::from_spki_pem(include_str!("../tests/fixtures/rsa2048.pkcs1.pub.pem"))
                .err(),
            Some(spki.clone())
        );
        assert_eq!(VerifyingKey::from_spki_pem(RSA_PEM).err(), Some(spki));
    }

    #[test]
    fn rejects_unsupported_key_types() {
        let unsupported = JoseError::InvalidKey("unsupported key type");
        assert_eq!(
            private(include_str!("../tests/fixtures/es384.pem")).err(),
            Some(unsupported.clone())
        );
        assert_eq!(
            private(include_str!("../tests/fixtures/rsa-pss.pem")).err(),
            Some(unsupported.clone())
        );
        assert_eq!(
            VerifyingKey::from_spki_pem(include_str!("../tests/fixtures/es384.pub.pem")).err(),
            Some(unsupported)
        );
    }

    #[test]
    fn rejects_rsa_modulus_outside_2048_to_4096() {
        let size = JoseError::InvalidKey("rsa modulus size");
        assert_eq!(
            private(include_str!("../tests/fixtures/rsa1024.pem")).err(),
            Some(size.clone())
        );
        assert_eq!(
            VerifyingKey::from_spki_pem(include_str!("../tests/fixtures/rsa1024.pub.pem")).err(),
            Some(size.clone())
        );
        assert_eq!(
            VerifyingKey::from_spki_pem(include_str!("../tests/fixtures/rsa8192.pub.pem")).err(),
            Some(size)
        );
    }

    #[test]
    fn rsa_exponent_rules() {
        let e = |v: u64| check_rsa_exponent(&BoxedUint::from(v));
        for ok in [3, 5, 17, 65537, (1 << 33) - 1] {
            assert_eq!(e(ok), Ok(()), "{ok}");
        }
        for bad in [0, 1, 2, 4, 65536, 1 << 33, (1 << 33) + 1, u64::MAX] {
            assert_eq!(e(bad), Err(JoseError::InvalidKey("rsa e")), "{bad}");
        }
        // Wider than 64 bits.
        let wide = BoxedUint::from_be_slice_vartime(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            check_rsa_exponent(&wide),
            Err(JoseError::InvalidKey("rsa e"))
        );
    }

    #[test]
    fn signature_of_the_wrong_length_is_invalid() {
        for key in [private(RSA_PEM).unwrap(), private(ES_PEM).unwrap()] {
            let public = key.verifying_key();
            let mut signature = key.sign_raw(b"m").unwrap();
            signature.pop();
            assert_eq!(
                public.verify_raw(b"m", &signature),
                Err(JoseError::InvalidSignature)
            );
            signature.extend([0, 0]);
            assert_eq!(
                public.verify_raw(b"m", &signature),
                Err(JoseError::InvalidSignature)
            );
            assert_eq!(
                public.verify_raw(b"m", &[]),
                Err(JoseError::InvalidSignature)
            );
        }
    }

    #[test]
    fn es256_signature_is_64_bytes_and_rejects_zero_scalars() {
        let key = private(ES_PEM).unwrap();
        assert_eq!(key.sign_raw(b"m").unwrap().len(), 64);
        assert_eq!(
            key.verifying_key().verify_raw(b"m", &[0; 64]),
            Err(JoseError::InvalidSignature)
        );
    }

    #[test]
    fn debug_shows_no_key_material() {
        let kid = Kid::try_new("k1".to_owned()).unwrap();
        for (pem, alg) in [(ES_PEM, "ES256"), (RSA_PEM, "RS256")] {
            let key = private(pem).unwrap().with_kid(kid.clone());
            assert_eq!(
                format!("{key:?}"),
                format!("SigningKey {{ alg: {alg}, kid: Some(\"k1\"), .. }}")
            );
            assert_eq!(
                format!("{:?}", private(pem).unwrap()),
                format!("SigningKey {{ alg: {alg}, kid: None, .. }}")
            );
            let body: String = pem.lines().nth(1).unwrap().to_owned();
            assert!(!format!("{key:#?}").contains(&body));
        }
    }

    #[test]
    fn kid_is_carried_to_the_verifying_key() {
        let kid = Kid::try_new("k1".to_owned()).unwrap();
        let key = private(ES_PEM).unwrap().with_kid(kid.clone());
        assert_eq!(key.kid(), Some(&kid));
        assert_eq!(key.verifying_key().kid(), Some(&kid));
        let public = VerifyingKey::from_spki_pem(ES_PUB_PEM).unwrap();
        assert!(public.kid().is_none());
        assert_ne!(public.clone().with_kid(kid.clone()), public);
        assert_eq!(public.clone().with_kid(kid.clone()).kid(), Some(&kid));
    }
}
