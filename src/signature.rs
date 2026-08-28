use ed25519_dalek::{
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    Signature, Signer, SigningKey, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Current detached signature envelope version.
pub const SIGNATURE_ENVELOPE_VERSION: u32 = 1;

/// Signature primitive used by envelope version 1.
pub const SIGNATURE_ALGORITHM: &str = "ed25519";

/// Domain separation for signatures produced by SciCapsule.
const SIGNING_DOMAIN: &[u8] = b"SciCapsule detached signature v1\0";

/// Versioned, detached signature metadata.
///
/// The public key is intentionally not embedded. Verification therefore requires
/// an explicit key supplied by the caller instead of treating signer-controlled
/// key material as trusted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEnvelope {
    pub version: u32,
    pub algorithm: String,
    pub signature: Vec<u8>,
}

impl SignatureEnvelope {
    /// Parse and structurally validate an envelope.
    pub fn from_json(encoded: &[u8]) -> Result<Self, SignatureModelError> {
        let envelope: Self = serde_json::from_slice(encoded).map_err(|error| {
            SignatureModelError::new(format!("invalid signature envelope JSON: {error}"))
        })?;
        envelope.validate()?;
        Ok(envelope)
    }

    /// Serialize an envelope as deterministic, human-readable JSON.
    pub fn to_json(&self) -> Result<Vec<u8>, SignatureModelError> {
        self.validate()?;
        let mut encoded = serde_json::to_vec_pretty(self).map_err(|error| {
            SignatureModelError::new(format!("cannot serialize signature envelope: {error}"))
        })?;
        encoded.push(b'\n');
        Ok(encoded)
    }

    fn validate(&self) -> Result<(), SignatureModelError> {
        if self.version != SIGNATURE_ENVELOPE_VERSION {
            return Err(SignatureModelError::new(format!(
                "unsupported signature envelope version {}; expected {}",
                self.version, SIGNATURE_ENVELOPE_VERSION
            )));
        }
        if self.algorithm != SIGNATURE_ALGORITHM {
            return Err(SignatureModelError::new(format!(
                "unsupported signature algorithm {:?}; expected {:?}",
                self.algorithm, SIGNATURE_ALGORITHM
            )));
        }
        if self.signature.len() != ed25519_dalek::SIGNATURE_LENGTH {
            return Err(SignatureModelError::new(format!(
                "invalid Ed25519 signature length {}; expected {} bytes",
                self.signature.len(),
                ed25519_dalek::SIGNATURE_LENGTH
            )));
        }
        Ok(())
    }
}

/// Sign the exact canonical capsule bytes with an Ed25519 PKCS#8 PEM private key.
pub fn sign_capsule(
    capsule_bytes: &[u8],
    private_key_pem: &str,
) -> Result<SignatureEnvelope, SignatureModelError> {
    let signing_key = SigningKey::from_pkcs8_pem(private_key_pem)
        .map_err(|_| SignatureModelError::new("invalid Ed25519 PKCS#8 private key PEM"))?;
    let message = signing_message(capsule_bytes);
    let signature: Signature = signing_key.sign(&message);

    Ok(SignatureEnvelope {
        version: SIGNATURE_ENVELOPE_VERSION,
        algorithm: SIGNATURE_ALGORITHM.to_owned(),
        signature: signature.to_bytes().to_vec(),
    })
}

/// Verify a detached envelope using an explicitly supplied Ed25519 SPKI PEM public key.
pub fn verify_capsule_signature(
    capsule_bytes: &[u8],
    envelope: &SignatureEnvelope,
    public_key_pem: &str,
) -> Result<(), SignatureModelError> {
    envelope.validate()?;
    let verifying_key = VerifyingKey::from_public_key_pem(public_key_pem)
        .map_err(|_| SignatureModelError::new("invalid Ed25519 SPKI public key PEM"))?;
    let signature = Signature::try_from(envelope.signature.as_slice())
        .map_err(|_| SignatureModelError::new("invalid Ed25519 signature bytes"))?;
    let message = signing_message(capsule_bytes);
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| SignatureModelError::new("Ed25519 signature verification failed"))
}

fn signing_message(capsule_bytes: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNING_DOMAIN.len().saturating_add(capsule_bytes.len()));
    message.extend_from_slice(SIGNING_DOMAIN);
    message.extend_from_slice(capsule_bytes);
    message
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureModelError {
    message: String,
}

impl SignatureModelError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for SignatureModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SignatureModelError {}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use pkcs8::LineEnding;

    fn test_keys(seed: u8) -> (String, String) {
        let signing_key = SigningKey::from_bytes(&[seed; ed25519_dalek::SECRET_KEY_LENGTH]);
        let private_key = signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string();
        let public_key = signing_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        (private_key, public_key)
    }

    #[test]
    fn envelope_round_trip_is_versioned_and_strict() {
        let (private_key, _) = test_keys(7);
        let envelope = sign_capsule(b"capsule", &private_key).unwrap();
        let encoded = envelope.to_json().unwrap();
        let decoded = SignatureEnvelope::from_json(&encoded).unwrap();

        assert_eq!(decoded, envelope);
        assert_eq!(decoded.version, SIGNATURE_ENVELOPE_VERSION);
        assert_eq!(decoded.algorithm, SIGNATURE_ALGORITHM);

        let unknown_field = br#"{"version":1,"algorithm":"ed25519","signature":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"extra":true}"#;
        assert!(SignatureEnvelope::from_json(unknown_field).is_err());
    }

    #[test]
    fn signature_verifies_only_for_exact_capsule_and_key() {
        let (private_key, public_key) = test_keys(11);
        let (_, other_public_key) = test_keys(12);
        let capsule = b"exact canonical capsule bytes";
        let envelope = sign_capsule(capsule, &private_key).unwrap();

        verify_capsule_signature(capsule, &envelope, &public_key).unwrap();
        assert!(verify_capsule_signature(b"tampered", &envelope, &public_key).is_err());
        assert!(verify_capsule_signature(capsule, &envelope, &other_public_key).is_err());
    }

    #[test]
    fn envelope_rejects_unsupported_version_algorithm_and_length() {
        let (private_key, public_key) = test_keys(21);
        let capsule = b"capsule";
        let envelope = sign_capsule(capsule, &private_key).unwrap();

        let mut wrong_version = envelope.clone();
        wrong_version.version += 1;
        assert!(verify_capsule_signature(capsule, &wrong_version, &public_key).is_err());

        let mut wrong_algorithm = envelope.clone();
        wrong_algorithm.algorithm = "other".to_owned();
        assert!(verify_capsule_signature(capsule, &wrong_algorithm, &public_key).is_err());

        let mut wrong_length = envelope;
        wrong_length.signature.pop();
        assert!(verify_capsule_signature(capsule, &wrong_length, &public_key).is_err());
    }

    #[test]
    fn invalid_key_encodings_are_rejected() {
        let (private_key, public_key) = test_keys(31);
        let envelope = sign_capsule(b"capsule", &private_key).unwrap();

        assert!(sign_capsule(b"capsule", "not a private key").is_err());
        assert!(verify_capsule_signature(b"capsule", &envelope, "not a public key").is_err());
        verify_capsule_signature(b"capsule", &envelope, &public_key).unwrap();
    }
}
