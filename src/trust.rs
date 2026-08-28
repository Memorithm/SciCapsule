use crate::signature::{
    verify_capsule_signature_with_public_key_bytes, SignatureEnvelope, SIGNATURE_ALGORITHM,
};
use ed25519_dalek::{pkcs8::DecodePublicKey, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

pub const TRUST_POLICY_VERSION: u32 = 1;
pub const MAX_TRUSTED_KEYS: usize = 64;
pub const MAX_SIGNATURES: usize = 64;
const MAX_KEY_NAME_BYTES: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedKey {
    pub name: String,
    pub public_key: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPolicy {
    pub version: u32,
    pub algorithm: String,
    pub minimum_signatures: u32,
    pub trusted_keys: Vec<TrustedKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustDecision {
    pub required_signatures: u32,
    pub matched_signers: Vec<String>,
}

impl TrustPolicy {
    pub fn from_json(encoded: &[u8]) -> Result<Self, TrustPolicyError> {
        let policy: Self = serde_json::from_slice(encoded).map_err(|error| {
            TrustPolicyError::new(format!("invalid trust policy JSON: {error}"))
        })?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn to_json(&self) -> Result<Vec<u8>, TrustPolicyError> {
        self.validate()?;
        let mut encoded = serde_json::to_vec_pretty(self).map_err(|error| {
            TrustPolicyError::new(format!("cannot serialize trust policy: {error}"))
        })?;
        encoded.push(b'\n');
        Ok(encoded)
    }

    pub fn from_named_pem_keys(
        minimum_signatures: u32,
        keys: Vec<(String, String)>,
    ) -> Result<Self, TrustPolicyError> {
        let mut trusted_keys = Vec::with_capacity(keys.len());
        for (name, pem) in keys {
            let verifying_key = VerifyingKey::from_public_key_pem(&pem).map_err(|_| {
                TrustPolicyError::new(format!("invalid Ed25519 SPKI public key PEM for {name:?}"))
            })?;
            trusted_keys.push(TrustedKey {
                name,
                public_key: verifying_key.to_bytes().to_vec(),
            });
        }

        let policy = Self {
            version: TRUST_POLICY_VERSION,
            algorithm: SIGNATURE_ALGORITHM.to_owned(),
            minimum_signatures,
            trusted_keys,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn verify(
        &self,
        capsule_bytes: &[u8],
        signatures: &[SignatureEnvelope],
    ) -> Result<TrustDecision, TrustPolicyError> {
        self.validate()?;
        validate_signature_count(signatures.len())?;

        let mut matched_signers = Vec::new();
        for trusted_key in &self.trusted_keys {
            let matched = signatures.iter().any(|signature| {
                verify_capsule_signature_with_public_key_bytes(
                    capsule_bytes,
                    signature,
                    &trusted_key.public_key,
                )
                .is_ok()
            });
            if matched {
                matched_signers.push(trusted_key.name.clone());
            }
        }
        self.finish_decision(matched_signers)
    }

    /// Apply this policy's distinct-key threshold to raw Ed25519 signatures.
    ///
    /// `keyid` hints are intentionally absent from this interface. Callers pass
    /// the exact authenticated message and signature bytes; every configured
    /// trust anchor is tried and a given trusted key counts at most once.
    pub fn verify_raw_ed25519_signatures(
        &self,
        message: &[u8],
        signatures: &[Vec<u8>],
    ) -> Result<TrustDecision, TrustPolicyError> {
        self.validate()?;
        validate_signature_count(signatures.len())?;
        for signature in signatures {
            if signature.len() != ed25519_dalek::SIGNATURE_LENGTH {
                return Err(TrustPolicyError::new(format!(
                    "invalid Ed25519 signature length {}; expected {} bytes",
                    signature.len(),
                    ed25519_dalek::SIGNATURE_LENGTH
                )));
            }
        }

        let mut matched_signers = Vec::new();
        for trusted_key in &self.trusted_keys {
            let key_bytes: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] =
                trusted_key.public_key.as_slice().try_into().map_err(|_| {
                    TrustPolicyError::new("invalid trusted Ed25519 public key length")
                })?;
            let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
                TrustPolicyError::new(format!(
                    "trusted key {:?} is not a valid Ed25519 key",
                    trusted_key.name
                ))
            })?;
            let matched = signatures.iter().any(|bytes| {
                Signature::try_from(bytes.as_slice())
                    .ok()
                    .is_some_and(|signature| {
                        verifying_key.verify_strict(message, &signature).is_ok()
                    })
            });
            if matched {
                matched_signers.push(trusted_key.name.clone());
            }
        }
        self.finish_decision(matched_signers)
    }

    fn finish_decision(
        &self,
        matched_signers: Vec<String>,
    ) -> Result<TrustDecision, TrustPolicyError> {
        if matched_signers.len() < self.minimum_signatures as usize {
            return Err(TrustPolicyError::new(format!(
                "trust threshold not met: matched {} distinct trusted key(s), require {}",
                matched_signers.len(),
                self.minimum_signatures
            )));
        }

        Ok(TrustDecision {
            required_signatures: self.minimum_signatures,
            matched_signers,
        })
    }

    fn validate(&self) -> Result<(), TrustPolicyError> {
        if self.version != TRUST_POLICY_VERSION {
            return Err(TrustPolicyError::new(format!(
                "unsupported trust policy version {}; expected {}",
                self.version, TRUST_POLICY_VERSION
            )));
        }
        if self.algorithm != SIGNATURE_ALGORITHM {
            return Err(TrustPolicyError::new(format!(
                "unsupported trust policy algorithm {:?}; expected {:?}",
                self.algorithm, SIGNATURE_ALGORITHM
            )));
        }
        if self.trusted_keys.is_empty() {
            return Err(TrustPolicyError::new(
                "trust policy must contain at least one trusted key",
            ));
        }
        if self.trusted_keys.len() > MAX_TRUSTED_KEYS {
            return Err(TrustPolicyError::new(format!(
                "too many trusted keys: {}; limit is {}",
                self.trusted_keys.len(),
                MAX_TRUSTED_KEYS
            )));
        }
        if self.minimum_signatures == 0 {
            return Err(TrustPolicyError::new(
                "minimum_signatures must be at least 1",
            ));
        }
        if self.minimum_signatures as usize > self.trusted_keys.len() {
            return Err(TrustPolicyError::new(format!(
                "minimum_signatures {} exceeds trusted key count {}",
                self.minimum_signatures,
                self.trusted_keys.len()
            )));
        }

        let mut names = BTreeSet::new();
        let mut public_keys = BTreeSet::new();
        for key in &self.trusted_keys {
            validate_key_name(&key.name)?;
            if !names.insert(key.name.clone()) {
                return Err(TrustPolicyError::new(format!(
                    "duplicate trusted key name {:?}",
                    key.name
                )));
            }
            if key.public_key.len() != ed25519_dalek::PUBLIC_KEY_LENGTH {
                return Err(TrustPolicyError::new(format!(
                    "trusted key {:?} has invalid Ed25519 public key length {}; expected {} bytes",
                    key.name,
                    key.public_key.len(),
                    ed25519_dalek::PUBLIC_KEY_LENGTH
                )));
            }
            let key_bytes: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = key
                .public_key
                .as_slice()
                .try_into()
                .map_err(|_| TrustPolicyError::new("invalid Ed25519 public key length"))?;
            VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
                TrustPolicyError::new(format!(
                    "trusted key {:?} is not a valid Ed25519 key",
                    key.name
                ))
            })?;
            if !public_keys.insert(key.public_key.clone()) {
                return Err(TrustPolicyError::new(
                    "duplicate Ed25519 public key in trust policy",
                ));
            }
        }
        Ok(())
    }
}

fn validate_signature_count(count: usize) -> Result<(), TrustPolicyError> {
    if count == 0 {
        return Err(TrustPolicyError::new(
            "trust verification requires at least one signature",
        ));
    }
    if count > MAX_SIGNATURES {
        return Err(TrustPolicyError::new(format!(
            "too many signatures: {count}; limit is {MAX_SIGNATURES}"
        )));
    }
    Ok(())
}

fn validate_key_name(name: &str) -> Result<(), TrustPolicyError> {
    if name.is_empty() {
        return Err(TrustPolicyError::new("trusted key name must not be empty"));
    }
    if name.len() > MAX_KEY_NAME_BYTES {
        return Err(TrustPolicyError::new(format!(
            "trusted key name is {} bytes; limit is {} bytes",
            name.len(),
            MAX_KEY_NAME_BYTES
        )));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(TrustPolicyError::new(format!(
            "trusted key name {:?} contains unsupported characters",
            name
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustPolicyError {
    message: String,
}

impl TrustPolicyError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for TrustPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for TrustPolicyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::sign_capsule;
    use ed25519_dalek::{pkcs8::EncodePublicKey, Signer, SigningKey};
    use pkcs8::LineEnding;

    fn public_pem(seed: u8) -> String {
        SigningKey::from_bytes(&[seed; ed25519_dalek::SECRET_KEY_LENGTH])
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap()
    }

    fn private_pem(seed: u8) -> String {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        SigningKey::from_bytes(&[seed; ed25519_dalek::SECRET_KEY_LENGTH])
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string()
    }

    #[test]
    fn policy_round_trip_is_versioned_and_strict() {
        let policy =
            TrustPolicy::from_named_pem_keys(1, vec![("release".to_owned(), public_pem(1))])
                .unwrap();
        let encoded = policy.to_json().unwrap();
        assert_eq!(TrustPolicy::from_json(&encoded).unwrap(), policy);

        let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        value["extra"] = serde_json::Value::Bool(true);
        assert!(TrustPolicy::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn threshold_counts_distinct_trusted_keys_only_once() {
        let capsule = b"canonical capsule bytes";
        let policy = TrustPolicy::from_named_pem_keys(
            2,
            vec![
                ("alpha".to_owned(), public_pem(2)),
                ("beta".to_owned(), public_pem(3)),
            ],
        )
        .unwrap();
        let alpha = sign_capsule(capsule, &private_pem(2)).unwrap();
        let beta = sign_capsule(capsule, &private_pem(3)).unwrap();

        let duplicate_alpha = vec![alpha.clone(), alpha];
        assert!(policy.verify(capsule, &duplicate_alpha).is_err());

        let decision = policy
            .verify(
                capsule,
                &[
                    beta.clone(),
                    beta,
                    sign_capsule(capsule, &private_pem(2)).unwrap(),
                ],
            )
            .unwrap();
        assert_eq!(decision.required_signatures, 2);
        assert_eq!(decision.matched_signers, vec!["alpha", "beta"]);
    }

    #[test]
    fn raw_signature_threshold_counts_each_key_once() {
        let policy = TrustPolicy::from_named_pem_keys(
            2,
            vec![
                ("alpha".to_owned(), public_pem(10)),
                ("beta".to_owned(), public_pem(11)),
            ],
        )
        .unwrap();
        let message = b"authenticated statement bytes";
        let alpha_key = SigningKey::from_bytes(&[10; ed25519_dalek::SECRET_KEY_LENGTH]);
        let beta_key = SigningKey::from_bytes(&[11; ed25519_dalek::SECRET_KEY_LENGTH]);
        let alpha = alpha_key.sign(message).to_bytes().to_vec();
        let beta = beta_key.sign(message).to_bytes().to_vec();

        assert!(policy
            .verify_raw_ed25519_signatures(message, &[alpha.clone(), alpha])
            .is_err());
        let decision = policy
            .verify_raw_ed25519_signatures(
                message,
                &[beta, alpha_key.sign(message).to_bytes().to_vec()],
            )
            .unwrap();
        assert_eq!(decision.matched_signers, vec!["alpha", "beta"]);
    }

    #[test]
    fn unknown_signer_and_tampering_do_not_satisfy_policy() {
        let capsule = b"canonical capsule bytes";
        let policy =
            TrustPolicy::from_named_pem_keys(1, vec![("release".to_owned(), public_pem(4))])
                .unwrap();
        let unknown = sign_capsule(capsule, &private_pem(5)).unwrap();
        assert!(policy.verify(capsule, &[unknown]).is_err());

        let trusted = sign_capsule(capsule, &private_pem(4)).unwrap();
        assert!(policy.verify(b"tampered", &[trusted]).is_err());
    }

    #[test]
    fn malformed_threshold_duplicates_and_names_fail_closed() {
        assert!(
            TrustPolicy::from_named_pem_keys(0, vec![("release".to_owned(), public_pem(6))])
                .is_err()
        );
        assert!(
            TrustPolicy::from_named_pem_keys(2, vec![("release".to_owned(), public_pem(6))])
                .is_err()
        );
        assert!(TrustPolicy::from_named_pem_keys(
            1,
            vec![
                ("same".to_owned(), public_pem(6)),
                ("same".to_owned(), public_pem(7)),
            ],
        )
        .is_err());
        assert!(TrustPolicy::from_named_pem_keys(
            1,
            vec![
                ("one".to_owned(), public_pem(8)),
                ("two".to_owned(), public_pem(8)),
            ],
        )
        .is_err());
        assert!(
            TrustPolicy::from_named_pem_keys(1, vec![("bad name".to_owned(), public_pem(9))],)
                .is_err()
        );
    }
}
