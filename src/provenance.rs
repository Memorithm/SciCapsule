use crate::trust::{TrustDecision, TrustPolicy, MAX_SIGNATURES};
use base64ct::{Base64, Encoding};
use ed25519_dalek::{pkcs8::DecodePrivateKey, Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

pub const IN_TOTO_STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";
pub const SLSA_PROVENANCE_V1: &str = "https://slsa.dev/provenance/v1";
pub const DSSE_IN_TOTO_JSON_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
pub const MAX_PROVENANCE_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_TYPE_URI_BYTES: usize = 2048;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResourceDescriptor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default)]
    pub digest: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildDefinition {
    pub build_type: String,
    pub external_parameters: serde_json::Value,
    #[serde(default = "empty_object")]
    pub internal_parameters: serde_json::Value,
    #[serde(default)]
    pub resolved_dependencies: Vec<ResourceDescriptor>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Builder {
    pub id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunDetails {
    pub builder: Builder,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlsaProvenance {
    pub build_definition: BuildDefinition,
    pub run_details: RunDetails,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceStatement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<ResourceDescriptor>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: SlsaProvenance,
}

impl ProvenanceStatement {
    pub fn for_capsule(
        capsule_name: &str,
        capsule_bytes: &[u8],
        builder_id: &str,
        build_type: &str,
        source_uri: &str,
        source_sha256: &str,
    ) -> Result<Self, ProvenanceError> {
        validate_type_uri(builder_id, "builder ID")?;
        validate_type_uri(build_type, "build type")?;
        validate_type_uri(source_uri, "source URI")?;
        let source_sha256 = normalize_sha256(source_sha256, "source SHA-256")?;

        let mut subject_digest = BTreeMap::new();
        subject_digest.insert("sha256".to_owned(), sha256_hex(capsule_bytes));

        let mut source_digest = BTreeMap::new();
        source_digest.insert("sha256".to_owned(), source_sha256);

        let statement = Self {
            statement_type: IN_TOTO_STATEMENT_V1.to_owned(),
            subject: vec![ResourceDescriptor {
                uri: None,
                digest: subject_digest,
                name: Some(capsule_name.to_owned()),
            }],
            predicate_type: SLSA_PROVENANCE_V1.to_owned(),
            predicate: SlsaProvenance {
                build_definition: BuildDefinition {
                    build_type: build_type.to_owned(),
                    external_parameters: empty_object(),
                    internal_parameters: empty_object(),
                    resolved_dependencies: vec![ResourceDescriptor {
                        uri: Some(source_uri.to_owned()),
                        digest: source_digest,
                        name: None,
                    }],
                },
                run_details: RunDetails {
                    builder: Builder {
                        id: builder_id.to_owned(),
                    },
                },
            },
        };
        statement.validate()?;
        Ok(statement)
    }

    pub fn from_json(encoded: &[u8]) -> Result<Self, ProvenanceError> {
        let statement: Self = serde_json::from_slice(encoded).map_err(|error| {
            ProvenanceError::new(format!("invalid in-toto provenance statement JSON: {error}"))
        })?;
        statement.validate()?;
        Ok(statement)
    }

    pub fn to_json(&self) -> Result<Vec<u8>, ProvenanceError> {
        self.validate()?;
        let mut encoded = serde_json::to_vec_pretty(self).map_err(|error| {
            ProvenanceError::new(format!("cannot serialize provenance statement: {error}"))
        })?;
        encoded.push(b'\n');
        if encoded.len() > MAX_PROVENANCE_PAYLOAD_BYTES {
            return Err(ProvenanceError::new(format!(
                "provenance statement is {} bytes; payload limit is {} bytes",
                encoded.len(),
                MAX_PROVENANCE_PAYLOAD_BYTES
            )));
        }
        Ok(encoded)
    }

    pub fn matches_capsule(&self, capsule_bytes: &[u8]) -> bool {
        let expected = sha256_hex(capsule_bytes);
        self.subject.iter().any(|subject| {
            subject
                .digest
                .get("sha256")
                .is_some_and(|actual| actual.eq_ignore_ascii_case(&expected))
        })
    }

    fn validate(&self) -> Result<(), ProvenanceError> {
        if self.statement_type != IN_TOTO_STATEMENT_V1 {
            return Err(ProvenanceError::new(format!(
                "unsupported in-toto statement type {:?}; expected {:?}",
                self.statement_type, IN_TOTO_STATEMENT_V1
            )));
        }
        if self.predicate_type != SLSA_PROVENANCE_V1 {
            return Err(ProvenanceError::new(format!(
                "unsupported provenance predicate type {:?}; expected {:?}",
                self.predicate_type, SLSA_PROVENANCE_V1
            )));
        }
        if self.subject.is_empty() {
            return Err(ProvenanceError::new(
                "provenance statement must contain at least one subject",
            ));
        }
        validate_type_uri(
            &self.predicate.build_definition.build_type,
            "provenance build type",
        )?;
        validate_type_uri(
            &self.predicate.run_details.builder.id,
            "provenance builder ID",
        )?;
        validate_parameters(
            &self.predicate.build_definition.external_parameters,
            "externalParameters",
        )?;
        validate_parameters(
            &self.predicate.build_definition.internal_parameters,
            "internalParameters",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DsseSignature {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyid: Option<String>,
    pub sig: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseEnvelope {
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<DsseSignature>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedProvenance {
    pub statement: ProvenanceStatement,
    pub trust: TrustDecision,
}

impl DsseEnvelope {
    pub fn sign_statement(
        statement_bytes: &[u8],
        private_key_pems: &[String],
    ) -> Result<Self, ProvenanceError> {
        if statement_bytes.is_empty() {
            return Err(ProvenanceError::new(
                "DSSE provenance payload must not be empty",
            ));
        }
        if statement_bytes.len() > MAX_PROVENANCE_PAYLOAD_BYTES {
            return Err(ProvenanceError::new(format!(
                "provenance payload is {} bytes; limit is {} bytes",
                statement_bytes.len(),
                MAX_PROVENANCE_PAYLOAD_BYTES
            )));
        }
        validate_signature_count(private_key_pems.len())?;
        ProvenanceStatement::from_json(statement_bytes)?;

        let authenticated = dsse_pae(DSSE_IN_TOTO_JSON_PAYLOAD_TYPE, statement_bytes);
        let mut signatures = Vec::with_capacity(private_key_pems.len());
        for private_key_pem in private_key_pems {
            let signing_key = SigningKey::from_pkcs8_pem(private_key_pem).map_err(|_| {
                ProvenanceError::new("invalid Ed25519 PKCS#8 private key PEM for provenance")
            })?;
            let signature = signing_key.sign(&authenticated);
            signatures.push(DsseSignature {
                keyid: None,
                sig: Base64::encode_string(&signature.to_bytes()),
            });
        }

        Ok(Self {
            payload_type: DSSE_IN_TOTO_JSON_PAYLOAD_TYPE.to_owned(),
            payload: Base64::encode_string(statement_bytes),
            signatures,
        })
    }

    pub fn from_json(encoded: &[u8]) -> Result<Self, ProvenanceError> {
        serde_json::from_slice(encoded)
            .map_err(|error| ProvenanceError::new(format!("invalid DSSE envelope JSON: {error}")))
    }

    pub fn to_json(&self) -> Result<Vec<u8>, ProvenanceError> {
        self.decode_authenticated_parts()?;
        let mut encoded = serde_json::to_vec_pretty(self)
            .map_err(|error| ProvenanceError::new(format!("cannot serialize DSSE envelope: {error}")))?;
        encoded.push(b'\n');
        Ok(encoded)
    }

    pub fn verify_for_capsule(
        &self,
        capsule_bytes: &[u8],
        policy: &TrustPolicy,
    ) -> Result<VerifiedProvenance, ProvenanceError> {
        let (payload, signatures) = self.decode_authenticated_parts()?;
        let authenticated = dsse_pae(&self.payload_type, &payload);
        let trust = policy
            .verify_raw_ed25519_signatures(&authenticated, &signatures)
            .map_err(|error| {
                ProvenanceError::new(format!("provenance trust verification failed: {error}"))
            })?;

        // DSSE verification deliberately happens before parsing the payload.
        let statement = ProvenanceStatement::from_json(&payload)?;
        if !statement.matches_capsule(capsule_bytes) {
            return Err(ProvenanceError::new(
                "provenance subject SHA-256 does not match the capsule bytes",
            ));
        }

        Ok(VerifiedProvenance { statement, trust })
    }

    fn decode_authenticated_parts(&self) -> Result<(Vec<u8>, Vec<Vec<u8>>), ProvenanceError> {
        if self.payload_type != DSSE_IN_TOTO_JSON_PAYLOAD_TYPE {
            return Err(ProvenanceError::new(format!(
                "unsupported DSSE payloadType {:?}; expected {:?}",
                self.payload_type, DSSE_IN_TOTO_JSON_PAYLOAD_TYPE
            )));
        }
        validate_signature_count(self.signatures.len())?;

        let payload = Base64::decode_vec(&self.payload)
            .map_err(|_| ProvenanceError::new("invalid base64 DSSE payload"))?;
        if payload.is_empty() {
            return Err(ProvenanceError::new("DSSE provenance payload is empty"));
        }
        if payload.len() > MAX_PROVENANCE_PAYLOAD_BYTES {
            return Err(ProvenanceError::new(format!(
                "decoded provenance payload is {} bytes; limit is {} bytes",
                payload.len(),
                MAX_PROVENANCE_PAYLOAD_BYTES
            )));
        }

        let mut signatures = Vec::with_capacity(self.signatures.len());
        for signature in &self.signatures {
            let decoded = Base64::decode_vec(&signature.sig)
                .map_err(|_| ProvenanceError::new("invalid base64 DSSE signature"))?;
            if decoded.len() != ed25519_dalek::SIGNATURE_LENGTH {
                return Err(ProvenanceError::new(format!(
                    "invalid DSSE Ed25519 signature length {}; expected {} bytes",
                    decoded.len(),
                    ed25519_dalek::SIGNATURE_LENGTH
                )));
            }
            signatures.push(decoded);
        }
        Ok((payload, signatures))
    }
}

fn validate_signature_count(count: usize) -> Result<(), ProvenanceError> {
    if count == 0 {
        return Err(ProvenanceError::new(
            "DSSE envelope requires at least one signature",
        ));
    }
    if count > MAX_SIGNATURES {
        return Err(ProvenanceError::new(format!(
            "too many DSSE signatures: {count}; limit is {MAX_SIGNATURES}"
        )));
    }
    Ok(())
}

fn validate_parameters(value: &serde_json::Value, field: &str) -> Result<(), ProvenanceError> {
    if value.is_null() || value.is_object() {
        Ok(())
    } else {
        Err(ProvenanceError::new(format!(
            "SLSA {field} must be a JSON object or null"
        )))
    }
}

fn validate_type_uri(value: &str, label: &str) -> Result<(), ProvenanceError> {
    if value.is_empty() {
        return Err(ProvenanceError::new(format!("{label} must not be empty")));
    }
    if value.len() > MAX_TYPE_URI_BYTES {
        return Err(ProvenanceError::new(format!(
            "{label} is {} bytes; limit is {} bytes",
            value.len(),
            MAX_TYPE_URI_BYTES
        )));
    }
    if !value.is_ascii() || value.bytes().any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control()) {
        return Err(ProvenanceError::new(format!(
            "{label} must be an ASCII URI without whitespace or control characters"
        )));
    }
    let Some((scheme, _)) = value.split_once(':') else {
        return Err(ProvenanceError::new(format!(
            "{label} must be an absolute URI with a scheme"
        )));
    };
    let mut scheme_bytes = scheme.bytes();
    if !scheme_bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        || !scheme_bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return Err(ProvenanceError::new(format!(
            "{label} has an invalid URI scheme"
        )));
    }
    Ok(())
}

fn normalize_sha256(value: &str, label: &str) -> Result<String, ProvenanceError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ProvenanceError::new(format!(
            "{label} must contain exactly 64 hexadecimal characters"
        )));
    }
    Ok(value.to_ascii_lowercase())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn empty_object() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(
        16usize
            .saturating_add(payload_type.len())
            .saturating_add(payload.len()),
    );
    encoded.extend_from_slice(b"DSSEv1 ");
    encoded.extend_from_slice(payload_type.len().to_string().as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload_type.as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload.len().to_string().as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload);
    encoded
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenanceError {
    message: String,
}

impl ProvenanceError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ProvenanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ProvenanceError {}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{
        pkcs8::{EncodePrivateKey, EncodePublicKey},
        SigningKey,
    };
    use pkcs8::LineEnding;

    fn private_pem(seed: u8) -> String {
        SigningKey::from_bytes(&[seed; ed25519_dalek::SECRET_KEY_LENGTH])
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string()
    }

    fn public_pem(seed: u8) -> String {
        SigningKey::from_bytes(&[seed; ed25519_dalek::SECRET_KEY_LENGTH])
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap()
    }

    fn statement(capsule: &[u8]) -> ProvenanceStatement {
        ProvenanceStatement::for_capsule(
            "demo",
            capsule,
            "https://builder.example/v1",
            "https://build.example/scicapsule/v1",
            "https://github.com/example/project",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap()
    }

    #[test]
    fn dsse_pae_matches_the_standard_encoding() {
        assert_eq!(
            dsse_pae("text/plain", b"hello"),
            b"DSSEv1 10 text/plain 5 hello"
        );
    }

    #[test]
    fn generated_statement_binds_capsule_and_explicit_build_inputs() {
        let capsule = b"exact capsule bytes";
        let statement = statement(capsule);
        assert!(statement.matches_capsule(capsule));
        assert!(!statement.matches_capsule(b"different capsule"));
        assert_eq!(statement.statement_type, IN_TOTO_STATEMENT_V1);
        assert_eq!(statement.predicate_type, SLSA_PROVENANCE_V1);
        assert_eq!(
            statement.predicate.run_details.builder.id,
            "https://builder.example/v1"
        );
        assert_eq!(
            statement.predicate.build_definition.resolved_dependencies[0]
                .digest
                .get("sha256")
                .unwrap(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn dsse_verification_uses_distinct_trusted_keys() {
        let capsule = b"exact capsule bytes";
        let payload = statement(capsule).to_json().unwrap();
        let policy = TrustPolicy::from_named_pem_keys(
            2,
            vec![
                ("builder-a".to_owned(), public_pem(1)),
                ("builder-b".to_owned(), public_pem(2)),
            ],
        )
        .unwrap();

        let duplicate = DsseEnvelope::sign_statement(
            &payload,
            &[private_pem(1), private_pem(1)],
        )
        .unwrap();
        assert!(duplicate.verify_for_capsule(capsule, &policy).is_err());

        let envelope =
            DsseEnvelope::sign_statement(&payload, &[private_pem(2), private_pem(1)]).unwrap();
        let verified = envelope.verify_for_capsule(capsule, &policy).unwrap();
        assert_eq!(verified.trust.matched_signers, vec!["builder-a", "builder-b"]);
    }

    #[test]
    fn tampered_payload_and_untrusted_signer_fail() {
        let capsule = b"exact capsule bytes";
        let payload = statement(capsule).to_json().unwrap();
        let policy = TrustPolicy::from_named_pem_keys(
            1,
            vec![("trusted".to_owned(), public_pem(3))],
        )
        .unwrap();

        let untrusted = DsseEnvelope::sign_statement(&payload, &[private_pem(4)]).unwrap();
        assert!(untrusted.verify_for_capsule(capsule, &policy).is_err());

        let mut trusted = DsseEnvelope::sign_statement(&payload, &[private_pem(3)]).unwrap();
        let mut tampered = Base64::decode_vec(&trusted.payload).unwrap();
        tampered.push(b' ');
        trusted.payload = Base64::encode_string(&tampered);
        assert!(trusted.verify_for_capsule(capsule, &policy).is_err());
    }

    #[test]
    fn authenticated_wrong_predicate_and_wrong_subject_fail_after_signature_verification() {
        let capsule = b"exact capsule bytes";
        let policy = TrustPolicy::from_named_pem_keys(
            1,
            vec![("builder".to_owned(), public_pem(5))],
        )
        .unwrap();

        let mut wrong_predicate: serde_json::Value =
            serde_json::from_slice(&statement(capsule).to_json().unwrap()).unwrap();
        wrong_predicate["predicateType"] = serde_json::Value::String("urn:wrong".to_owned());
        let wrong_predicate_bytes = serde_json::to_vec(&wrong_predicate).unwrap();
        let envelope = DsseEnvelope::sign_statement_unchecked_for_test(
            &wrong_predicate_bytes,
            &[private_pem(5)],
        )
        .unwrap();
        assert!(envelope.verify_for_capsule(capsule, &policy).is_err());

        let other_payload = statement(b"other capsule").to_json().unwrap();
        let wrong_subject = DsseEnvelope::sign_statement(&other_payload, &[private_pem(5)]).unwrap();
        let error = wrong_subject.verify_for_capsule(capsule, &policy).unwrap_err();
        assert!(error.to_string().contains("subject SHA-256"));
    }

    #[test]
    fn standard_extension_fields_are_ignored() {
        let capsule = b"exact capsule bytes";
        let policy = TrustPolicy::from_named_pem_keys(
            1,
            vec![("builder".to_owned(), public_pem(6))],
        )
        .unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&statement(capsule).to_json().unwrap()).unwrap();
        value["https://example.com/extension"] = serde_json::json!({"value": true});
        value["predicate"]["https://example.com/predicate-extension"] =
            serde_json::json!("preserved-by-producer");
        let payload = serde_json::to_vec(&value).unwrap();
        let envelope =
            DsseEnvelope::sign_statement_unchecked_for_test(&payload, &[private_pem(6)]).unwrap();
        envelope.verify_for_capsule(capsule, &policy).unwrap();
    }

    #[test]
    fn wrong_payload_type_and_bad_source_digest_are_rejected() {
        let capsule = b"exact capsule bytes";
        let payload = statement(capsule).to_json().unwrap();
        let mut envelope = DsseEnvelope::sign_statement(&payload, &[private_pem(7)]).unwrap();
        envelope.payload_type = "application/json".to_owned();
        assert!(envelope.to_json().is_err());

        assert!(ProvenanceStatement::for_capsule(
            "demo",
            capsule,
            "https://builder.example/v1",
            "https://build.example/v1",
            "https://github.com/example/project",
            "not-a-sha256",
        )
        .is_err());
    }

    impl DsseEnvelope {
        fn sign_statement_unchecked_for_test(
            statement_bytes: &[u8],
            private_key_pems: &[String],
        ) -> Result<Self, ProvenanceError> {
            validate_signature_count(private_key_pems.len())?;
            let authenticated = dsse_pae(DSSE_IN_TOTO_JSON_PAYLOAD_TYPE, statement_bytes);
            let mut signatures = Vec::with_capacity(private_key_pems.len());
            for private_key_pem in private_key_pems {
                let signing_key = SigningKey::from_pkcs8_pem(private_key_pem).map_err(|_| {
                    ProvenanceError::new("invalid test Ed25519 PKCS#8 private key PEM")
                })?;
                signatures.push(DsseSignature {
                    keyid: None,
                    sig: Base64::encode_string(&signing_key.sign(&authenticated).to_bytes()),
                });
            }
            Ok(Self {
                payload_type: DSSE_IN_TOTO_JSON_PAYLOAD_TYPE.to_owned(),
                payload: Base64::encode_string(statement_bytes),
                signatures,
            })
        }
    }
}
