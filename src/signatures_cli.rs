use crate::signature::SignatureEnvelope;
use crate::trust::{TrustPolicy, MAX_SIGNATURES};
use crate::{
    read_regular_file_bounded, read_regular_input_bounded, take_unique_value, CliError,
    DEFAULT_CAPSULE_READ_LIMIT,
};
use scirust_capsule::Capsule;
use serde::Serialize;
use std::path::PathBuf;

const SIGNATURES_RESULT_SCHEMA_VERSION: u32 = 1;
const MAX_SIGNATURE_ENVELOPE_BYTES: u64 = 16 * 1024;
const MAX_TRUST_POLICY_BYTES: u64 = 256 * 1024;

#[derive(Debug, Eq, PartialEq)]
struct SignaturesCommand {
    capsule: PathBuf,
    signatures: Vec<PathBuf>,
    policy: Option<PathBuf>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct SignatureEnvelopeSummary {
    version: u32,
    algorithm: String,
    signature_bytes: usize,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct TrustSummary {
    trusted: bool,
    matched_signers: Vec<String>,
    required_signatures: u32,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct SignaturesResult {
    schema_version: u32,
    capsule_name: String,
    entrypoint: String,
    integrity_verified: bool,
    signature_count: usize,
    signatures: Vec<SignatureEnvelopeSummary>,
    authenticity: &'static str,
    trust: Option<TrustSummary>,
}

pub(crate) fn handles(args: &[String]) -> bool {
    matches!(args.first().map(String::as_str), Some("signatures"))
}

pub(crate) fn help_text() -> &'static str {
    "\nSIGNATURE INSPECTION COMMAND:\n\
    scicapsule signatures FILE [--signature FILE.sig ...] [--policy POLICY.json]\n\n\
    signatures           Inspect detached signature envelopes and optionally evaluate local trust\n\n\
SIGNATURE INSPECTION OPTIONS:\n\
    --signature FILE     Detached signature envelope; repeatable; zero envelopes are allowed\n\
    --policy FILE        Optional local trust policy. Without it, authenticity and trust are not evaluated.\n\n\
SIGNATURE INSPECTION SEMANTICS:\n\
    The command always verifies canonical capsule integrity first. With no policy it validates only\n\
    envelope structure and does not claim that a signature is authentic or trusted. With --policy,\n\
    the existing trust-policy threshold is enforced; unknown or invalid signatures do not satisfy it.\n"
}

pub(crate) fn run(args: &[String]) -> Result<String, CliError> {
    let command = parse(args)?;
    let capsule_bytes = read_regular_file_bounded(&command.capsule, DEFAULT_CAPSULE_READ_LIMIT)?;
    let capsule = Capsule::decode(&capsule_bytes).map_err(|error| {
        CliError::operation(format!(
            "invalid capsule {}: {error}",
            command.capsule.display()
        ))
    })?;

    let mut envelopes = Vec::with_capacity(command.signatures.len());
    let mut summaries = Vec::with_capacity(command.signatures.len());
    for signature_path in &command.signatures {
        let encoded = read_regular_input_bounded(
            signature_path,
            MAX_SIGNATURE_ENVELOPE_BYTES,
            "signature envelope",
        )?;
        let envelope = SignatureEnvelope::from_json(&encoded).map_err(|error| {
            CliError::operation(format!(
                "invalid signature envelope {}: {error}",
                signature_path.display()
            ))
        })?;
        summaries.push(SignatureEnvelopeSummary {
            version: envelope.version,
            algorithm: envelope.algorithm.clone(),
            signature_bytes: envelope.signature.len(),
        });
        envelopes.push(envelope);
    }

    let trust = if let Some(policy_path) = command.policy {
        let encoded =
            read_regular_input_bounded(&policy_path, MAX_TRUST_POLICY_BYTES, "trust policy")?;
        let policy = TrustPolicy::from_json(&encoded)
            .map_err(|error| CliError::operation(format!("invalid trust policy: {error}")))?;
        let decision = policy
            .verify(&capsule_bytes, &envelopes)
            .map_err(|error| CliError::operation(format!("trust verification failed: {error}")))?;
        Some(TrustSummary {
            trusted: true,
            matched_signers: decision.matched_signers,
            required_signatures: decision.required_signatures,
        })
    } else {
        None
    };

    let result = SignaturesResult {
        schema_version: SIGNATURES_RESULT_SCHEMA_VERSION,
        capsule_name: capsule.manifest().name().to_owned(),
        entrypoint: capsule.manifest().entrypoint().to_string(),
        integrity_verified: true,
        signature_count: summaries.len(),
        signatures: summaries,
        authenticity: if trust.is_some() {
            "evaluated only against explicit local trust-policy keys"
        } else {
            "not evaluated; no verification key or trust policy was supplied"
        },
        trust,
    };
    let mut output = serde_json::to_string_pretty(&result).map_err(|error| {
        CliError::operation(format!(
            "cannot serialize signature inspection result: {error}"
        ))
    })?;
    output.push('\n');
    Ok(output)
}

fn parse(args: &[String]) -> Result<SignaturesCommand, CliError> {
    let [command, rest @ ..] = args else {
        return Err(CliError::usage("signatures requires a capsule file"));
    };
    if command != "signatures" {
        return Err(CliError::usage("unknown signature inspection command"));
    }

    let mut capsule = None;
    let mut signatures = Vec::new();
    let mut policy = None;
    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "--signature" => {
                signatures.push(PathBuf::from(take_value(rest, &mut index, "--signature")?));
                if signatures.len() > MAX_SIGNATURES {
                    return Err(CliError::usage(format!(
                        "too many --signature values; limit is {MAX_SIGNATURES}"
                    )));
                }
            }
            "--policy" => {
                policy = Some(PathBuf::from(take_unique_value(
                    rest,
                    &mut index,
                    "--policy",
                    policy.is_some(),
                )?));
            }
            argument if argument.starts_with('-') => {
                return Err(CliError::usage(format!(
                    "unknown signatures option: {argument}"
                )));
            }
            argument if capsule.is_none() => capsule = Some(PathBuf::from(argument)),
            argument => {
                return Err(CliError::usage(format!(
                    "unexpected signatures argument: {argument}"
                )));
            }
        }
        index += 1;
    }

    Ok(SignaturesCommand {
        capsule: capsule.ok_or_else(|| CliError::usage("signatures requires a capsule file"))?,
        signatures,
        policy,
    })
}

fn take_value(args: &[String], index: &mut usize, option: &str) -> Result<String, CliError> {
    *index += 1;
    args.get(*index)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| CliError::usage(format!("{option} requires a value")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::sign_capsule;
    use ed25519_dalek::{
        pkcs8::{EncodePrivateKey, EncodePublicKey},
        SigningKey,
    };
    use pkcs8::LineEnding;
    use scirust_capsule::CapsulePayload;
    use scirust_capsule_schema::CapsulePath;
    use std::fs;

    fn fixture(seed: u8) -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-tmp");
        fs::create_dir_all(&base).unwrap();
        let dir = tempfile::Builder::new()
            .prefix("signatures-")
            .tempdir_in(base)
            .unwrap();
        let capsule_path = dir.path().join("demo.scicap");
        let signature_path = dir.path().join("demo.sig");
        let policy_path = dir.path().join("policy.json");

        let capsule = Capsule::new(
            "demo",
            CapsulePath::new("bin/run").unwrap(),
            vec![CapsulePayload::new(
                CapsulePath::new("bin/run").unwrap(),
                b"runner".to_vec(),
            )],
        )
        .unwrap();
        let capsule_bytes = capsule.encode().unwrap();
        fs::write(&capsule_path, &capsule_bytes).unwrap();

        let signing_key = SigningKey::from_bytes(&[seed; ed25519_dalek::SECRET_KEY_LENGTH]);
        let private_pem = signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string();
        let public_pem = signing_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let envelope = sign_capsule(&capsule_bytes, &private_pem).unwrap();
        fs::write(&signature_path, envelope.to_json().unwrap()).unwrap();
        let policy =
            TrustPolicy::from_named_pem_keys(1, vec![("release".to_owned(), public_pem)]).unwrap();
        fs::write(&policy_path, policy.to_json().unwrap()).unwrap();

        (dir, capsule_path, signature_path, policy_path)
    }

    #[test]
    fn optional_signatures_do_not_imply_authenticity_or_trust() {
        let (_dir, capsule, _signature, _policy) = fixture(91);
        let output = run(&["signatures".to_owned(), capsule.display().to_string()]).unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(value["integrity_verified"], true);
        assert_eq!(value["signature_count"], 0);
        assert!(value["trust"].is_null());
        assert!(value["authenticity"]
            .as_str()
            .unwrap()
            .starts_with("not evaluated"));
    }

    #[test]
    fn explicit_policy_reports_trusted_signer() {
        let (_dir, capsule, signature, policy) = fixture(92);
        let output = run(&[
            "signatures".to_owned(),
            capsule.display().to_string(),
            "--signature".to_owned(),
            signature.display().to_string(),
            "--policy".to_owned(),
            policy.display().to_string(),
        ])
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(value["signature_count"], 1);
        assert_eq!(value["trust"]["trusted"], true);
        assert_eq!(
            value["trust"]["matched_signers"],
            serde_json::json!(["release"])
        );
        assert_eq!(value["trust"]["required_signatures"], 1);
    }

    #[test]
    fn unknown_signer_does_not_satisfy_explicit_policy() {
        let (dir, capsule, _signature, policy) = fixture(93);
        let (_, _, unknown_signature, _) = fixture(94);
        let copied_unknown = dir.path().join("unknown.sig");
        fs::copy(unknown_signature, &copied_unknown).unwrap();

        let error = run(&[
            "signatures".to_owned(),
            capsule.display().to_string(),
            "--signature".to_owned(),
            copied_unknown.display().to_string(),
            "--policy".to_owned(),
            policy.display().to_string(),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("threshold not met"));
    }

    #[test]
    fn malformed_signature_envelope_is_rejected() {
        let (dir, capsule, _signature, _policy) = fixture(95);
        let malformed = dir.path().join("malformed.sig");
        fs::write(&malformed, b"{\"version\":1}").unwrap();
        let error = run(&[
            "signatures".to_owned(),
            capsule.display().to_string(),
            "--signature".to_owned(),
            malformed.display().to_string(),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("invalid signature envelope"));
    }
}
