use crate::execution_cli::{
    DEFAULT_TIMEOUT_SECONDS, MAX_ARGUMENTS, MAX_ARGUMENT_BYTES, MAX_ENVIRONMENT_BYTES,
    MAX_ENVIRONMENT_ENTRIES, MAX_TIMEOUT_SECONDS,
};
use crate::signature::{SignatureEnvelope, SIGNATURE_ALGORITHM, SIGNATURE_ENVELOPE_VERSION};
use crate::trust::TrustPolicy;
use crate::{
    read_regular_file_bounded, take_unique_value, take_value, write_new_file, ProductError,
    MAX_SIGNATURE_ENVELOPE_BYTES, MAX_TRUST_POLICY_BYTES,
};
use scicapsule::extraction::{DEFAULT_EXTRACTION_LIMITS, MAX_CAPSULE_METADATA_BYTES};
use scirust_capsule::Capsule;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const HUB_REQUEST_SCHEMA_VERSION: u32 = 1;
const HUB_RESULT_SCHEMA_VERSION: u32 = 1;
const HUB_MANIFEST_SCHEMA_VERSION: u16 = 1;
const HUB_CAPABILITY_CONTRACT_VERSION: &str = "1.0.0";
const MAX_HUB_REQUEST_BYTES: u64 = 512 * 1024;
const MAX_HUB_RESULT_BYTES: usize = 64 * 1024;

const CAPSULE_MEDIA_TYPE: &str = "application/vnd.scirust.scicap";
const POLICY_MEDIA_TYPE: &str = "application/vnd.scicapsule.trust-policy.v1+json";
const REQUEST_MEDIA_TYPE: &str = "application/vnd.scicapsule.hub-run-request.v1+json";
const RESULT_MEDIA_TYPE: &str = "application/vnd.scicapsule.hub-run-result.v1+json";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HubEnvironmentEntry {
    name: String,
    value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HubRunRequest {
    schema_version: u32,
    signatures: Vec<SignatureEnvelope>,
    timeout_seconds: u64,
    max_files: usize,
    max_bytes: u64,
    environment: Vec<HubEnvironmentEntry>,
    arguments: Vec<String>,
}

impl HubRunRequest {
    fn validate(&self) -> Result<(), ProductError> {
        if self.schema_version != HUB_REQUEST_SCHEMA_VERSION {
            return Err(ProductError::operation(format!(
                "unsupported Hub request schema_version {}; expected {}",
                self.schema_version, HUB_REQUEST_SCHEMA_VERSION
            )));
        }
        if self.signatures.is_empty() {
            return Err(ProductError::operation(
                "Hub request requires at least one detached signature",
            ));
        }
        if self.signatures.len() > crate::trust::MAX_SIGNATURES {
            return Err(ProductError::operation(format!(
                "Hub request contains too many signatures: {}; limit is {}",
                self.signatures.len(),
                crate::trust::MAX_SIGNATURES
            )));
        }
        let mut previous_signature: Option<&[u8]> = None;
        for signature in &self.signatures {
            if signature.version != SIGNATURE_ENVELOPE_VERSION
                || signature.algorithm != SIGNATURE_ALGORITHM
                || signature.signature.len() != ed25519_dalek::SIGNATURE_LENGTH
            {
                return Err(ProductError::operation(
                    "Hub request contains an invalid detached signature envelope",
                ));
            }
            if let Some(previous) = previous_signature {
                if previous >= signature.signature.as_slice() {
                    return Err(ProductError::operation(
                        "Hub request signatures must be strictly sorted and unique",
                    ));
                }
            }
            previous_signature = Some(&signature.signature);
        }
        if self.timeout_seconds == 0 || self.timeout_seconds > MAX_TIMEOUT_SECONDS {
            return Err(ProductError::operation(format!(
                "Hub request timeout_seconds must be between 1 and {MAX_TIMEOUT_SECONDS}"
            )));
        }
        validate_environment(&self.environment)?;
        validate_arguments(&self.arguments)?;
        Ok(())
    }

    fn to_json(&self) -> Result<Vec<u8>, ProductError> {
        self.validate()?;
        let mut encoded = serde_json::to_vec_pretty(self).map_err(|error| {
            ProductError::operation(format!("cannot encode Hub execution request: {error}"))
        })?;
        encoded.push(b'\n');
        if encoded.len() as u64 > MAX_HUB_REQUEST_BYTES {
            return Err(ProductError::operation(format!(
                "Hub execution request is {} bytes; limit is {} bytes",
                encoded.len(),
                MAX_HUB_REQUEST_BYTES
            )));
        }
        Ok(encoded)
    }

    fn from_json(encoded: &[u8]) -> Result<Self, ProductError> {
        let request: Self = serde_json::from_slice(encoded).map_err(|error| {
            ProductError::operation(format!("invalid Hub execution request JSON: {error}"))
        })?;
        request.validate()?;
        Ok(request)
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct HubRunResult {
    schema_version: u32,
    status: &'static str,
    capsule_sha256: String,
    capsule_name: String,
    entrypoint: String,
    matched_signers: Vec<String>,
    required_signatures: u32,
}

impl HubRunResult {
    fn to_json(&self) -> Result<Vec<u8>, ProductError> {
        let mut encoded = serde_json::to_vec_pretty(self).map_err(|error| {
            ProductError::operation(format!("cannot encode Hub execution result: {error}"))
        })?;
        encoded.push(b'\n');
        if encoded.len() > MAX_HUB_RESULT_BYTES {
            return Err(ProductError::operation(
                "Hub execution result exceeded size limit",
            ));
        }
        Ok(encoded)
    }
}

#[derive(Debug, Serialize)]
struct HubComponentManifest {
    schema_version: u16,
    id: String,
    name: &'static str,
    version: &'static str,
    kind: &'static str,
    capabilities: Vec<HubCapability>,
    execution: HubExecutionBinding,
    metadata: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct HubCapability {
    name: &'static str,
    contract_version: &'static str,
    inputs: Vec<HubPort>,
    outputs: Vec<HubPort>,
    properties: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct HubPort {
    name: &'static str,
    description: &'static str,
}

#[derive(Debug, Serialize)]
struct HubExecutionBinding {
    #[serde(rename = "type")]
    binding_type: &'static str,
    program: String,
    args: Vec<&'static str>,
    outputs: Vec<HubOutputSpec>,
}

#[derive(Debug, Serialize)]
struct HubOutputSpec {
    name: &'static str,
    path: &'static str,
    media_type: &'static str,
    required: bool,
}

pub(crate) fn handles(args: &[String]) -> bool {
    matches!(
        args.first().map(String::as_str),
        Some("create-hub-request" | "hub-run" | "hub-manifest")
    )
}

pub(crate) fn run(args: &[String]) -> Result<String, ProductError> {
    match args {
        [command, rest @ ..] if command == "create-hub-request" => create_request(rest),
        [command, rest @ ..] if command == "hub-run" => hub_run(rest),
        [command, rest @ ..] if command == "hub-manifest" => create_manifest(rest),
        _ => Err(ProductError::usage("unknown SciRust Hub command")),
    }
}

fn create_request(args: &[String]) -> Result<String, ProductError> {
    let mut output = None;
    let mut signature_paths = Vec::new();
    let mut timeout_seconds = DEFAULT_TIMEOUT_SECONDS;
    let mut max_files = DEFAULT_EXTRACTION_LIMITS.max_files;
    let mut max_bytes = DEFAULT_EXTRACTION_LIMITS.max_total_bytes;
    let mut timeout_seen = false;
    let mut max_files_seen = false;
    let mut max_bytes_seen = false;
    let mut environment = Vec::new();
    let mut arguments = Vec::new();
    let mut index = 0;
    let mut positional_arguments = false;

    while index < args.len() {
        if positional_arguments {
            arguments.push(args[index].clone());
            index += 1;
            continue;
        }
        match args[index].as_str() {
            "--" => positional_arguments = true,
            "--output" => {
                output = Some(PathBuf::from(take_unique_value(
                    args,
                    &mut index,
                    "--output",
                    output.is_some(),
                )?));
            }
            "--signature" => {
                signature_paths.push(PathBuf::from(take_value(args, &mut index, "--signature")?));
                if signature_paths.len() > crate::trust::MAX_SIGNATURES {
                    return Err(ProductError::usage(format!(
                        "too many --signature values; limit is {}",
                        crate::trust::MAX_SIGNATURES
                    )));
                }
            }
            "--timeout-seconds" => {
                let raw = take_unique_value(args, &mut index, "--timeout-seconds", timeout_seen)?;
                timeout_seconds = raw.parse().map_err(|_| {
                    ProductError::usage("--timeout-seconds requires a positive integer")
                })?;
                timeout_seen = true;
            }
            "--max-files" => {
                let raw = take_unique_value(args, &mut index, "--max-files", max_files_seen)?;
                max_files = raw.parse().map_err(|_| {
                    ProductError::usage("--max-files requires a non-negative integer")
                })?;
                max_files_seen = true;
            }
            "--max-bytes" => {
                let raw = take_unique_value(args, &mut index, "--max-bytes", max_bytes_seen)?;
                max_bytes = raw.parse().map_err(|_| {
                    ProductError::usage("--max-bytes requires a non-negative integer")
                })?;
                max_bytes_seen = true;
            }
            "--env" => {
                let raw = take_value(args, &mut index, "--env")?;
                let (name, value) = raw.split_once('=').ok_or_else(|| {
                    ProductError::usage(format!("--env expects NAME=VALUE, got {raw:?}"))
                })?;
                environment.push(HubEnvironmentEntry {
                    name: name.to_owned(),
                    value: value.to_owned(),
                });
            }
            argument if argument.starts_with('-') => {
                return Err(ProductError::usage(format!(
                    "unknown create-hub-request option: {argument}; use -- before entrypoint arguments"
                )));
            }
            argument => {
                return Err(ProductError::usage(format!(
                    "unexpected create-hub-request argument {argument:?}"
                )));
            }
        }
        index += 1;
    }

    if signature_paths.is_empty() {
        return Err(ProductError::usage(
            "create-hub-request requires at least one --signature FILE",
        ));
    }
    let output = output
        .ok_or_else(|| ProductError::usage("create-hub-request requires --output REQUEST.json"))?;

    environment.sort_by(|left, right| left.name.cmp(&right.name));
    let mut signatures = Vec::with_capacity(signature_paths.len());
    for path in &signature_paths {
        let encoded = read_regular_file_bounded(
            path,
            MAX_SIGNATURE_ENVELOPE_BYTES,
            "Hub request signature envelope",
        )?;
        signatures.push(SignatureEnvelope::from_json(&encoded).map_err(|error| {
            ProductError::operation(format!(
                "invalid signature envelope {}: {error}",
                path.display()
            ))
        })?);
    }
    signatures.sort_by(|left, right| left.signature.cmp(&right.signature));

    let request = HubRunRequest {
        schema_version: HUB_REQUEST_SCHEMA_VERSION,
        signatures,
        timeout_seconds,
        max_files,
        max_bytes,
        environment,
        arguments,
    };
    let encoded = request.to_json()?;
    write_new_file(&output, &encoded, "Hub execution request")?;
    Ok(format!(
        "created Hub execution request {}\n",
        output.display()
    ))
}

fn hub_run(args: &[String]) -> Result<String, ProductError> {
    let mut capsule = None;
    let mut policy = None;
    let mut request = None;
    let mut result = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--capsule" => {
                capsule = Some(PathBuf::from(take_unique_value(
                    args,
                    &mut index,
                    "--capsule",
                    capsule.is_some(),
                )?));
            }
            "--policy" => {
                policy = Some(PathBuf::from(take_unique_value(
                    args,
                    &mut index,
                    "--policy",
                    policy.is_some(),
                )?));
            }
            "--request" => {
                request = Some(PathBuf::from(take_unique_value(
                    args,
                    &mut index,
                    "--request",
                    request.is_some(),
                )?));
            }
            "--result" => {
                result = Some(PathBuf::from(take_unique_value(
                    args,
                    &mut index,
                    "--result",
                    result.is_some(),
                )?));
            }
            argument => {
                return Err(ProductError::usage(format!(
                    "unknown hub-run argument: {argument}"
                )));
            }
        }
        index += 1;
    }

    let capsule_path =
        capsule.ok_or_else(|| ProductError::usage("hub-run requires --capsule FILE"))?;
    let policy_path =
        policy.ok_or_else(|| ProductError::usage("hub-run requires --policy FILE"))?;
    let request_path =
        request.ok_or_else(|| ProductError::usage("hub-run requires --request FILE"))?;
    let result_path =
        result.ok_or_else(|| ProductError::usage("hub-run requires --result FILE"))?;

    let request_bytes = read_regular_file_bounded(
        &request_path,
        MAX_HUB_REQUEST_BYTES,
        "Hub execution request",
    )?;
    let request = HubRunRequest::from_json(&request_bytes)?;

    let maximum_encoded_bytes = request
        .max_bytes
        .checked_add(MAX_CAPSULE_METADATA_BYTES)
        .ok_or_else(|| ProductError::operation("Hub request max_bytes is too large"))?;
    let capsule_bytes =
        read_regular_file_bounded(&capsule_path, maximum_encoded_bytes, "capsule input")?;
    let capsule = Capsule::decode(&capsule_bytes).map_err(|error| {
        ProductError::operation(format!(
            "invalid capsule {}: {error}",
            capsule_path.display()
        ))
    })?;
    let policy_bytes =
        read_regular_file_bounded(&policy_path, MAX_TRUST_POLICY_BYTES, "trust policy")?;
    let policy = TrustPolicy::from_json(&policy_bytes)
        .map_err(|error| ProductError::operation(format!("invalid trust policy: {error}")))?;
    let trust = policy
        .verify(&capsule_bytes, &request.signatures)
        .map_err(|error| ProductError::operation(format!("Hub execution trust failed: {error}")))?;

    let signature_dir = tempfile::Builder::new()
        .prefix("scicapsule-hub-signatures-")
        .tempdir()
        .map_err(|error| {
            ProductError::operation(format!(
                "cannot create private Hub signature directory: {error}"
            ))
        })?;
    let mut run_args = vec![
        "run".to_owned(),
        capsule_path.display().to_string(),
        "--policy".to_owned(),
        policy_path.display().to_string(),
    ];
    for (index, signature) in request.signatures.iter().enumerate() {
        let path = signature_dir.path().join(format!("signature-{index}.json"));
        fs::write(
            &path,
            signature.to_json().map_err(|error| {
                ProductError::operation(format!("cannot encode Hub request signature: {error}"))
            })?,
        )
        .map_err(|error| {
            ProductError::operation(format!("cannot materialize Hub request signature: {error}"))
        })?;
        run_args.push("--signature".to_owned());
        run_args.push(path.display().to_string());
    }
    run_args.extend([
        "--timeout-seconds".to_owned(),
        request.timeout_seconds.to_string(),
        "--max-files".to_owned(),
        request.max_files.to_string(),
        "--max-bytes".to_owned(),
        request.max_bytes.to_string(),
    ]);
    for entry in &request.environment {
        run_args.push("--env".to_owned());
        run_args.push(format!("{}={}", entry.name, entry.value));
    }
    if !request.arguments.is_empty() {
        run_args.push("--".to_owned());
        run_args.extend(request.arguments.iter().cloned());
    }

    crate::execution_cli::run(&run_args)?;

    let result = HubRunResult {
        schema_version: HUB_RESULT_SCHEMA_VERSION,
        status: "succeeded",
        capsule_sha256: sha256_hex(&capsule_bytes),
        capsule_name: capsule.manifest().name().to_owned(),
        entrypoint: capsule.manifest().entrypoint().to_string(),
        matched_signers: trust.matched_signers,
        required_signatures: trust.required_signatures,
    };
    write_new_file(&result_path, &result.to_json()?, "Hub execution result")?;
    Ok(format!(
        "wrote Hub execution result {}\n",
        result_path.display()
    ))
}

fn create_manifest(args: &[String]) -> Result<String, ProductError> {
    let mut component_id = None;
    let mut program = None;
    let mut output = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--component-id" => {
                component_id = Some(take_unique_value(
                    args,
                    &mut index,
                    "--component-id",
                    component_id.is_some(),
                )?);
            }
            "--program" => {
                program = Some(take_unique_value(
                    args,
                    &mut index,
                    "--program",
                    program.is_some(),
                )?);
            }
            "--output" => {
                output = Some(PathBuf::from(take_unique_value(
                    args,
                    &mut index,
                    "--output",
                    output.is_some(),
                )?));
            }
            argument => {
                return Err(ProductError::usage(format!(
                    "unknown hub-manifest argument: {argument}"
                )));
            }
        }
        index += 1;
    }

    let component_id = canonical_uuid(
        &component_id
            .ok_or_else(|| ProductError::usage("hub-manifest requires --component-id UUID"))?,
    )?;
    let program = program.ok_or_else(|| {
        ProductError::usage("hub-manifest requires --program /absolute/path/to/scicapsule")
    })?;
    if program.is_empty() || program.len() > 4096 || program.contains('\0') {
        return Err(ProductError::usage(
            "hub-manifest --program must be 1..=4096 characters without NUL",
        ));
    }
    if !Path::new(&program).is_absolute() {
        return Err(ProductError::usage(
            "hub-manifest --program must be an absolute path",
        ));
    }
    let output = output
        .ok_or_else(|| ProductError::usage("hub-manifest requires --output COMPONENT.json"))?;

    let mut properties = BTreeMap::new();
    properties.insert("authorization".to_owned(), "local_trust_policy".to_owned());
    properties.insert(
        "request_media_type".to_owned(),
        REQUEST_MEDIA_TYPE.to_owned(),
    );
    properties.insert("result_media_type".to_owned(), RESULT_MEDIA_TYPE.to_owned());
    properties.insert("sandbox".to_owned(), "none".to_owned());

    let mut metadata = BTreeMap::new();
    metadata.insert("canonical_capsule_owner".to_owned(), "scirust".to_owned());
    metadata.insert("contract".to_owned(), "scicapsule-hub-v1".to_owned());

    let manifest = HubComponentManifest {
        schema_version: HUB_MANIFEST_SCHEMA_VERSION,
        id: component_id,
        name: "SciCapsule",
        version: env!("CARGO_PKG_VERSION"),
        kind: "tool",
        capabilities: vec![HubCapability {
            name: "capsule.execute",
            contract_version: HUB_CAPABILITY_CONTRACT_VERSION,
            inputs: vec![
                HubPort {
                    name: "capsule",
                    description: CAPSULE_MEDIA_TYPE,
                },
                HubPort {
                    name: "policy",
                    description: POLICY_MEDIA_TYPE,
                },
                HubPort {
                    name: "request",
                    description: REQUEST_MEDIA_TYPE,
                },
            ],
            outputs: vec![HubPort {
                name: "result",
                description: RESULT_MEDIA_TYPE,
            }],
            properties,
        }],
        execution: HubExecutionBinding {
            binding_type: "process",
            program,
            args: vec![
                "hub-run",
                "--capsule",
                "{input:capsule}",
                "--policy",
                "{input:policy}",
                "--request",
                "{input:request}",
                "--result",
                "{output:result}",
            ],
            outputs: vec![HubOutputSpec {
                name: "result",
                path: "outputs/scicapsule-result.json",
                media_type: RESULT_MEDIA_TYPE,
                required: true,
            }],
        },
        metadata,
    };
    let mut encoded = serde_json::to_vec_pretty(&manifest).map_err(|error| {
        ProductError::operation(format!(
            "cannot encode SciRust Hub component manifest: {error}"
        ))
    })?;
    encoded.push(b'\n');
    write_new_file(&output, &encoded, "SciRust Hub component manifest")?;
    Ok(format!(
        "created SciRust Hub component manifest {}\n",
        output.display()
    ))
}

fn validate_environment(environment: &[HubEnvironmentEntry]) -> Result<(), ProductError> {
    if environment.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err(ProductError::operation(format!(
            "Hub request contains too many environment entries; limit is {MAX_ENVIRONMENT_ENTRIES}"
        )));
    }
    let mut total = 0usize;
    let mut previous: Option<&str> = None;
    for entry in environment {
        if entry.name.is_empty() || entry.name.contains('\0') || entry.value.contains('\0') {
            return Err(ProductError::operation(
                "Hub request contains an invalid environment entry",
            ));
        }
        if let Some(previous) = previous {
            if previous >= entry.name.as_str() {
                return Err(ProductError::operation(
                    "Hub request environment entries must be strictly sorted by unique name",
                ));
            }
        }
        previous = Some(&entry.name);
        total = total
            .checked_add(entry.name.len())
            .and_then(|bytes| bytes.checked_add(entry.value.len()))
            .ok_or_else(|| ProductError::operation("Hub request environment size overflow"))?;
    }
    if total > MAX_ENVIRONMENT_BYTES {
        return Err(ProductError::operation(format!(
            "Hub request environment is {total} bytes; limit is {MAX_ENVIRONMENT_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_arguments(arguments: &[String]) -> Result<(), ProductError> {
    if arguments.len() > MAX_ARGUMENTS {
        return Err(ProductError::operation(format!(
            "Hub request contains too many arguments; limit is {MAX_ARGUMENTS}"
        )));
    }
    let total = arguments.iter().try_fold(0usize, |total, argument| {
        if argument.contains('\0') {
            return Err(());
        }
        total.checked_add(argument.len()).ok_or(())
    });
    let total = total.map_err(|()| {
        ProductError::operation("Hub request contains an invalid argument or size overflow")
    })?;
    if total > MAX_ARGUMENT_BYTES {
        return Err(ProductError::operation(format!(
            "Hub request arguments are {total} bytes; limit is {MAX_ARGUMENT_BYTES} bytes"
        )));
    }
    Ok(())
}

fn canonical_uuid(raw: &str) -> Result<String, ProductError> {
    if raw.len() != 36 {
        return Err(ProductError::usage(
            "--component-id must be a canonical hyphenated UUID",
        ));
    }
    for (index, byte) in raw.bytes().enumerate() {
        let hyphen = matches!(index, 8 | 13 | 18 | 23);
        if (hyphen && byte != b'-') || (!hyphen && !byte.is_ascii_hexdigit()) {
            return Err(ProductError::usage(
                "--component-id must be a canonical hyphenated UUID",
            ));
        }
    }
    Ok(raw.to_ascii_lowercase())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{pkcs8::EncodePrivateKey, Signer, SigningKey};
    use pkcs8::LineEnding;

    fn signature(seed: u8) -> SignatureEnvelope {
        let key = SigningKey::from_bytes(&[seed; ed25519_dalek::SECRET_KEY_LENGTH]);
        let signed = key.sign(b"hub-contract-test");
        SignatureEnvelope {
            version: SIGNATURE_ENVELOPE_VERSION,
            algorithm: SIGNATURE_ALGORITHM.to_owned(),
            signature: signed.to_bytes().to_vec(),
        }
    }

    #[test]
    fn request_round_trip_is_strict_and_deterministic() {
        let mut signatures = vec![signature(2), signature(1)];
        signatures.sort_by(|left, right| left.signature.cmp(&right.signature));
        let request = HubRunRequest {
            schema_version: HUB_REQUEST_SCHEMA_VERSION,
            signatures,
            timeout_seconds: 30,
            max_files: 4,
            max_bytes: 1024,
            environment: vec![HubEnvironmentEntry {
                name: "LANG".to_owned(),
                value: "C".to_owned(),
            }],
            arguments: vec!["--literal".to_owned()],
        };
        let first = request.to_json().unwrap();
        let second = HubRunRequest::from_json(&first).unwrap().to_json().unwrap();
        assert_eq!(first, second);

        let mut value: serde_json::Value = serde_json::from_slice(&first).unwrap();
        value["unknown"] = serde_json::json!(true);
        assert!(HubRunRequest::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn request_rejects_noncanonical_ordering_and_duplicate_environment() {
        let request = HubRunRequest {
            schema_version: HUB_REQUEST_SCHEMA_VERSION,
            signatures: vec![signature(1)],
            timeout_seconds: 30,
            max_files: 4,
            max_bytes: 1024,
            environment: vec![
                HubEnvironmentEntry {
                    name: "Z".to_owned(),
                    value: "1".to_owned(),
                },
                HubEnvironmentEntry {
                    name: "A".to_owned(),
                    value: "2".to_owned(),
                },
            ],
            arguments: Vec::new(),
        };
        assert!(request.validate().is_err());
    }

    #[test]
    fn manifest_shape_matches_hub_v1_process_contract() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("component.json");
        create_manifest(&[
            "--component-id".to_owned(),
            "00000000-0000-0000-0000-000000000001".to_owned(),
            "--program".to_owned(),
            "/opt/scicapsule/bin/scicapsule".to_owned(),
            "--output".to_owned(),
            output.display().to_string(),
        ])
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["kind"], "tool");
        assert_eq!(value["capabilities"][0]["name"], "capsule.execute");
        assert_eq!(value["execution"]["type"], "process");
        assert_eq!(value["execution"]["args"][2], "{input:capsule}");
        assert_eq!(value["execution"]["args"][8], "{output:result}");
        assert_eq!(value["execution"]["outputs"][0]["required"], true);
    }

    #[test]
    fn component_id_is_normalized_and_program_must_be_absolute() {
        assert_eq!(
            canonical_uuid("ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB").unwrap(),
            "abcdefab-cdef-abcd-efab-cdefabcdefab"
        );
        assert!(canonical_uuid("not-a-uuid").is_err());

        let dir = tempfile::tempdir().unwrap();
        let error = create_manifest(&[
            "--component-id".to_owned(),
            "00000000-0000-0000-0000-000000000001".to_owned(),
            "--program".to_owned(),
            "scicapsule".to_owned(),
            "--output".to_owned(),
            dir.path().join("component.json").display().to_string(),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("absolute path"));
    }

    #[test]
    fn create_request_parses_real_signature_envelopes() {
        let dir = tempfile::tempdir().unwrap();
        let signature_path = dir.path().join("one.sig");
        let output = dir.path().join("request.json");
        fs::write(&signature_path, signature(9).to_json().unwrap()).unwrap();
        create_request(&[
            "--output".to_owned(),
            output.display().to_string(),
            "--signature".to_owned(),
            signature_path.display().to_string(),
            "--env".to_owned(),
            "LANG=C".to_owned(),
            "--".to_owned(),
            "--x".to_owned(),
        ])
        .unwrap();
        let request = HubRunRequest::from_json(&fs::read(output).unwrap()).unwrap();
        assert_eq!(request.arguments, vec!["--x"]);
        assert_eq!(request.environment[0].name, "LANG");
    }

    #[test]
    fn private_key_encoding_used_by_contract_tests_stays_supported() {
        let key = SigningKey::from_bytes(&[7; ed25519_dalek::SECRET_KEY_LENGTH]);
        assert!(key.to_pkcs8_pem(LineEnding::LF).is_ok());
    }
}
