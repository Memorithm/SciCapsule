#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

const CONTRACT: &str = "capsule.execute@2.0.0";
const RESULT_MEDIA_TYPE_V1: &str = "application/vnd.scicapsule.hub-run-result.v1+json";
const RESULT_MEDIA_TYPE_V2: &str = "application/vnd.scicapsule.hub-run-result.v2+json";
const MAX_REQUEST_BYTES: u64 = 512 * 1024;
const MAX_POLICY_BYTES: u64 = 256 * 1024;
const MAX_RESULT_BYTES: u64 = 64 * 1024;
const MAX_RUNTIME_BINARY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SIGNATURES: usize = 64;

#[derive(Debug)]
struct Cli {
    capsule: PathBuf,
    policy: PathBuf,
    request: PathBuf,
    result: PathBuf,
    scicapsule_program: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct RequestIdentity {
    schema_version: u32,
    signatures: Vec<Value>,
    max_bytes: u64,
}

#[derive(Debug, Deserialize)]
struct HubRunResultV1 {
    schema_version: u32,
    status: String,
    capsule_sha256: String,
    capsule_name: String,
    entrypoint: String,
    matched_signers: Vec<String>,
    required_signatures: u32,
}

#[derive(Debug, Serialize)]
struct RuntimeIdentity {
    launcher_sha256: String,
    scicapsule_sha256: String,
    package_version: &'static str,
}

#[derive(Debug, Serialize)]
struct EnvironmentScope {
    os: &'static str,
    arch: &'static str,
    execution_mode: &'static str,
    sandbox: &'static str,
}

#[derive(Debug, Serialize)]
struct SourceResultIdentity {
    schema_version: u32,
    media_type: &'static str,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct HubRunResultV2 {
    schema_version: u32,
    contract: &'static str,
    media_type: &'static str,
    status: String,
    capsule_sha256: String,
    policy_sha256: String,
    request_sha256: String,
    signature_envelope_sha256: Vec<String>,
    capsule_name: String,
    entrypoint: String,
    matched_signers: Vec<String>,
    required_signatures: u32,
    runtime: RuntimeIdentity,
    environment_scope: EnvironmentScope,
    source_result: SourceResultIdentity,
    trust_is_scientific_verdict: bool,
}

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(summary) => {
            println!("{summary}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<String>) -> Result<String, String> {
    #[cfg(not(unix))]
    {
        let _ = args;
        return Err(
            "capsule.execute@2.0.0 requires the Unix bounded-process contract; refusing to execute"
                .to_owned(),
        );
    }

    #[cfg(unix)]
    {
        let cli = parse(&args)?;
        execute(cli)
    }
}

fn parse(args: &[String]) -> Result<Cli, String> {
    let mut capsule = None;
    let mut policy = None;
    let mut request = None;
    let mut result = None;
    let mut scicapsule_program = None;
    let mut index = 0usize;
    while index < args.len() {
        let option = args[index].as_str();
        let target = match option {
            "--capsule" => &mut capsule,
            "--policy" => &mut policy,
            "--request" => &mut request,
            "--result" => &mut result,
            "--scicapsule-program" => &mut scicapsule_program,
            _ => return Err(format!("unknown argument: {option}")),
        };
        index += 1;
        let value = args
            .get(index)
            .ok_or_else(|| format!("{option} requires a value"))?;
        if target.is_some() {
            return Err(format!("duplicate option: {option}"));
        }
        *target = Some(PathBuf::from(value));
        index += 1;
    }

    Ok(Cli {
        capsule: capsule.ok_or_else(|| "--capsule is required".to_owned())?,
        policy: policy.ok_or_else(|| "--policy is required".to_owned())?,
        request: request.ok_or_else(|| "--request is required".to_owned())?,
        result: result.ok_or_else(|| "--result is required".to_owned())?,
        scicapsule_program,
    })
}

#[cfg(unix)]
fn execute(cli: Cli) -> Result<String, String> {
    ensure_absent(&cli.result, "v2 result")?;

    let request_bytes = read_regular_bounded(&cli.request, MAX_REQUEST_BYTES, "Hub request")?;
    let request_sha256 = sha256_hex(&request_bytes);
    let request: RequestIdentity = serde_json::from_slice(&request_bytes)
        .map_err(|error| format!("invalid Hub request JSON: {error}"))?;
    validate_request_identity(&request)?;

    let policy_bytes = read_regular_bounded(&cli.policy, MAX_POLICY_BYTES, "trust policy")?;
    let policy_sha256 = sha256_hex(&policy_bytes);
    let signature_envelope_sha256 = signature_identities(&request.signatures)?;

    let capsule_limit = request
        .max_bytes
        .checked_add(scicapsule::extraction::MAX_CAPSULE_METADATA_BYTES)
        .ok_or_else(|| "Hub request max_bytes overflows capsule bound".to_owned())?;

    let work = tempfile::Builder::new()
        .prefix("scicapsule-hub-v2-")
        .tempdir()
        .map_err(|error| format!("cannot create private v2 input snapshot: {error}"))?;
    let capsule_snapshot = work.path().join("capsule.scicap");
    let policy_snapshot = work.path().join("policy.json");
    let request_snapshot = work.path().join("request.json");
    let v1_result = work.path().join("result-v1.json");

    let capsule_sha256 = snapshot_regular_bounded(
        &cli.capsule,
        &capsule_snapshot,
        capsule_limit,
        "capsule input",
    )?;
    write_new_file(&policy_snapshot, &policy_bytes, "policy snapshot")?;
    write_new_file(&request_snapshot, &request_bytes, "request snapshot")?;

    let launcher = std::env::current_exe()
        .map_err(|error| format!("cannot identify v2 launcher executable: {error}"))?;
    let scicapsule_program = match cli.scicapsule_program {
        Some(path) => path,
        None => sibling_scicapsule(&launcher)?,
    };
    if !scicapsule_program.is_absolute() {
        return Err("--scicapsule-program must be an absolute path".to_owned());
    }
    let launcher_sha256 = hash_regular_bounded(
        &launcher,
        MAX_RUNTIME_BINARY_BYTES,
        "v2 launcher executable",
    )?;
    let scicapsule_sha256 = hash_regular_bounded(
        &scicapsule_program,
        MAX_RUNTIME_BINARY_BYTES,
        "SciCapsule executable",
    )?;

    let status = Command::new(&scicapsule_program)
        .args([
            "hub-run",
            "--capsule",
            capsule_snapshot
                .to_str()
                .ok_or_else(|| "private capsule snapshot path is not UTF-8".to_owned())?,
            "--policy",
            policy_snapshot
                .to_str()
                .ok_or_else(|| "private policy snapshot path is not UTF-8".to_owned())?,
            "--request",
            request_snapshot
                .to_str()
                .ok_or_else(|| "private request snapshot path is not UTF-8".to_owned())?,
            "--result",
            v1_result
                .to_str()
                .ok_or_else(|| "private result path is not UTF-8".to_owned())?,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .env_clear()
        .status()
        .map_err(|error| format!("cannot launch qualified SciCapsule v1 process: {error}"))?;
    if !status.success() {
        return Err(format!(
            "qualified SciCapsule v1 process failed with status {status}"
        ));
    }

    let source_result_bytes =
        read_regular_bounded(&v1_result, MAX_RESULT_BYTES, "SciCapsule v1 result")?;
    let source_result_sha256 = sha256_hex(&source_result_bytes);
    let source: HubRunResultV1 = serde_json::from_slice(&source_result_bytes)
        .map_err(|error| format!("invalid SciCapsule v1 result JSON: {error}"))?;
    if source.schema_version != 1 || source.status != "succeeded" {
        return Err("qualified SciCapsule process returned an unsupported v1 result".to_owned());
    }
    if source.capsule_sha256 != capsule_sha256 {
        return Err(
            "SciCapsule v1 result capsule identity disagrees with the v2 pinned snapshot".to_owned(),
        );
    }

    let result = HubRunResultV2 {
        schema_version: 2,
        contract: CONTRACT,
        media_type: RESULT_MEDIA_TYPE_V2,
        status: source.status,
        capsule_sha256,
        policy_sha256,
        request_sha256,
        signature_envelope_sha256,
        capsule_name: source.capsule_name,
        entrypoint: source.entrypoint,
        matched_signers: source.matched_signers,
        required_signatures: source.required_signatures,
        runtime: RuntimeIdentity {
            launcher_sha256,
            scicapsule_sha256,
            package_version: env!("CARGO_PKG_VERSION"),
        },
        environment_scope: EnvironmentScope {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            execution_mode: "bounded_process_unix",
            sandbox: "none",
        },
        source_result: SourceResultIdentity {
            schema_version: 1,
            media_type: RESULT_MEDIA_TYPE_V1,
            sha256: source_result_sha256,
        },
        trust_is_scientific_verdict: false,
    };
    let mut encoded = serde_json::to_vec_pretty(&result)
        .map_err(|error| format!("cannot encode SciCapsule v2 result: {error}"))?;
    encoded.push(b'\n');
    if encoded.len() as u64 > MAX_RESULT_BYTES {
        return Err("SciCapsule v2 result exceeded size bound".to_owned());
    }
    write_new_file(&cli.result, &encoded, "SciCapsule v2 result")?;
    Ok(format!(
        "wrote SciCapsule Hub execution evidence {}",
        cli.result.display()
    ))
}

fn validate_request_identity(request: &RequestIdentity) -> Result<(), String> {
    if request.schema_version != 1 {
        return Err(format!(
            "unsupported Hub request schema_version {}; expected 1",
            request.schema_version
        ));
    }
    if request.signatures.is_empty() || request.signatures.len() > MAX_SIGNATURES {
        return Err(format!(
            "Hub request signature count must be 1..={MAX_SIGNATURES}"
        ));
    }
    Ok(())
}

fn signature_identities(signatures: &[Value]) -> Result<Vec<String>, String> {
    signatures
        .iter()
        .map(|signature| {
            serde_json::to_vec(signature)
                .map(|bytes| sha256_hex(&bytes))
                .map_err(|error| format!("cannot normalize signature envelope identity: {error}"))
        })
        .collect()
}

fn sibling_scicapsule(launcher: &Path) -> Result<PathBuf, String> {
    let parent = launcher
        .parent()
        .ok_or_else(|| "v2 launcher has no parent directory".to_owned())?;
    Ok(parent.join("scicapsule"))
}

fn ensure_absent(path: &Path, label: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(format!("refusing to overwrite existing {label}: {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot inspect {label} {}: {error}", path.display())),
    }
}

fn read_regular_bounded(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {label} {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{label} is not a regular non-symlink file"));
    }
    if metadata.len() > max_bytes {
        return Err(format!("{label} exceeds {max_bytes} bytes"));
    }
    let mut input = File::open(path)
        .map_err(|error| format!("cannot open {label} {}: {error}", path.display()))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    input
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {label}: {error}"))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!("{label} exceeds {max_bytes} bytes"));
    }
    Ok(bytes)
}

fn snapshot_regular_bounded(
    source: &Path,
    destination: &Path,
    max_bytes: u64,
    label: &str,
) -> Result<String, String> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| format!("cannot inspect {label} {}: {error}", source.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{label} is not a regular non-symlink file"));
    }
    if metadata.len() > max_bytes {
        return Err(format!("{label} exceeds {max_bytes} bytes"));
    }
    let mut input = File::open(source)
        .map_err(|error| format!("cannot open {label} {}: {error}", source.display()))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| format!("cannot create private {label} snapshot: {error}"))?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|error| format!("cannot read {label}: {error}"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| format!("{label} size overflow"))?;
        if total > max_bytes {
            return Err(format!("{label} exceeds {max_bytes} bytes"));
        }
        hasher.update(&buffer[..read]);
        output
            .write_all(&buffer[..read])
            .map_err(|error| format!("cannot write private {label} snapshot: {error}"))?;
    }
    output
        .flush()
        .map_err(|error| format!("cannot flush private {label} snapshot: {error}"))?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn hash_regular_bounded(path: &Path, max_bytes: u64, label: &str) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {label} {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{label} is not a regular non-symlink file"));
    }
    if metadata.len() > max_bytes {
        return Err(format!("{label} exceeds {max_bytes} bytes"));
    }
    let mut input = File::open(path)
        .map_err(|error| format!("cannot open {label} {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|error| format!("cannot read {label}: {error}"))?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > max_bytes {
            return Err(format!("{label} exceeds {max_bytes} bytes"));
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn write_new_file(path: &Path, bytes: &[u8], label: &str) -> Result<(), String> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("cannot create {label} {}: {error}", path.display()))?;
    output
        .write_all(bytes)
        .and_then(|()| output.flush())
        .map_err(|error| format!("cannot write {label} {}: {error}", path.display()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_identity_rejects_empty_signature_set() {
        let request = RequestIdentity {
            schema_version: 1,
            signatures: Vec::new(),
            max_bytes: 1024,
        };
        assert!(validate_request_identity(&request).is_err());
    }

    #[test]
    fn signature_identity_is_deterministic() {
        let signatures = vec![serde_json::json!({
            "algorithm": "ed25519",
            "signature": [1, 2, 3],
            "version": 1
        })];
        assert_eq!(
            signature_identities(&signatures).unwrap(),
            signature_identities(&signatures).unwrap()
        );
    }

    #[test]
    fn sibling_program_does_not_depend_on_caller_input_paths() {
        let launcher = Path::new("/opt/scicapsule/libexec/scicapsule-hub-evidence");
        assert_eq!(
            sibling_scicapsule(launcher).unwrap(),
            PathBuf::from("/opt/scicapsule/libexec/scicapsule")
        );
    }
}
