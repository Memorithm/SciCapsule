use crate::signature::SignatureEnvelope;
use crate::trust::{TrustPolicy, MAX_SIGNATURES};
use crate::{
    read_regular_file_bounded, take_unique_value, take_value, ProductError,
    MAX_SIGNATURE_ENVELOPE_BYTES, MAX_TRUST_POLICY_BYTES,
};
use scicapsule::extraction::{
    extract_capsule, ExtractionLimits, DEFAULT_EXTRACTION_LIMITS, MAX_CAPSULE_METADATA_BYTES,
};
use scirust_capsule::Capsule;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_TIMEOUT_SECONDS: u64 = 300;
const MAX_TIMEOUT_SECONDS: u64 = 86_400;
const MAX_ENVIRONMENT_ENTRIES: usize = 128;
const MAX_ENVIRONMENT_BYTES: usize = 64 * 1024;
const MAX_ARGUMENTS: usize = 256;
const MAX_ARGUMENT_BYTES: usize = 64 * 1024;

#[derive(Debug, Eq, PartialEq)]
struct RunCommand {
    capsule: PathBuf,
    policy: PathBuf,
    signatures: Vec<PathBuf>,
    limits: ExtractionLimits,
    timeout_seconds: u64,
    environment: Vec<(String, String)>,
    arguments: Vec<String>,
}

pub(crate) fn handles(args: &[String]) -> bool {
    matches!(args.first().map(String::as_str), Some("run"))
}

pub(crate) fn help_text() -> &'static str {
    "\nEXECUTION COMMAND:\n\
    scicapsule run FILE --policy POLICY.json --signature FILE.sig [--signature FILE.sig ...] [--timeout-seconds N] [--max-files N] [--max-bytes N] [--env NAME=VALUE ...] [-- ARG ...]\n\n\
    run                  Verify trust, materialize privately, and execute the exact manifest entrypoint\n\n\
EXECUTION OPTIONS:\n\
    --policy FILE        Required local trust-policy JSON; execution never trusts an embedded key\n\
    --signature FILE     Required detached signature envelope; repeatable for threshold policies\n\
    --timeout-seconds N  Wall-clock limit in seconds (default: 300; maximum: 86400)\n\
    --max-files N        Maximum materialized payload files (default: 4096)\n\
    --max-bytes N        Maximum total materialized payload bytes (default: 1073741824)\n\
    --env NAME=VALUE     Explicit environment entry; repeatable; inherited environment is cleared\n\
    -- ARG ...           Arguments passed verbatim to the manifest entrypoint; no shell is used\n\n\
EXECUTION SECURITY BOUNDARY:\n\
    The v1 runner is Unix-only and fail-closed elsewhere. It uses a private materialization,\n\
    a dedicated process group, a wall-clock timeout, null stdin, and an empty inherited environment.\n\
    It is NOT an OS sandbox: filesystem, network, memory, CPU, syscall, and privilege isolation are\n\
    not claimed by this command. Use an external sandbox/container when those controls are required.\n"
}

pub(crate) fn run(args: &[String]) -> Result<String, ProductError> {
    #[cfg(not(unix))]
    {
        let _ = args;
        return Err(ProductError::operation(
            "secure execution v1 is not implemented on this platform; refusing to execute",
        ));
    }

    #[cfg(unix)]
    {
        execute(parse(args)?)
    }
}

fn parse(args: &[String]) -> Result<RunCommand, ProductError> {
    let [command, rest @ ..] = args else {
        return Err(ProductError::usage("run requires a capsule file"));
    };
    if command != "run" {
        return Err(ProductError::usage("unknown execution command"));
    }

    let mut capsule = None;
    let mut policy = None;
    let mut signatures = Vec::new();
    let mut max_files = DEFAULT_EXTRACTION_LIMITS.max_files;
    let mut max_bytes = DEFAULT_EXTRACTION_LIMITS.max_total_bytes;
    let mut timeout_seconds = DEFAULT_TIMEOUT_SECONDS;
    let mut max_files_seen = false;
    let mut max_bytes_seen = false;
    let mut timeout_seen = false;
    let mut environment = Vec::new();
    let mut arguments = Vec::new();
    let mut index = 0;
    let mut positional_arguments = false;

    while index < rest.len() {
        if positional_arguments {
            arguments.push(rest[index].clone());
            validate_argument_limits(&arguments)?;
            index += 1;
            continue;
        }

        match rest[index].as_str() {
            "--" => positional_arguments = true,
            "--policy" => {
                policy = Some(PathBuf::from(take_unique_value(
                    rest,
                    &mut index,
                    "--policy",
                    policy.is_some(),
                )?));
            }
            "--signature" => {
                signatures.push(PathBuf::from(take_value(rest, &mut index, "--signature")?));
                if signatures.len() > MAX_SIGNATURES {
                    return Err(ProductError::usage(format!(
                        "too many --signature values; limit is {MAX_SIGNATURES}"
                    )));
                }
            }
            "--max-files" => {
                let raw = take_unique_value(rest, &mut index, "--max-files", max_files_seen)?;
                max_files = raw.parse().map_err(|_| {
                    ProductError::usage("--max-files requires a non-negative integer")
                })?;
                max_files_seen = true;
            }
            "--max-bytes" => {
                let raw = take_unique_value(rest, &mut index, "--max-bytes", max_bytes_seen)?;
                max_bytes = raw.parse().map_err(|_| {
                    ProductError::usage("--max-bytes requires a non-negative integer")
                })?;
                max_bytes_seen = true;
            }
            "--timeout-seconds" => {
                let raw = take_unique_value(rest, &mut index, "--timeout-seconds", timeout_seen)?;
                timeout_seconds = raw.parse().map_err(|_| {
                    ProductError::usage("--timeout-seconds requires a positive integer")
                })?;
                if timeout_seconds == 0 || timeout_seconds > MAX_TIMEOUT_SECONDS {
                    return Err(ProductError::usage(format!(
                        "--timeout-seconds must be between 1 and {MAX_TIMEOUT_SECONDS}"
                    )));
                }
                timeout_seen = true;
            }
            "--env" => {
                let raw = take_value(rest, &mut index, "--env")?;
                environment.push(parse_environment(&raw)?);
                validate_environment(&environment)?;
            }
            argument if argument.starts_with('-') => {
                return Err(ProductError::usage(format!(
                    "unknown run option: {argument}; use -- before entrypoint arguments"
                )));
            }
            argument if capsule.is_none() => capsule = Some(PathBuf::from(argument)),
            argument => {
                return Err(ProductError::usage(format!(
                    "unexpected run argument {argument:?}; use -- before entrypoint arguments"
                )));
            }
        }
        index += 1;
    }

    if signatures.is_empty() {
        return Err(ProductError::usage(
            "run requires at least one --signature FILE",
        ));
    }

    Ok(RunCommand {
        capsule: capsule.ok_or_else(|| ProductError::usage("run requires a capsule file"))?,
        policy: policy.ok_or_else(|| ProductError::usage("run requires --policy FILE"))?,
        signatures,
        limits: ExtractionLimits {
            max_files,
            max_total_bytes: max_bytes,
        },
        timeout_seconds,
        environment,
        arguments,
    })
}

fn parse_environment(raw: &str) -> Result<(String, String), ProductError> {
    let (name, value) = raw
        .split_once('=')
        .ok_or_else(|| ProductError::usage(format!("--env expects NAME=VALUE, got {raw:?}")))?;
    if name.is_empty() || name.contains('\0') || value.contains('\0') {
        return Err(ProductError::usage(format!(
            "invalid --env NAME=VALUE entry {raw:?}"
        )));
    }
    Ok((name.to_owned(), value.to_owned()))
}

fn validate_environment(environment: &[(String, String)]) -> Result<(), ProductError> {
    if environment.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err(ProductError::usage(format!(
            "too many --env values; limit is {MAX_ENVIRONMENT_ENTRIES}"
        )));
    }
    let mut names = BTreeSet::new();
    let mut total = 0usize;
    for (name, value) in environment {
        if !names.insert(name.as_str()) {
            return Err(ProductError::usage(format!(
                "duplicate --env variable {name:?}"
            )));
        }
        total = total
            .checked_add(name.len())
            .and_then(|value_bytes| value_bytes.checked_add(value.len()))
            .ok_or_else(|| ProductError::usage("environment size overflow"))?;
    }
    if total > MAX_ENVIRONMENT_BYTES {
        return Err(ProductError::usage(format!(
            "explicit environment is {total} bytes; limit is {MAX_ENVIRONMENT_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_argument_limits(arguments: &[String]) -> Result<(), ProductError> {
    if arguments.len() > MAX_ARGUMENTS {
        return Err(ProductError::usage(format!(
            "too many entrypoint arguments; limit is {MAX_ARGUMENTS}"
        )));
    }
    let total = arguments.iter().try_fold(0usize, |total, argument| {
        total.checked_add(argument.len()).ok_or(())
    });
    let total = total.map_err(|()| ProductError::usage("argument size overflow"))?;
    if total > MAX_ARGUMENT_BYTES {
        return Err(ProductError::usage(format!(
            "entrypoint arguments are {total} bytes; limit is {MAX_ARGUMENT_BYTES} bytes"
        )));
    }
    Ok(())
}

#[cfg(unix)]
struct ProcessGroupGuard(rustix::process::Pid);

#[cfg(unix)]
impl ProcessGroupGuard {
    fn kill(&self) {
        let _ = rustix::process::kill_process_group(self.0, rustix::process::Signal::KILL);
    }
}

#[cfg(unix)]
impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        self.kill();
    }
}

#[cfg(unix)]
fn execute(command: RunCommand) -> Result<String, ProductError> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;

    let maximum_encoded_bytes = command
        .limits
        .max_total_bytes
        .checked_add(MAX_CAPSULE_METADATA_BYTES)
        .ok_or_else(|| ProductError::usage("--max-bytes is too large"))?;
    let capsule_bytes =
        read_regular_file_bounded(&command.capsule, maximum_encoded_bytes, "capsule input")?;
    let capsule = Capsule::decode(&capsule_bytes).map_err(|error| {
        ProductError::operation(format!(
            "invalid capsule {}: {error}",
            command.capsule.display()
        ))
    })?;

    let policy_bytes =
        read_regular_file_bounded(&command.policy, MAX_TRUST_POLICY_BYTES, "trust policy")?;
    let policy = TrustPolicy::from_json(&policy_bytes)
        .map_err(|error| ProductError::operation(format!("invalid trust policy: {error}")))?;
    let mut signatures = Vec::with_capacity(command.signatures.len());
    for path in &command.signatures {
        let bytes =
            read_regular_file_bounded(path, MAX_SIGNATURE_ENVELOPE_BYTES, "signature envelope")?;
        signatures.push(SignatureEnvelope::from_json(&bytes).map_err(|error| {
            ProductError::operation(format!(
                "invalid signature envelope {}: {error}",
                path.display()
            ))
        })?);
    }
    let trust = policy
        .verify(&capsule_bytes, &signatures)
        .map_err(|error| ProductError::operation(format!("execution trust failed: {error}")))?;

    let materialization_parent = tempfile::Builder::new()
        .prefix("scicapsule-run-")
        .tempdir()
        .map_err(|error| {
            ProductError::operation(format!("cannot create private run directory: {error}"))
        })?;
    let materialized = materialization_parent.path().join("root");
    let summary = extract_capsule(&capsule, &materialized, command.limits).map_err(|error| {
        ProductError::operation(format!("cannot materialize capsule for execution: {error}"))
    })?;

    let metadata = fs::symlink_metadata(&summary.entrypoint).map_err(|error| {
        ProductError::operation(format!(
            "cannot inspect materialized entrypoint {}: {error}",
            summary.entrypoint.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(ProductError::operation(format!(
            "materialized entrypoint {} is not a regular file",
            summary.entrypoint.display()
        )));
    }
    fs::set_permissions(&summary.entrypoint, fs::Permissions::from_mode(0o500)).map_err(
        |error| {
            ProductError::operation(format!(
                "cannot make materialized entrypoint executable {}: {error}",
                summary.entrypoint.display()
            ))
        },
    )?;

    let mut process = Command::new(&summary.entrypoint);
    process
        .args(&command.arguments)
        .current_dir(&summary.destination)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .process_group(0);
    for (name, value) in &command.environment {
        process.env(name, value);
    }

    let mut child = process.spawn().map_err(|error| {
        ProductError::operation(format!(
            "cannot execute manifest entrypoint {}: {error}",
            capsule.manifest().entrypoint()
        ))
    })?;
    let process_group = ProcessGroupGuard(rustix::process::Pid::from_child(&child));
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(command.timeout_seconds))
        .ok_or_else(|| ProductError::operation("execution deadline overflow"))?;

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                process_group.kill();
                let _ = child.wait();
                return Err(ProductError::operation(format!(
                    "capsule execution timed out after {} second(s)",
                    command.timeout_seconds
                )));
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                process_group.kill();
                let _ = child.wait();
                return Err(ProductError::operation(format!(
                    "cannot wait for capsule entrypoint: {error}"
                )));
            }
        }
    };

    if !status.success() {
        return Err(ProductError::operation(format!(
            "capsule entrypoint exited unsuccessfully: {status}"
        )));
    }

    Ok(format!(
        "executed {}: {} entrypoint={} matched [{}], require {}\n",
        command.capsule.display(),
        capsule.manifest().name(),
        capsule.manifest().entrypoint(),
        trust.matched_signers.join(","),
        trust.required_signatures
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn parser_requires_explicit_trust_inputs() {
        let missing = parse(&args(&["run", "demo.scicap"])).unwrap_err();
        assert!(missing.usage);
        assert!(missing.to_string().contains("--signature"));

        let policy = parse(&args(&["run", "demo.scicap", "--signature", "demo.sig"])).unwrap_err();
        assert!(policy.to_string().contains("--policy"));
    }

    #[test]
    fn parser_separates_options_from_verbatim_entrypoint_arguments() {
        let parsed = parse(&args(&[
            "run",
            "demo.scicap",
            "--policy",
            "policy.json",
            "--signature",
            "demo.sig",
            "--env",
            "LANG=C",
            "--",
            "--not-a-runner-option",
            "value",
        ]))
        .unwrap();
        assert_eq!(parsed.arguments, vec!["--not-a-runner-option", "value"]);
        assert_eq!(
            parsed.environment,
            vec![("LANG".to_owned(), "C".to_owned())]
        );
    }

    #[test]
    fn parser_rejects_duplicate_environment_and_unbounded_timeout() {
        let duplicate = parse(&args(&[
            "run",
            "demo.scicap",
            "--policy",
            "policy.json",
            "--signature",
            "demo.sig",
            "--env",
            "A=1",
            "--env",
            "A=2",
        ]))
        .unwrap_err();
        assert!(duplicate.to_string().contains("duplicate --env"));

        let timeout = parse(&args(&[
            "run",
            "demo.scicap",
            "--policy",
            "policy.json",
            "--signature",
            "demo.sig",
            "--timeout-seconds",
            "86401",
        ]))
        .unwrap_err();
        assert!(timeout.to_string().contains("between 1 and"));
    }

    #[cfg(unix)]
    fn trusted_fixture(script: &[u8], seed: u8) -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        use ed25519_dalek::{
            pkcs8::{EncodePrivateKey, EncodePublicKey},
            SigningKey,
        };
        use pkcs8::LineEnding;

        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-tmp");
        fs::create_dir_all(&base).unwrap();
        let dir = tempfile::Builder::new()
            .prefix("execution-")
            .tempdir_in(base)
            .unwrap();
        let source = dir.path().join("run.sh");
        let capsule = dir.path().join("demo.scicap");
        let signature = dir.path().join("demo.sig");
        let policy = dir.path().join("policy.json");
        fs::write(&source, script).unwrap();
        scicapsule::run(&[
            "pack".to_owned(),
            "--name".to_owned(),
            "demo".to_owned(),
            "--entrypoint".to_owned(),
            "bin/run".to_owned(),
            "--output".to_owned(),
            capsule.display().to_string(),
            format!("bin/run={}", source.display()),
        ])
        .unwrap();

        let signing_key = SigningKey::from_bytes(&[seed; ed25519_dalek::SECRET_KEY_LENGTH]);
        let private_pem = signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string();
        let public_pem = signing_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let capsule_bytes = fs::read(&capsule).unwrap();
        let envelope = crate::signature::sign_capsule(&capsule_bytes, &private_pem).unwrap();
        fs::write(&signature, envelope.to_json().unwrap()).unwrap();
        let trust =
            TrustPolicy::from_named_pem_keys(1, vec![("release".to_owned(), public_pem)]).unwrap();
        fs::write(&policy, trust.to_json().unwrap()).unwrap();
        (dir, capsule, signature, policy)
    }

    #[cfg(unix)]
    #[test]
    fn trusted_execution_runs_exact_entrypoint_with_explicit_environment_and_arguments() {
        let (_dir, capsule, signature, policy) = trusted_fixture(
            b"#!/bin/sh\n[ \"$SCICAPSULE_TEST\" = \"ok\" ] || exit 21\n[ \"$1\" = \"--literal\" ] || exit 22\n[ \"$2\" = '$(false)' ] || exit 23\nexit 0\n",
            81,
        );
        let result = run(&[
            "run".to_owned(),
            capsule.display().to_string(),
            "--policy".to_owned(),
            policy.display().to_string(),
            "--signature".to_owned(),
            signature.display().to_string(),
            "--env".to_owned(),
            "SCICAPSULE_TEST=ok".to_owned(),
            "--timeout-seconds".to_owned(),
            "5".to_owned(),
            "--".to_owned(),
            "--literal".to_owned(),
            "$(false)".to_owned(),
        ])
        .unwrap();
        assert!(result.contains("executed"));
        assert!(result.contains("matched [release]"));
    }

    #[cfg(unix)]
    #[test]
    fn untrusted_signature_fails_before_entrypoint_execution() {
        let (dir, capsule, _trusted_signature, policy) =
            trusted_fixture(b"#!/bin/sh\nprintf ran > \"$MARKER\"\n", 82);
        let marker = dir.path().join("marker");
        let other = trusted_fixture(b"#!/bin/sh\nexit 0\n", 83);
        let untrusted_signature = other.2;
        let error = run(&[
            "run".to_owned(),
            capsule.display().to_string(),
            "--policy".to_owned(),
            policy.display().to_string(),
            "--signature".to_owned(),
            untrusted_signature.display().to_string(),
            "--env".to_owned(),
            format!("MARKER={}", marker.display()),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("execution trust failed"));
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn timeout_terminates_entrypoint_process_group() {
        let (_dir, capsule, signature, policy) = trusted_fixture(b"#!/bin/sh\n/bin/sleep 5\n", 84);
        let error = run(&[
            "run".to_owned(),
            capsule.display().to_string(),
            "--policy".to_owned(),
            policy.display().to_string(),
            "--signature".to_owned(),
            signature.display().to_string(),
            "--timeout-seconds".to_owned(),
            "1".to_owned(),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("timed out after 1 second"));
    }
}
