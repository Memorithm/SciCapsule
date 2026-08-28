#![forbid(unsafe_code)]

mod signature;
mod trust;

use scirust_capsule::Capsule;
use signature::{sign_capsule, verify_capsule_signature, SignatureEnvelope};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use trust::{TrustPolicy, MAX_SIGNATURES, MAX_TRUSTED_KEYS};

const MAX_SIGNATURE_ENVELOPE_BYTES: u64 = 16 * 1024;
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;
const MAX_TRUST_POLICY_BYTES: u64 = 256 * 1024;

#[derive(Debug, Eq, PartialEq)]
enum ProductCommand {
    Help,
    Delegate,
    Sign {
        capsule: PathBuf,
        key: PathBuf,
        output: PathBuf,
    },
    VerifySignature {
        capsule: PathBuf,
        signature: PathBuf,
        key: PathBuf,
    },
    CreateTrustPolicy {
        output: PathBuf,
        minimum_signatures: u32,
        keys: Vec<(String, PathBuf)>,
    },
    VerifyTrusted {
        capsule: PathBuf,
        policy: PathBuf,
        signatures: Vec<PathBuf>,
    },
}

#[derive(Debug)]
struct ProductError {
    message: String,
    usage: bool,
}

impl ProductError {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            usage: true,
        }
    }

    fn operation(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            usage: false,
        }
    }

    fn from_core(error: scicapsule::CliError) -> Self {
        Self {
            usage: error.is_usage(),
            message: error.to_string(),
        }
    }
}

impl fmt::Display for ProductError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ProductError {}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run_product(&args) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            if error.usage {
                eprintln!("run `scicapsule --help` for usage");
                ExitCode::from(2)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn run_product(args: &[String]) -> Result<String, ProductError> {
    match parse_product_command(args)? {
        ProductCommand::Help => Ok(help_text()),
        ProductCommand::Delegate => scicapsule::run(args).map_err(ProductError::from_core),
        ProductCommand::Sign {
            capsule,
            key,
            output,
        } => sign_command(&capsule, &key, &output),
        ProductCommand::VerifySignature {
            capsule,
            signature,
            key,
        } => verify_signature_command(&capsule, &signature, &key),
        ProductCommand::CreateTrustPolicy {
            output,
            minimum_signatures,
            keys,
        } => create_trust_policy_command(&output, minimum_signatures, &keys),
        ProductCommand::VerifyTrusted {
            capsule,
            policy,
            signatures,
        } => verify_trusted_command(&capsule, &policy, &signatures),
    }
}

fn help_text() -> String {
    let mut help = scicapsule::help_text();
    help.push_str(
        "\nSIGNATURE AND TRUST COMMANDS:\n\
    scicapsule sign FILE --key PRIVATE_KEY.pem --output FILE.sig\n\
    scicapsule verify-signature FILE --signature FILE.sig --key PUBLIC_KEY.pem\n\
    scicapsule create-trust-policy --output POLICY.json --require N NAME=PUBLIC_KEY.pem ...\n\
    scicapsule verify-trusted FILE --policy POLICY.json --signature FILE.sig [--signature FILE.sig ...]\n\n\
    sign                 Verify a canonical capsule, then create a detached Ed25519 v1 signature\n\
    verify-signature     Verify capsule integrity and a detached signature against an explicit key\n\
    create-trust-policy  Create a versioned local Ed25519 trust policy from explicit public keys\n\
    verify-trusted       Require a policy threshold of distinct trusted signing keys\n\n\
SIGNATURE AND TRUST OPTIONS:\n\
    --key FILE          PKCS#8 private PEM for sign; SPKI public PEM for verify-signature\n\
    --output FILE       New output file; existing files are never overwritten\n\
    --signature FILE    Detached signature envelope; repeatable for verify-trusted\n\
    --policy FILE       Local trust-policy JSON file\n\
    --require N         Minimum number of distinct trusted signing keys required\n",
    );
    help
}

fn parse_product_command(args: &[String]) -> Result<ProductCommand, ProductError> {
    match args {
        [] => Ok(ProductCommand::Help),
        [argument] if argument == "-h" || argument == "--help" => Ok(ProductCommand::Help),
        [command, rest @ ..] if command == "sign" => parse_sign(rest),
        [command, rest @ ..] if command == "verify-signature" => parse_verify_signature(rest),
        [command, rest @ ..] if command == "create-trust-policy" => parse_create_trust_policy(rest),
        [command, rest @ ..] if command == "verify-trusted" => parse_verify_trusted(rest),
        _ => Ok(ProductCommand::Delegate),
    }
}

fn parse_sign(args: &[String]) -> Result<ProductCommand, ProductError> {
    if matches!(args, [argument] if argument == "-h" || argument == "--help") {
        return Ok(ProductCommand::Help);
    }

    let mut capsule = None;
    let mut key = None;
    let mut output = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--key" => {
                key = Some(PathBuf::from(take_unique_value(
                    args,
                    &mut index,
                    "--key",
                    key.is_some(),
                )?));
            }
            "--output" => {
                output = Some(PathBuf::from(take_unique_value(
                    args,
                    &mut index,
                    "--output",
                    output.is_some(),
                )?));
            }
            argument if argument.starts_with('-') => {
                return Err(ProductError::usage(format!(
                    "unknown sign option: {argument}"
                )));
            }
            argument if capsule.is_none() => capsule = Some(PathBuf::from(argument)),
            argument => {
                return Err(ProductError::usage(format!(
                    "unexpected sign argument: {argument}"
                )));
            }
        }
        index += 1;
    }

    Ok(ProductCommand::Sign {
        capsule: capsule.ok_or_else(|| ProductError::usage("sign requires a capsule file"))?,
        key: key.ok_or_else(|| ProductError::usage("sign requires --key PRIVATE_KEY.pem"))?,
        output: output.ok_or_else(|| ProductError::usage("sign requires --output FILE"))?,
    })
}

fn parse_verify_signature(args: &[String]) -> Result<ProductCommand, ProductError> {
    if matches!(args, [argument] if argument == "-h" || argument == "--help") {
        return Ok(ProductCommand::Help);
    }

    let mut capsule = None;
    let mut signature = None;
    let mut key = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--signature" => {
                signature = Some(PathBuf::from(take_unique_value(
                    args,
                    &mut index,
                    "--signature",
                    signature.is_some(),
                )?));
            }
            "--key" => {
                key = Some(PathBuf::from(take_unique_value(
                    args,
                    &mut index,
                    "--key",
                    key.is_some(),
                )?));
            }
            argument if argument.starts_with('-') => {
                return Err(ProductError::usage(format!(
                    "unknown verify-signature option: {argument}"
                )));
            }
            argument if capsule.is_none() => capsule = Some(PathBuf::from(argument)),
            argument => {
                return Err(ProductError::usage(format!(
                    "unexpected verify-signature argument: {argument}"
                )));
            }
        }
        index += 1;
    }

    Ok(ProductCommand::VerifySignature {
        capsule: capsule
            .ok_or_else(|| ProductError::usage("verify-signature requires a capsule file"))?,
        signature: signature
            .ok_or_else(|| ProductError::usage("verify-signature requires --signature FILE"))?,
        key: key
            .ok_or_else(|| ProductError::usage("verify-signature requires --key PUBLIC_KEY.pem"))?,
    })
}

fn parse_create_trust_policy(args: &[String]) -> Result<ProductCommand, ProductError> {
    if matches!(args, [argument] if argument == "-h" || argument == "--help") {
        return Ok(ProductCommand::Help);
    }

    let mut output = None;
    let mut minimum_signatures = None;
    let mut keys = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--output" => {
                output = Some(PathBuf::from(take_unique_value(
                    args,
                    &mut index,
                    "--output",
                    output.is_some(),
                )?));
            }
            "--require" => {
                let raw =
                    take_unique_value(args, &mut index, "--require", minimum_signatures.is_some())?;
                let value = raw.parse::<u32>().map_err(|_| {
                    ProductError::usage(format!(
                        "--require expects a positive integer, got {raw:?}"
                    ))
                })?;
                if value == 0 {
                    return Err(ProductError::usage("--require must be at least 1"));
                }
                minimum_signatures = Some(value);
            }
            argument if argument.starts_with('-') => {
                return Err(ProductError::usage(format!(
                    "unknown create-trust-policy option: {argument}"
                )));
            }
            mapping => {
                let (name, path) = mapping.split_once('=').ok_or_else(|| {
                    ProductError::usage(format!(
                        "trusted key mapping must be NAME=PUBLIC_KEY.pem: {mapping}"
                    ))
                })?;
                if name.is_empty() || path.is_empty() {
                    return Err(ProductError::usage(format!(
                        "trusted key mapping must contain a non-empty name and path: {mapping}"
                    )));
                }
                keys.push((name.to_owned(), PathBuf::from(path)));
                if keys.len() > MAX_TRUSTED_KEYS {
                    return Err(ProductError::usage(format!(
                        "too many trusted keys; limit is {MAX_TRUSTED_KEYS}"
                    )));
                }
            }
        }
        index += 1;
    }

    if keys.is_empty() {
        return Err(ProductError::usage(
            "create-trust-policy requires at least one NAME=PUBLIC_KEY.pem mapping",
        ));
    }

    Ok(ProductCommand::CreateTrustPolicy {
        output: output
            .ok_or_else(|| ProductError::usage("create-trust-policy requires --output FILE"))?,
        minimum_signatures: minimum_signatures
            .ok_or_else(|| ProductError::usage("create-trust-policy requires --require N"))?,
        keys,
    })
}

fn parse_verify_trusted(args: &[String]) -> Result<ProductCommand, ProductError> {
    if matches!(args, [argument] if argument == "-h" || argument == "--help") {
        return Ok(ProductCommand::Help);
    }

    let mut capsule = None;
    let mut policy = None;
    let mut signatures = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--policy" => {
                policy = Some(PathBuf::from(take_unique_value(
                    args,
                    &mut index,
                    "--policy",
                    policy.is_some(),
                )?));
            }
            "--signature" => {
                let value = take_value(args, &mut index, "--signature")?;
                signatures.push(PathBuf::from(value));
                if signatures.len() > MAX_SIGNATURES {
                    return Err(ProductError::usage(format!(
                        "too many --signature values; limit is {MAX_SIGNATURES}"
                    )));
                }
            }
            argument if argument.starts_with('-') => {
                return Err(ProductError::usage(format!(
                    "unknown verify-trusted option: {argument}"
                )));
            }
            argument if capsule.is_none() => capsule = Some(PathBuf::from(argument)),
            argument => {
                return Err(ProductError::usage(format!(
                    "unexpected verify-trusted argument: {argument}"
                )));
            }
        }
        index += 1;
    }

    if signatures.is_empty() {
        return Err(ProductError::usage(
            "verify-trusted requires at least one --signature FILE",
        ));
    }

    Ok(ProductCommand::VerifyTrusted {
        capsule: capsule
            .ok_or_else(|| ProductError::usage("verify-trusted requires a capsule file"))?,
        policy: policy
            .ok_or_else(|| ProductError::usage("verify-trusted requires --policy FILE"))?,
        signatures,
    })
}

fn take_unique_value(
    args: &[String],
    index: &mut usize,
    option: &str,
    already_set: bool,
) -> Result<String, ProductError> {
    if already_set {
        return Err(ProductError::usage(format!(
            "{option} may be specified only once"
        )));
    }
    take_value(args, index, option)
}

fn take_value(args: &[String], index: &mut usize, option: &str) -> Result<String, ProductError> {
    *index += 1;
    args.get(*index)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| ProductError::usage(format!("{option} requires a value")))
}

fn sign_command(
    capsule_path: &Path,
    key_path: &Path,
    output: &Path,
) -> Result<String, ProductError> {
    let capsule_bytes = read_file(capsule_path)?;
    let capsule = Capsule::decode(&capsule_bytes).map_err(|error| {
        ProductError::operation(format!(
            "invalid capsule {}: {error}",
            capsule_path.display()
        ))
    })?;
    let private_key = read_regular_utf8_bounded(key_path, MAX_KEY_FILE_BYTES, "private key")?;
    let envelope = sign_capsule(&capsule_bytes, &private_key)
        .map_err(|error| ProductError::operation(format!("cannot sign capsule: {error}")))?;
    let encoded = envelope.to_json().map_err(|error| {
        ProductError::operation(format!("cannot encode signature envelope: {error}"))
    })?;
    write_new_file(output, &encoded, "signature file")?;

    Ok(format!(
        "signed {}: {} -> {}\n",
        capsule_path.display(),
        capsule.manifest().name(),
        output.display()
    ))
}

fn verify_signature_command(
    capsule_path: &Path,
    signature_path: &Path,
    key_path: &Path,
) -> Result<String, ProductError> {
    let capsule_bytes = read_file(capsule_path)?;
    let capsule = Capsule::decode(&capsule_bytes).map_err(|error| {
        ProductError::operation(format!(
            "invalid capsule {}: {error}",
            capsule_path.display()
        ))
    })?;
    let signature_bytes = read_regular_file_bounded(
        signature_path,
        MAX_SIGNATURE_ENVELOPE_BYTES,
        "signature envelope",
    )?;
    let envelope = SignatureEnvelope::from_json(&signature_bytes)
        .map_err(|error| ProductError::operation(format!("invalid signature envelope: {error}")))?;
    let public_key = read_regular_utf8_bounded(key_path, MAX_KEY_FILE_BYTES, "public key")?;
    verify_capsule_signature(&capsule_bytes, &envelope, &public_key).map_err(|error| {
        ProductError::operation(format!("signature verification failed: {error}"))
    })?;

    Ok(format!(
        "verified signature {}: {} ({})\n",
        capsule_path.display(),
        capsule.manifest().name(),
        signature_path.display()
    ))
}

fn create_trust_policy_command(
    output: &Path,
    minimum_signatures: u32,
    keys: &[(String, PathBuf)],
) -> Result<String, ProductError> {
    let mut pem_keys = Vec::with_capacity(keys.len());
    for (name, path) in keys {
        let pem = read_regular_utf8_bounded(path, MAX_KEY_FILE_BYTES, "trusted public key")?;
        pem_keys.push((name.clone(), pem));
    }
    let policy = TrustPolicy::from_named_pem_keys(minimum_signatures, pem_keys)
        .map_err(|error| ProductError::operation(format!("invalid trust policy: {error}")))?;
    let encoded = policy
        .to_json()
        .map_err(|error| ProductError::operation(format!("cannot encode trust policy: {error}")))?;
    write_new_file(output, &encoded, "trust policy")?;

    Ok(format!(
        "created trust policy {}: require {} of {} trusted key(s)\n",
        output.display(),
        policy.minimum_signatures,
        policy.trusted_keys.len()
    ))
}

fn verify_trusted_command(
    capsule_path: &Path,
    policy_path: &Path,
    signature_paths: &[PathBuf],
) -> Result<String, ProductError> {
    let capsule_bytes = read_file(capsule_path)?;
    let capsule = Capsule::decode(&capsule_bytes).map_err(|error| {
        ProductError::operation(format!(
            "invalid capsule {}: {error}",
            capsule_path.display()
        ))
    })?;

    let policy_bytes =
        read_regular_file_bounded(policy_path, MAX_TRUST_POLICY_BYTES, "trust policy")?;
    let policy = TrustPolicy::from_json(&policy_bytes)
        .map_err(|error| ProductError::operation(format!("invalid trust policy: {error}")))?;

    let mut signatures = Vec::with_capacity(signature_paths.len());
    for signature_path in signature_paths {
        let signature_bytes = read_regular_file_bounded(
            signature_path,
            MAX_SIGNATURE_ENVELOPE_BYTES,
            "signature envelope",
        )?;
        let envelope = SignatureEnvelope::from_json(&signature_bytes).map_err(|error| {
            ProductError::operation(format!(
                "invalid signature envelope {}: {error}",
                signature_path.display()
            ))
        })?;
        signatures.push(envelope);
    }

    let decision = policy
        .verify(&capsule_bytes, &signatures)
        .map_err(|error| ProductError::operation(format!("trust verification failed: {error}")))?;

    Ok(format!(
        "trusted {}: {} matched [{}], require {}\n",
        capsule_path.display(),
        capsule.manifest().name(),
        decision.matched_signers.join(","),
        decision.required_signatures
    ))
}

fn read_file(path: &Path) -> Result<Vec<u8>, ProductError> {
    fs::read(path).map_err(|error| {
        ProductError::operation(format!("cannot read {}: {error}", path.display()))
    })
}

fn read_regular_utf8_bounded(
    path: &Path,
    maximum_bytes: u64,
    label: &str,
) -> Result<String, ProductError> {
    let bytes = read_regular_file_bounded(path, maximum_bytes, label)?;
    String::from_utf8(bytes).map_err(|_| {
        ProductError::operation(format!("{label} {} is not valid UTF-8", path.display()))
    })
}

fn read_regular_file_bounded(
    path: &Path,
    maximum_bytes: u64,
    label: &str,
) -> Result<Vec<u8>, ProductError> {
    let read_limit = maximum_bytes
        .checked_add(1)
        .ok_or_else(|| ProductError::operation("configured read limit is too large"))?;
    let file = open_regular_nofollow(path, label)?;
    let metadata = file.metadata().map_err(|error| {
        ProductError::operation(format!(
            "cannot inspect {label} {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(ProductError::operation(format!(
            "refusing to read non-regular {label} {}",
            path.display()
        )));
    }
    if metadata.len() > maximum_bytes {
        return Err(ProductError::operation(format!(
            "{label} {} is {} bytes; read limit is {} bytes",
            path.display(),
            metadata.len(),
            maximum_bytes
        )));
    }

    let mut bytes = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            ProductError::operation(format!("cannot read {label} {}: {error}", path.display()))
        })?;
    if bytes.len() as u128 > u128::from(maximum_bytes) {
        return Err(ProductError::operation(format!(
            "{label} {} exceeded the {} byte read limit",
            path.display(),
            maximum_bytes
        )));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_regular_nofollow(path: &Path, label: &str) -> Result<File, ProductError> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| {
        ProductError::operation(format!(
            "cannot safely open {label} {}: {error}",
            path.display()
        ))
    })?;
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_regular_nofollow(path: &Path, label: &str) -> Result<File, ProductError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        ProductError::operation(format!(
            "cannot inspect {label} {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(ProductError::operation(format!(
            "refusing to read non-regular or linked {label} {}",
            path.display()
        )));
    }
    File::open(path).map_err(|error| {
        ProductError::operation(format!("cannot read {label} {}: {error}", path.display()))
    })
}

fn write_new_file(path: &Path, bytes: &[u8], label: &str) -> Result<(), ProductError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }

    let mut file = options.open(path).map_err(|error| {
        ProductError::operation(format!(
            "cannot create new {label} {}: {error}",
            path.display()
        ))
    })?;
    let result = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            ProductError::operation(format!("cannot write {label} {}: {error}", path.display()))
        });
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{
        pkcs8::{EncodePrivateKey, EncodePublicKey},
        SigningKey,
    };
    use pkcs8::LineEnding;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn test_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-tmp");
        fs::create_dir_all(&base).unwrap();
        let path = base.join(format!("signature-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn write_keys(dir: &Path, seed: u8) -> (PathBuf, PathBuf) {
        let signing_key = SigningKey::from_bytes(&[seed; ed25519_dalek::SECRET_KEY_LENGTH]);
        let private = signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string();
        let public = signing_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let private_path = dir.join(format!("private-{seed}.pem"));
        let public_path = dir.join(format!("public-{seed}.pem"));
        fs::write(&private_path, private).unwrap();
        fs::write(&public_path, public).unwrap();
        (private_path, public_path)
    }

    fn pack_capsule(dir: &Path) -> PathBuf {
        let runner = dir.join("run.bin");
        let capsule = dir.join("demo.scicap");
        fs::write(&runner, b"runner bytes").unwrap();
        let spec = format!("bin/run={}", runner.display());
        scicapsule::run(&[
            "pack".to_owned(),
            "--name".to_owned(),
            "demo".to_owned(),
            "--entrypoint".to_owned(),
            "bin/run".to_owned(),
            "--output".to_owned(),
            capsule.display().to_string(),
            spec,
        ])
        .unwrap();
        capsule
    }

    fn sign_file(capsule: &Path, private_key: &Path, output: &Path) {
        run_product(&[
            "sign".to_owned(),
            capsule.display().to_string(),
            "--key".to_owned(),
            private_key.display().to_string(),
            "--output".to_owned(),
            output.display().to_string(),
        ])
        .unwrap();
    }

    fn create_policy(
        output: &Path,
        required: u32,
        keys: &[(&str, &Path)],
    ) -> Result<String, ProductError> {
        let mut command = vec![
            "create-trust-policy".to_owned(),
            "--output".to_owned(),
            output.display().to_string(),
            "--require".to_owned(),
            required.to_string(),
        ];
        for (name, path) in keys {
            command.push(format!("{name}={}", path.display()));
        }
        run_product(&command)
    }

    #[test]
    fn help_exposes_signature_and_trust_commands_without_changing_core_verify_semantics() {
        let help = help_text();
        assert!(help.contains("scicapsule sign FILE"));
        assert!(help.contains("scicapsule verify-signature FILE"));
        assert!(help.contains("scicapsule create-trust-policy"));
        assert!(help.contains("scicapsule verify-trusted FILE"));
        assert!(help.contains("verify canonical encoding, lengths, and payload SHA-256"));
    }

    #[test]
    fn parser_requires_explicit_signature_and_trust_inputs() {
        let sign = parse_product_command(&args(&["sign", "demo.scicap"])).unwrap_err();
        assert!(sign.usage);
        assert!(sign.to_string().contains("--key"));

        let verify = parse_product_command(&args(&[
            "verify-signature",
            "demo.scicap",
            "--key",
            "public.pem",
        ]))
        .unwrap_err();
        assert!(verify.usage);
        assert!(verify.to_string().contains("--signature"));

        let policy = parse_product_command(&args(&[
            "create-trust-policy",
            "--output",
            "policy.json",
            "release=public.pem",
        ]))
        .unwrap_err();
        assert!(policy.usage);
        assert!(policy.to_string().contains("--require"));

        let trusted = parse_product_command(&args(&[
            "verify-trusted",
            "demo.scicap",
            "--policy",
            "policy.json",
        ]))
        .unwrap_err();
        assert!(trusted.usage);
        assert!(trusted.to_string().contains("--signature"));
    }

    #[test]
    fn sign_and_verify_signature_round_trip() {
        let dir = test_dir("round-trip");
        let capsule = pack_capsule(&dir);
        let (private, public) = write_keys(&dir, 17);
        let envelope = dir.join("demo.sig");

        sign_file(&capsule, &private, &envelope);

        let verified = run_product(&[
            "verify-signature".to_owned(),
            capsule.display().to_string(),
            "--signature".to_owned(),
            envelope.display().to_string(),
            "--key".to_owned(),
            public.display().to_string(),
        ])
        .unwrap();
        assert!(verified.contains("verified signature"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn trust_policy_requires_distinct_trusted_signers() {
        let dir = test_dir("trust-threshold");
        let capsule = pack_capsule(&dir);
        let (private_a, public_a) = write_keys(&dir, 41);
        let (private_b, public_b) = write_keys(&dir, 42);
        let sig_a = dir.join("a.sig");
        let sig_b = dir.join("b.sig");
        let policy = dir.join("policy.json");
        sign_file(&capsule, &private_a, &sig_a);
        sign_file(&capsule, &private_b, &sig_b);
        create_policy(
            &policy,
            2,
            &[("alpha", public_a.as_path()), ("beta", public_b.as_path())],
        )
        .unwrap();

        let duplicate_error = run_product(&[
            "verify-trusted".to_owned(),
            capsule.display().to_string(),
            "--policy".to_owned(),
            policy.display().to_string(),
            "--signature".to_owned(),
            sig_a.display().to_string(),
            "--signature".to_owned(),
            sig_a.display().to_string(),
        ])
        .unwrap_err();
        assert!(duplicate_error.to_string().contains("threshold not met"));

        let trusted = run_product(&[
            "verify-trusted".to_owned(),
            capsule.display().to_string(),
            "--policy".to_owned(),
            policy.display().to_string(),
            "--signature".to_owned(),
            sig_b.display().to_string(),
            "--signature".to_owned(),
            sig_a.display().to_string(),
        ])
        .unwrap();
        assert!(trusted.contains("matched [alpha,beta]"));
        assert!(trusted.contains("require 2"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn trust_policy_rejects_unknown_signer_and_malformed_policy() {
        let dir = test_dir("trust-negative");
        let capsule = pack_capsule(&dir);
        let (_, public_trusted) = write_keys(&dir, 51);
        let (private_unknown, _) = write_keys(&dir, 52);
        let sig_unknown = dir.join("unknown.sig");
        let policy = dir.join("policy.json");
        sign_file(&capsule, &private_unknown, &sig_unknown);
        create_policy(&policy, 1, &[("release", public_trusted.as_path())]).unwrap();

        let unknown_error = run_product(&[
            "verify-trusted".to_owned(),
            capsule.display().to_string(),
            "--policy".to_owned(),
            policy.display().to_string(),
            "--signature".to_owned(),
            sig_unknown.display().to_string(),
        ])
        .unwrap_err();
        assert!(unknown_error.to_string().contains("threshold not met"));

        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&policy).unwrap()).unwrap();
        value["version"] = serde_json::Value::from(999_u64);
        fs::write(&policy, serde_json::to_vec(&value).unwrap()).unwrap();
        let malformed_error = run_product(&[
            "verify-trusted".to_owned(),
            capsule.display().to_string(),
            "--policy".to_owned(),
            policy.display().to_string(),
            "--signature".to_owned(),
            sig_unknown.display().to_string(),
        ])
        .unwrap_err();
        assert!(malformed_error
            .to_string()
            .contains("unsupported trust policy version"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn verification_rejects_wrong_key_and_tampered_capsule() {
        let dir = test_dir("negative");
        let capsule = pack_capsule(&dir);
        let (private, public) = write_keys(&dir, 23);
        let (_, wrong_public) = write_keys(&dir, 24);
        let envelope = dir.join("demo.sig");

        sign_file(&capsule, &private, &envelope);

        let wrong_key_error = run_product(&[
            "verify-signature".to_owned(),
            capsule.display().to_string(),
            "--signature".to_owned(),
            envelope.display().to_string(),
            "--key".to_owned(),
            wrong_public.display().to_string(),
        ])
        .unwrap_err();
        assert!(!wrong_key_error.usage);
        assert!(wrong_key_error.to_string().contains("verification failed"));

        let mut bytes = fs::read(&capsule).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&capsule, bytes).unwrap();
        let tampered_error = run_product(&[
            "verify-signature".to_owned(),
            capsule.display().to_string(),
            "--signature".to_owned(),
            envelope.display().to_string(),
            "--key".to_owned(),
            public.display().to_string(),
        ])
        .unwrap_err();
        assert!(tampered_error.to_string().contains("invalid capsule"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn sign_and_policy_creation_never_overwrite_existing_outputs() {
        let dir = test_dir("no-clobber");
        let capsule = pack_capsule(&dir);
        let (private, public) = write_keys(&dir, 29);
        let envelope = dir.join("demo.sig");
        fs::write(&envelope, b"existing").unwrap();

        let error = run_product(&[
            "sign".to_owned(),
            capsule.display().to_string(),
            "--key".to_owned(),
            private.display().to_string(),
            "--output".to_owned(),
            envelope.display().to_string(),
        ])
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("cannot create new signature file"));
        assert_eq!(fs::read(&envelope).unwrap(), b"existing");

        let policy = dir.join("policy.json");
        fs::write(&policy, b"existing-policy").unwrap();
        let policy_error = create_policy(&policy, 1, &[("release", public.as_path())]).unwrap_err();
        assert!(policy_error
            .to_string()
            .contains("cannot create new trust policy"));
        assert_eq!(fs::read(&policy).unwrap(), b"existing-policy");
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn security_sensitive_trust_inputs_reject_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = test_dir("trust-symlink");
        let capsule = pack_capsule(&dir);
        let (private, public) = write_keys(&dir, 61);
        let linked_public = dir.join("linked-public.pem");
        let policy = dir.join("policy.json");
        symlink(&public, &linked_public).unwrap();

        let key_error =
            create_policy(&policy, 1, &[("release", linked_public.as_path())]).unwrap_err();
        assert!(key_error
            .to_string()
            .contains("safely open trusted public key"));
        assert!(!policy.exists());

        create_policy(&policy, 1, &[("release", public.as_path())]).unwrap();
        let linked_policy = dir.join("linked-policy.json");
        symlink(&policy, &linked_policy).unwrap();
        let signature = dir.join("demo.sig");
        sign_file(&capsule, &private, &signature);
        let policy_error = run_product(&[
            "verify-trusted".to_owned(),
            capsule.display().to_string(),
            "--policy".to_owned(),
            linked_policy.display().to_string(),
            "--signature".to_owned(),
            signature.display().to_string(),
        ])
        .unwrap_err();
        assert!(policy_error
            .to_string()
            .contains("safely open trust policy"));
        fs::remove_dir_all(dir).unwrap();
    }
}
