#![forbid(unsafe_code)]

mod signature;

use scirust_capsule::Capsule;
use signature::{sign_capsule, verify_capsule_signature, SignatureEnvelope};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const MAX_SIGNATURE_ENVELOPE_BYTES: u64 = 16 * 1024;
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;

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
    }
}

fn help_text() -> String {
    let mut help = scicapsule::help_text();
    help.push_str(
        "\nSIGNATURE COMMANDS:\n\
    scicapsule sign FILE --key PRIVATE_KEY.pem --output FILE.sig\n\
    scicapsule verify-signature FILE --signature FILE.sig --key PUBLIC_KEY.pem\n\n\
    sign               Verify a canonical capsule, then create a detached Ed25519 v1 signature\n\
    verify-signature   Verify capsule integrity and a detached signature against an explicit key\n\n\
SIGNATURE OPTIONS:\n\
    --key FILE          PKCS#8 private PEM for sign; SPKI public PEM for verify-signature\n\
    --output FILE       New detached signature envelope; existing files are never overwritten\n\
    --signature FILE    Detached signature envelope to verify\n",
    );
    help
}

fn parse_product_command(args: &[String]) -> Result<ProductCommand, ProductError> {
    match args {
        [] => Ok(ProductCommand::Help),
        [argument] if argument == "-h" || argument == "--help" => Ok(ProductCommand::Help),
        [command, rest @ ..] if command == "sign" => parse_sign(rest),
        [command, rest @ ..] if command == "verify-signature" => parse_verify_signature(rest),
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
        signature: signature.ok_or_else(|| {
            ProductError::usage("verify-signature requires --signature FILE")
        })?,
        key: key
            .ok_or_else(|| ProductError::usage("verify-signature requires --key PUBLIC_KEY.pem"))?,
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
    *index += 1;
    args.get(*index)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| ProductError::usage(format!("{option} requires a value")))
}

fn sign_command(capsule_path: &Path, key_path: &Path, output: &Path) -> Result<String, ProductError> {
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
    write_new_file(output, &encoded)?;

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
    let envelope = SignatureEnvelope::from_json(&signature_bytes).map_err(|error| {
        ProductError::operation(format!("invalid signature envelope: {error}"))
    })?;
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

fn read_file(path: &Path) -> Result<Vec<u8>, ProductError> {
    fs::read(path)
        .map_err(|error| ProductError::operation(format!("cannot read {}: {error}", path.display())))
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
        ProductError::operation(format!("cannot inspect {label} {}: {error}", path.display()))
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
        ProductError::operation(format!("cannot inspect {label} {}: {error}", path.display()))
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

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), ProductError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }

    let mut file = options.open(path).map_err(|error| {
        ProductError::operation(format!(
            "cannot create new signature file {}: {error}",
            path.display()
        ))
    })?;
    let result = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            ProductError::operation(format!(
                "cannot write signature file {}: {error}",
                path.display()
            ))
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
        pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
        SigningKey,
    };
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

    #[test]
    fn help_exposes_signature_commands_without_changing_core_verify_semantics() {
        let help = help_text();
        assert!(help.contains("scicapsule sign FILE"));
        assert!(help.contains("scicapsule verify-signature FILE"));
        assert!(help.contains("verify canonical encoding, lengths, and payload SHA-256"));
    }

    #[test]
    fn parser_requires_explicit_key_signature_and_output_paths() {
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
    }

    #[test]
    fn sign_and_verify_signature_round_trip() {
        let dir = test_dir("round-trip");
        let capsule = pack_capsule(&dir);
        let (private, public) = write_keys(&dir, 17);
        let envelope = dir.join("demo.sig");

        let signed = run_product(&[
            "sign".to_owned(),
            capsule.display().to_string(),
            "--key".to_owned(),
            private.display().to_string(),
            "--output".to_owned(),
            envelope.display().to_string(),
        ])
        .unwrap();
        assert!(signed.contains("signed"));

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
    fn verification_rejects_wrong_key_and_tampered_capsule() {
        let dir = test_dir("negative");
        let capsule = pack_capsule(&dir);
        let (private, public) = write_keys(&dir, 23);
        let (_, wrong_public) = write_keys(&dir, 24);
        let envelope = dir.join("demo.sig");

        run_product(&[
            "sign".to_owned(),
            capsule.display().to_string(),
            "--key".to_owned(),
            private.display().to_string(),
            "--output".to_owned(),
            envelope.display().to_string(),
        ])
        .unwrap();

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
    fn sign_never_overwrites_an_existing_envelope() {
        let dir = test_dir("no-clobber");
        let capsule = pack_capsule(&dir);
        let (private, _) = write_keys(&dir, 29);
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
        assert!(error.to_string().contains("cannot create new signature file"));
        assert_eq!(fs::read(&envelope).unwrap(), b"existing");
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn signature_key_inputs_reject_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = test_dir("key-symlink");
        let capsule = pack_capsule(&dir);
        let (private, _) = write_keys(&dir, 37);
        let linked_private = dir.join("linked-private.pem");
        let envelope = dir.join("demo.sig");
        symlink(&private, &linked_private).unwrap();

        let error = run_product(&[
            "sign".to_owned(),
            capsule.display().to_string(),
            "--key".to_owned(),
            linked_private.display().to_string(),
            "--output".to_owned(),
            envelope.display().to_string(),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("safely open private key"));
        assert!(!envelope.exists());
        fs::remove_dir_all(dir).unwrap();
    }
}
