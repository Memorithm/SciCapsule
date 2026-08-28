#![forbid(unsafe_code)]

pub mod extraction;

use scirust_capsule::{Capsule, CapsulePayload};
use scirust_capsule_schema::CapsulePath;
use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use extraction::{
    extract_capsule, ExtractionLimits, DEFAULT_EXTRACTION_LIMITS, MAX_CAPSULE_METADATA_BYTES,
};

/// Human-readable product name.
pub const PRODUCT_NAME: &str = "SciCapsule";

/// Canonical extension reserved for SciCapsule artifacts.
pub const FORMAT_EXTENSION: &str = "scicap";

/// Product version compiled into the binary.
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Product CLI help.
pub fn help_text() -> String {
    format!(
        "{PRODUCT_NAME} {}\n\
Portable, reproducible SciRust execution capsules.\n\n\
USAGE:\n\
    scicapsule pack --name NAME --entrypoint PATH --output FILE PATH=FILE [PATH=FILE ...]\n\
    scicapsule inspect FILE\n\
    scicapsule verify FILE\n\
    scicapsule extract FILE --output DIR [--max-files N] [--max-bytes N] [--json]\n\
    scicapsule [--help] [--version]\n\n\
COMMANDS:\n\
    pack       Build a deterministic .scicap from explicitly mapped payload files\n\
    inspect    Decode, verify, and print the embedded manifest\n\
    verify     Decode and verify canonical encoding, lengths, and payload SHA-256\n\
    extract    Verify and safely materialize regular payload files into a new directory\n\n\
PACK OPTIONS:\n\
    --name NAME          Human-readable capsule name\n\
    --entrypoint PATH    Portable payload path that is the capsule entrypoint\n\
    --output FILE        Destination .scicap file\n\
    PATH=FILE            Map a capsule payload path to a source file; repeatable\n\n\
EXTRACT OPTIONS:\n\
    --output DIR         New destination directory; it must not already exist\n\
    --max-files N        Maximum files (default: 4096)\n\
    --max-bytes N        Maximum total payload bytes (default: 1073741824)\n\
    --json               Emit a machine-readable extraction summary\n\n\
OPTIONS:\n\
    -h, --help           Print help\n\
    -V, --version        Print version\n",
        version()
    )
}

#[derive(Debug)]
pub struct CliError {
    message: String,
    usage: bool,
}

impl CliError {
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

    #[must_use]
    pub const fn is_usage(&self) -> bool {
        self.usage
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

#[derive(Debug, Eq, PartialEq)]
enum Command {
    Help,
    Version,
    Pack {
        name: String,
        entrypoint: String,
        output: PathBuf,
        payload_specs: Vec<String>,
    },
    Inspect(PathBuf),
    Verify(PathBuf),
    Extract {
        capsule: PathBuf,
        output: PathBuf,
        limits: ExtractionLimits,
        json: bool,
    },
}

/// Parse and execute product CLI arguments (excluding argv[0]).
pub fn run(args: &[String]) -> Result<String, CliError> {
    match parse_command(args)? {
        Command::Help => Ok(help_text()),
        Command::Version => Ok(format!("scicapsule {}\n", version())),
        Command::Pack {
            name,
            entrypoint,
            output,
            payload_specs,
        } => pack_command(&name, &entrypoint, &output, &payload_specs),
        Command::Inspect(path) => inspect_command(&path),
        Command::Verify(path) => verify_command(&path),
        Command::Extract {
            capsule,
            output,
            limits,
            json,
        } => extract_command(&capsule, &output, limits, json),
    }
}

fn parse_command(args: &[String]) -> Result<Command, CliError> {
    match args {
        [] => Ok(Command::Help),
        [argument] if argument == "-h" || argument == "--help" => Ok(Command::Help),
        [argument] if argument == "-V" || argument == "--version" => Ok(Command::Version),
        [command, rest @ ..] if command == "pack" => parse_pack(rest),
        [command, rest @ ..] if command == "extract" => parse_extract(rest),
        [command, file] if command == "inspect" => Ok(Command::Inspect(PathBuf::from(file))),
        [command, file] if command == "verify" => Ok(Command::Verify(PathBuf::from(file))),
        [command, argument]
            if (command == "inspect" || command == "verify" || command == "extract")
                && argument == "--help" =>
        {
            Ok(Command::Help)
        }
        [command, ..] if command == "inspect" || command == "verify" => Err(CliError::usage(
            format!("`{command}` expects exactly one capsule file"),
        )),
        [command, ..] => Err(CliError::usage(format!(
            "unknown command or argument: {command}"
        ))),
    }
}

fn parse_extract(args: &[String]) -> Result<Command, CliError> {
    if matches!(args, [argument] if argument == "-h" || argument == "--help") {
        return Ok(Command::Help);
    }

    let mut capsule = None;
    let mut output = None;
    let mut max_files = DEFAULT_EXTRACTION_LIMITS.max_files;
    let mut max_bytes = DEFAULT_EXTRACTION_LIMITS.max_total_bytes;
    let mut max_files_seen = false;
    let mut max_bytes_seen = false;
    let mut json = false;
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
            "--max-files" => {
                let value = take_unique_value(args, &mut index, "--max-files", max_files_seen)?;
                max_files = value
                    .parse()
                    .map_err(|_| CliError::usage("--max-files requires a non-negative integer"))?;
                max_files_seen = true;
            }
            "--max-bytes" => {
                let value = take_unique_value(args, &mut index, "--max-bytes", max_bytes_seen)?;
                max_bytes = value
                    .parse()
                    .map_err(|_| CliError::usage("--max-bytes requires a non-negative integer"))?;
                max_bytes_seen = true;
            }
            "--json" if !json => json = true,
            "--json" => return Err(CliError::usage("--json may be specified only once")),
            argument if argument.starts_with('-') => {
                return Err(CliError::usage(format!(
                    "unknown extract option: {argument}"
                )));
            }
            argument if capsule.is_none() => capsule = Some(PathBuf::from(argument)),
            argument => {
                return Err(CliError::usage(format!(
                    "unexpected extract argument: {argument}"
                )));
            }
        }
        index += 1;
    }

    Ok(Command::Extract {
        capsule: capsule.ok_or_else(|| CliError::usage("extract requires a capsule file"))?,
        output: output.ok_or_else(|| CliError::usage("extract requires --output DIR"))?,
        limits: ExtractionLimits {
            max_files,
            max_total_bytes: max_bytes,
        },
        json,
    })
}

fn parse_pack(args: &[String]) -> Result<Command, CliError> {
    if matches!(args, [argument] if argument == "-h" || argument == "--help") {
        return Ok(Command::Help);
    }

    let mut name = None;
    let mut entrypoint = None;
    let mut output = None;
    let mut payload_specs = Vec::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--name" => {
                name = Some(take_unique_value(
                    args,
                    &mut index,
                    "--name",
                    name.is_some(),
                )?);
            }
            "--entrypoint" => {
                entrypoint = Some(take_unique_value(
                    args,
                    &mut index,
                    "--entrypoint",
                    entrypoint.is_some(),
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
            argument if argument.starts_with('-') => {
                return Err(CliError::usage(format!("unknown pack option: {argument}")));
            }
            _ => payload_specs.push(args[index].clone()),
        }
        index += 1;
    }

    let name = name.ok_or_else(|| CliError::usage("pack requires --name NAME"))?;
    let entrypoint =
        entrypoint.ok_or_else(|| CliError::usage("pack requires --entrypoint PATH"))?;
    let output = output.ok_or_else(|| CliError::usage("pack requires --output FILE"))?;
    if payload_specs.is_empty() {
        return Err(CliError::usage(
            "pack requires at least one PATH=FILE payload mapping",
        ));
    }

    Ok(Command::Pack {
        name,
        entrypoint,
        output,
        payload_specs,
    })
}

fn take_unique_value(
    args: &[String],
    index: &mut usize,
    option: &str,
    already_set: bool,
) -> Result<String, CliError> {
    if already_set {
        return Err(CliError::usage(format!(
            "{option} may be specified only once"
        )));
    }
    *index += 1;
    args.get(*index)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| CliError::usage(format!("{option} requires a value")))
}

fn pack_command(
    name: &str,
    entrypoint: &str,
    output: &Path,
    payload_specs: &[String],
) -> Result<String, CliError> {
    if name.trim().is_empty() {
        return Err(CliError::usage("--name must not be empty"));
    }

    let entrypoint = CapsulePath::new(entrypoint.to_owned())
        .map_err(|error| CliError::usage(format!("invalid --entrypoint: {error}")))?;
    let mut payloads = Vec::with_capacity(payload_specs.len());

    for spec in payload_specs {
        let (capsule_path, source_path) = spec.split_once('=').ok_or_else(|| {
            CliError::usage(format!(
                "invalid payload mapping {spec:?}: expected PATH=FILE"
            ))
        })?;
        if source_path.is_empty() {
            return Err(CliError::usage(format!(
                "invalid payload mapping {spec:?}: source file is empty"
            )));
        }
        let capsule_path = CapsulePath::new(capsule_path.to_owned()).map_err(|error| {
            CliError::usage(format!("invalid payload path {capsule_path:?}: {error}"))
        })?;
        let source_path = PathBuf::from(source_path);
        let bytes = read_file(&source_path)?;
        payloads.push(CapsulePayload::new(capsule_path, bytes));
    }

    let capsule = Capsule::new(name.to_owned(), entrypoint, payloads)
        .map_err(|error| CliError::operation(format!("cannot build capsule: {error}")))?;
    let encoded = capsule
        .encode()
        .map_err(|error| CliError::operation(format!("cannot encode capsule: {error}")))?;
    write_file(output, &encoded)?;

    Ok(format!(
        "packed {} payload(s) into {} ({} bytes)\n",
        capsule.payloads().len(),
        output.display(),
        encoded.len()
    ))
}

fn inspect_command(path: &Path) -> Result<String, CliError> {
    let encoded = read_file(path)?;
    let capsule = Capsule::decode(&encoded).map_err(|error| {
        CliError::operation(format!("invalid capsule {}: {error}", path.display()))
    })?;
    let mut json = serde_json::to_string_pretty(capsule.manifest())
        .map_err(|error| CliError::operation(format!("cannot serialize manifest: {error}")))?;
    json.push('\n');
    Ok(json)
}

fn verify_command(path: &Path) -> Result<String, CliError> {
    let encoded = read_file(path)?;
    let capsule = Capsule::decode(&encoded).map_err(|error| {
        CliError::operation(format!("invalid capsule {}: {error}", path.display()))
    })?;
    Ok(format!(
        "verified {}: {} ({} payload(s))\n",
        path.display(),
        capsule.manifest().name(),
        capsule.payloads().len()
    ))
}

fn extract_command(
    capsule_path: &Path,
    output: &Path,
    limits: ExtractionLimits,
    json: bool,
) -> Result<String, CliError> {
    let maximum_encoded_bytes = limits
        .max_total_bytes
        .checked_add(MAX_CAPSULE_METADATA_BYTES)
        .ok_or_else(|| CliError::usage("--max-bytes is too large"))?;
    let encoded = read_regular_file_bounded(capsule_path, maximum_encoded_bytes)?;
    let capsule = Capsule::decode(&encoded).map_err(|error| {
        CliError::operation(format!(
            "invalid capsule {}: {error}",
            capsule_path.display()
        ))
    })?;
    let summary = extract_capsule(&capsule, output, limits)
        .map_err(|error| CliError::operation(format!("cannot extract capsule: {error}")))?;

    if json {
        let mut output = serde_json::to_string_pretty(&serde_json::json!({
            "destination": summary.destination,
            "entrypoint": summary.entrypoint,
            "file_count": summary.file_count,
            "total_bytes": summary.total_bytes,
        }))
        .map_err(|error| CliError::operation(format!("cannot serialize result: {error}")))?;
        output.push('\n');
        Ok(output)
    } else {
        Ok(format!(
            "extracted {} file(s), {} bytes, into {}\n",
            summary.file_count,
            summary.total_bytes,
            summary.destination.display()
        ))
    }
}

fn read_regular_file_bounded(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>, CliError> {
    let read_limit = maximum_bytes
        .checked_add(1)
        .ok_or_else(|| CliError::usage("configured read limit is too large"))?;
    let file = open_regular_nofollow(path)?;
    let metadata = file.metadata().map_err(|error| {
        CliError::operation(format!("cannot inspect {}: {error}", path.display()))
    })?;
    if !metadata.is_file() {
        return Err(CliError::operation(format!(
            "refusing to read non-regular capsule input {}",
            path.display()
        )));
    }
    if metadata.len() > maximum_bytes {
        return Err(CliError::operation(format!(
            "capsule {} is {} bytes; read limit is {} bytes",
            path.display(),
            metadata.len(),
            maximum_bytes
        )));
    }

    let mut bytes = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|error| CliError::operation(format!("cannot read {}: {error}", path.display())))?;
    if bytes.len() as u128 > u128::from(maximum_bytes) {
        return Err(CliError::operation(format!(
            "capsule {} exceeded the {} byte read limit",
            path.display(),
            maximum_bytes
        )));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_regular_nofollow(path: &Path) -> Result<File, CliError> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| {
        CliError::operation(format!(
            "cannot safely open regular capsule input {}: {error}",
            path.display()
        ))
    })?;
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_regular_nofollow(path: &Path) -> Result<File, CliError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        CliError::operation(format!("cannot inspect {}: {error}", path.display()))
    })?;
    if !metadata.file_type().is_file() {
        return Err(CliError::operation(format!(
            "refusing to read non-regular or linked capsule input {}",
            path.display()
        )));
    }
    File::open(path)
        .map_err(|error| CliError::operation(format!("cannot read {}: {error}", path.display())))
}

fn read_file(path: &Path) -> Result<Vec<u8>, CliError> {
    fs::read(path)
        .map_err(|error| CliError::operation(format!("cannot read {}: {error}", path.display())))
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    fs::write(path, bytes)
        .map_err(|error| CliError::operation(format!("cannot write {}: {error}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn test_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("scicapsule-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn format_extension_is_scicap() {
        assert_eq!(FORMAT_EXTENSION, "scicap");
    }

    #[test]
    fn help_advertises_backed_commands() {
        let help = help_text();
        assert!(help.contains("scicapsule pack"));
        assert!(help.contains("scicapsule inspect"));
        assert!(help.contains("scicapsule verify"));
        assert!(help.contains("scicapsule extract"));
    }

    #[test]
    fn parser_rejects_incomplete_pack() {
        let error = parse_command(&args(&["pack", "--name", "demo"])).unwrap_err();
        assert!(error.is_usage());
        assert!(error.to_string().contains("--entrypoint"));
    }

    #[test]
    fn parser_rejects_incomplete_or_duplicate_extract_options() {
        let missing_output = parse_command(&args(&["extract", "demo.scicap"])).unwrap_err();
        assert!(missing_output.is_usage());
        assert!(missing_output.to_string().contains("--output"));

        let duplicate_limit = parse_command(&args(&[
            "extract",
            "demo.scicap",
            "--output",
            "out",
            "--max-files",
            "1",
            "--max-files",
            "2",
        ]))
        .unwrap_err();
        assert!(duplicate_limit.is_usage());
        assert!(duplicate_limit.to_string().contains("only once"));
    }

    #[test]
    fn pack_is_deterministic_across_mapping_order() {
        let dir = test_dir("determinism");
        let runner = dir.join("run.bin");
        let data = dir.join("input.bin");
        let first = dir.join("first.scicap");
        let second = dir.join("second.scicap");
        fs::write(&runner, b"runner").unwrap();
        fs::write(&data, b"input").unwrap();

        let runner_spec = format!("bin/run={}", runner.display());
        let data_spec = format!("data/input.bin={}", data.display());
        let first_args = vec![
            "pack".to_owned(),
            "--name".to_owned(),
            "demo".to_owned(),
            "--entrypoint".to_owned(),
            "bin/run".to_owned(),
            "--output".to_owned(),
            first.display().to_string(),
            data_spec.clone(),
            runner_spec.clone(),
        ];
        let second_args = vec![
            "pack".to_owned(),
            "--name".to_owned(),
            "demo".to_owned(),
            "--entrypoint".to_owned(),
            "bin/run".to_owned(),
            "--output".to_owned(),
            second.display().to_string(),
            runner_spec,
            data_spec,
        ];

        run(&first_args).unwrap();
        run(&second_args).unwrap();
        assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn inspect_and_verify_reject_tampering() {
        let dir = test_dir("verify");
        let runner = dir.join("run.bin");
        let capsule = dir.join("demo.scicap");
        fs::write(&runner, b"trusted bytes").unwrap();
        let spec = format!("bin/run={}", runner.display());
        let pack_args = vec![
            "pack".to_owned(),
            "--name".to_owned(),
            "demo".to_owned(),
            "--entrypoint".to_owned(),
            "bin/run".to_owned(),
            "--output".to_owned(),
            capsule.display().to_string(),
            spec,
        ];
        run(&pack_args).unwrap();

        let inspect = run(&["inspect".to_owned(), capsule.display().to_string()]).unwrap();
        assert!(inspect.contains("\"name\": \"demo\""));
        let verified = run(&["verify".to_owned(), capsule.display().to_string()]).unwrap();
        assert!(verified.contains("verified"));

        let mut bytes = fs::read(&capsule).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&capsule, bytes).unwrap();
        let error = run(&["verify".to_owned(), capsule.display().to_string()]).unwrap_err();
        assert!(!error.is_usage());
        assert!(error.to_string().contains("SHA-256 mismatch"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn extract_cli_writes_exact_bytes_and_json_summary() {
        let dir = test_dir("extract-cli");
        let runner = dir.join("run.bin");
        let capsule = dir.join("demo.scicap");
        let output = dir.join("materialized");
        fs::write(&runner, [0_u8, 1, 2, 0xff]).unwrap();
        let spec = format!("bin/run={}", runner.display());
        run(&[
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

        let result = run(&[
            "extract".to_owned(),
            capsule.display().to_string(),
            "--output".to_owned(),
            output.display().to_string(),
            "--json".to_owned(),
        ])
        .unwrap();

        assert_eq!(fs::read(output.join("bin/run")).unwrap(), [0, 1, 2, 0xff]);
        assert!(result.contains("\"file_count\": 1"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn extract_cli_rejects_symlink_capsule_input() {
        use std::os::unix::fs::symlink;

        let dir = test_dir("extract-input-symlink");
        let runner = dir.join("run.bin");
        let capsule = dir.join("demo.scicap");
        let linked_capsule = dir.join("linked.scicap");
        let output = dir.join("materialized");
        fs::write(&runner, b"runner").unwrap();
        let spec = format!("bin/run={}", runner.display());
        run(&[
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
        symlink(&capsule, &linked_capsule).unwrap();

        let error = run(&[
            "extract".to_owned(),
            linked_capsule.display().to_string(),
            "--output".to_owned(),
            output.display().to_string(),
        ])
        .unwrap_err();

        assert!(error.to_string().contains("safely open"));
        assert!(!output.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn extract_cli_rejects_malformed_and_corrupted_capsules_before_writing() {
        let dir = test_dir("extract-malformed");
        let runner = dir.join("run.bin");
        let capsule = dir.join("demo.scicap");
        let malformed = dir.join("malformed.scicap");
        let corrupted = dir.join("corrupted.scicap");
        let first_output = dir.join("first-output");
        let second_output = dir.join("second-output");
        fs::write(&runner, b"runner").unwrap();
        let spec = format!("bin/run={}", runner.display());
        run(&[
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

        fs::write(&malformed, b"not a capsule").unwrap();
        let malformed_error = run(&[
            "extract".to_owned(),
            malformed.display().to_string(),
            "--output".to_owned(),
            first_output.display().to_string(),
        ])
        .unwrap_err();
        assert!(malformed_error.to_string().contains("invalid capsule"));
        assert!(!first_output.exists());

        let mut bytes = fs::read(&capsule).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&corrupted, bytes).unwrap();
        let corrupted_error = run(&[
            "extract".to_owned(),
            corrupted.display().to_string(),
            "--output".to_owned(),
            second_output.display().to_string(),
        ])
        .unwrap_err();
        assert!(corrupted_error.to_string().contains("SHA-256 mismatch"));
        assert!(!second_output.exists());

        fs::remove_dir_all(dir).unwrap();
    }
}
