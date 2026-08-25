#![forbid(unsafe_code)]

use scirust_capsule::{Capsule, CapsulePayload};
use scirust_capsule_schema::CapsulePath;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

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
    scicapsule [--help] [--version]\n\n\
COMMANDS:\n\
    pack       Build a deterministic .scicap from explicitly mapped payload files\n\
    inspect    Decode, verify, and print the embedded manifest\n\
    verify     Decode and verify canonical encoding, lengths, and payload SHA-256\n\n\
PACK OPTIONS:\n\
    --name NAME          Human-readable capsule name\n\
    --entrypoint PATH    Portable payload path that is the capsule entrypoint\n\
    --output FILE        Destination .scicap file\n\
    PATH=FILE            Map a capsule payload path to a source file; repeatable\n\n\
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
    }
}

fn parse_command(args: &[String]) -> Result<Command, CliError> {
    match args {
        [] => Ok(Command::Help),
        [argument] if argument == "-h" || argument == "--help" => Ok(Command::Help),
        [argument] if argument == "-V" || argument == "--version" => Ok(Command::Version),
        [command, rest @ ..] if command == "pack" => parse_pack(rest),
        [command, file] if command == "inspect" => Ok(Command::Inspect(PathBuf::from(file))),
        [command, file] if command == "verify" => Ok(Command::Verify(PathBuf::from(file))),
        [command, argument] if (command == "inspect" || command == "verify") && argument == "--help" => {
            Ok(Command::Help)
        }
        [command, ..] if command == "inspect" || command == "verify" => Err(CliError::usage(
            format!("`{command}` expects exactly one capsule file"),
        )),
        [command, ..] => Err(CliError::usage(format!("unknown command or argument: {command}"))),
    }
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
                name = Some(take_unique_value(args, &mut index, "--name", name.is_some())?);
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
        return Err(CliError::usage(format!("{option} may be specified only once")));
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

fn read_file(path: &Path) -> Result<Vec<u8>, CliError> {
    fs::read(path).map_err(|error| {
        CliError::operation(format!("cannot read {}: {error}", path.display()))
    })
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    fs::write(path, bytes).map_err(|error| {
        CliError::operation(format!("cannot write {}: {error}", path.display()))
    })
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
        let path = std::env::temp_dir().join(format!(
            "scicapsule-{label}-{}-{nonce}",
            std::process::id()
        ));
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
    }

    #[test]
    fn parser_rejects_incomplete_pack() {
        let error = parse_command(&args(&["pack", "--name", "demo"])).unwrap_err();
        assert!(error.is_usage());
        assert!(error.to_string().contains("--entrypoint"));
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
}
