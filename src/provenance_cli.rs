use crate::provenance::{DsseEnvelope, ProvenanceStatement};
use crate::trust::{TrustPolicy, MAX_SIGNATURES};
use crate::{
    read_file, read_regular_file_bounded, read_regular_utf8_bounded, take_unique_value, take_value,
    write_new_file, ProductError, MAX_KEY_FILE_BYTES, MAX_TRUST_POLICY_BYTES,
};
use scirust_capsule::Capsule;
use std::path::{Path, PathBuf};

const MAX_PROVENANCE_ENVELOPE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Eq, PartialEq)]
enum ProvenanceCommand {
    Attest {
        capsule: PathBuf,
        keys: Vec<PathBuf>,
        output: PathBuf,
        builder_id: String,
        build_type: String,
        source_uri: String,
        source_sha256: String,
    },
    Verify {
        capsule: PathBuf,
        provenance: PathBuf,
        policy: PathBuf,
    },
}

pub(crate) fn handles(args: &[String]) -> bool {
    matches!(
        args.first().map(String::as_str),
        Some("attest-provenance" | "verify-provenance")
    )
}

pub(crate) fn run(args: &[String]) -> Result<String, ProductError> {
    match parse(args)? {
        ProvenanceCommand::Attest {
            capsule,
            keys,
            output,
            builder_id,
            build_type,
            source_uri,
            source_sha256,
        } => attest_command(
            &capsule,
            &keys,
            &output,
            &builder_id,
            &build_type,
            &source_uri,
            &source_sha256,
        ),
        ProvenanceCommand::Verify {
            capsule,
            provenance,
            policy,
        } => verify_command(&capsule, &provenance, &policy),
    }
}

pub(crate) fn help_text() -> &'static str {
    "\nPROVENANCE COMMANDS:\n\
    scicapsule attest-provenance FILE --key PRIVATE.pem [--key PRIVATE.pem ...] --builder-id URI --build-type URI --source URI --source-sha256 HEX --output FILE.intoto.json\n\
    scicapsule verify-provenance FILE --provenance FILE.intoto.json --policy POLICY.json\n\n\
    attest-provenance  Create an in-toto Statement v1 with SLSA Provenance v1 and sign it with DSSE\n\
    verify-provenance  Verify DSSE trust first, then validate SLSA provenance and capsule subject digest\n\n\
PROVENANCE OPTIONS:\n\
    --key FILE          Ed25519 PKCS#8 private PEM; repeatable to create a multi-signature DSSE envelope\n\
    --builder-id URI    Explicit SLSA builder identifier\n\
    --build-type URI    Explicit SLSA build type\n\
    --source URI        Explicit resolved source/dependency URI\n\
    --source-sha256 HEX Explicit 64-hex SHA-256 digest for the resolved source/dependency\n\
    --provenance FILE   DSSE-wrapped in-toto/SLSA provenance file\n\
    --policy FILE       Local SciCapsule trust-policy JSON used as the provenance trust roots\n\
    --output FILE       New provenance output; existing files are never overwritten\n"
}

fn parse(args: &[String]) -> Result<ProvenanceCommand, ProductError> {
    match args {
        [command, rest @ ..] if command == "attest-provenance" => parse_attest(rest),
        [command, rest @ ..] if command == "verify-provenance" => parse_verify(rest),
        _ => Err(ProductError::usage("unknown provenance command")),
    }
}

fn parse_attest(args: &[String]) -> Result<ProvenanceCommand, ProductError> {
    let mut capsule = None;
    let mut keys = Vec::new();
    let mut output = None;
    let mut builder_id = None;
    let mut build_type = None;
    let mut source_uri = None;
    let mut source_sha256 = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--key" => {
                keys.push(PathBuf::from(take_value(args, &mut index, "--key")?));
                if keys.len() > MAX_SIGNATURES {
                    return Err(ProductError::usage(format!(
                        "too many --key values; limit is {MAX_SIGNATURES}"
                    )));
                }
            }
            "--output" => {
                output = Some(PathBuf::from(take_unique_value(
                    args,
                    &mut index,
                    "--output",
                    output.is_some(),
                )?));
            }
            "--builder-id" => {
                builder_id = Some(take_unique_value(
                    args,
                    &mut index,
                    "--builder-id",
                    builder_id.is_some(),
                )?);
            }
            "--build-type" => {
                build_type = Some(take_unique_value(
                    args,
                    &mut index,
                    "--build-type",
                    build_type.is_some(),
                )?);
            }
            "--source" => {
                source_uri = Some(take_unique_value(
                    args,
                    &mut index,
                    "--source",
                    source_uri.is_some(),
                )?);
            }
            "--source-sha256" => {
                source_sha256 = Some(take_unique_value(
                    args,
                    &mut index,
                    "--source-sha256",
                    source_sha256.is_some(),
                )?);
            }
            argument if argument.starts_with('-') => {
                return Err(ProductError::usage(format!(
                    "unknown attest-provenance option: {argument}"
                )));
            }
            argument if capsule.is_none() => capsule = Some(PathBuf::from(argument)),
            argument => {
                return Err(ProductError::usage(format!(
                    "unexpected attest-provenance argument: {argument}"
                )));
            }
        }
        index += 1;
    }

    if keys.is_empty() {
        return Err(ProductError::usage(
            "attest-provenance requires at least one --key PRIVATE.pem",
        ));
    }

    Ok(ProvenanceCommand::Attest {
        capsule: capsule
            .ok_or_else(|| ProductError::usage("attest-provenance requires a capsule file"))?,
        keys,
        output: output
            .ok_or_else(|| ProductError::usage("attest-provenance requires --output FILE"))?,
        builder_id: builder_id
            .ok_or_else(|| ProductError::usage("attest-provenance requires --builder-id URI"))?,
        build_type: build_type
            .ok_or_else(|| ProductError::usage("attest-provenance requires --build-type URI"))?,
        source_uri: source_uri
            .ok_or_else(|| ProductError::usage("attest-provenance requires --source URI"))?,
        source_sha256: source_sha256
            .ok_or_else(|| ProductError::usage("attest-provenance requires --source-sha256 HEX"))?,
    })
}

fn parse_verify(args: &[String]) -> Result<ProvenanceCommand, ProductError> {
    let mut capsule = None;
    let mut provenance = None;
    let mut policy = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--provenance" => {
                provenance = Some(PathBuf::from(take_unique_value(
                    args,
                    &mut index,
                    "--provenance",
                    provenance.is_some(),
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
            argument if argument.starts_with('-') => {
                return Err(ProductError::usage(format!(
                    "unknown verify-provenance option: {argument}"
                )));
            }
            argument if capsule.is_none() => capsule = Some(PathBuf::from(argument)),
            argument => {
                return Err(ProductError::usage(format!(
                    "unexpected verify-provenance argument: {argument}"
                )));
            }
        }
        index += 1;
    }

    Ok(ProvenanceCommand::Verify {
        capsule: capsule
            .ok_or_else(|| ProductError::usage("verify-provenance requires a capsule file"))?,
        provenance: provenance
            .ok_or_else(|| ProductError::usage("verify-provenance requires --provenance FILE"))?,
        policy: policy
            .ok_or_else(|| ProductError::usage("verify-provenance requires --policy FILE"))?,
    })
}

fn attest_command(
    capsule_path: &Path,
    key_paths: &[PathBuf],
    output: &Path,
    builder_id: &str,
    build_type: &str,
    source_uri: &str,
    source_sha256: &str,
) -> Result<String, ProductError> {
    let capsule_bytes = read_file(capsule_path)?;
    let capsule = Capsule::decode(&capsule_bytes).map_err(|error| {
        ProductError::operation(format!(
            "invalid capsule {}: {error}",
            capsule_path.display()
        ))
    })?;

    let statement = ProvenanceStatement::for_capsule(
        capsule.manifest().name(),
        &capsule_bytes,
        builder_id,
        build_type,
        source_uri,
        source_sha256,
    )
    .map_err(|error| ProductError::operation(format!("invalid provenance inputs: {error}")))?;
    let statement_bytes = statement
        .to_json()
        .map_err(|error| ProductError::operation(format!("cannot encode provenance: {error}")))?;

    let mut private_keys = Vec::with_capacity(key_paths.len());
    for key_path in key_paths {
        private_keys.push(read_regular_utf8_bounded(
            key_path,
            MAX_KEY_FILE_BYTES,
            "provenance private key",
        )?);
    }
    let envelope = DsseEnvelope::sign_statement(&statement_bytes, &private_keys)
        .map_err(|error| ProductError::operation(format!("cannot sign provenance: {error}")))?;
    let encoded = envelope.to_json().map_err(|error| {
        ProductError::operation(format!("cannot encode DSSE provenance envelope: {error}"))
    })?;
    if encoded.len() as u128 > u128::from(MAX_PROVENANCE_ENVELOPE_BYTES) {
        return Err(ProductError::operation(format!(
            "encoded provenance envelope exceeds the {} byte limit",
            MAX_PROVENANCE_ENVELOPE_BYTES
        )));
    }
    write_new_file(output, &encoded, "provenance envelope")?;

    Ok(format!(
        "attested provenance {}: {} -> {} with {} DSSE signature(s)\n",
        capsule_path.display(),
        capsule.manifest().name(),
        output.display(),
        key_paths.len()
    ))
}

fn verify_command(
    capsule_path: &Path,
    provenance_path: &Path,
    policy_path: &Path,
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
    let provenance_bytes = read_regular_file_bounded(
        provenance_path,
        MAX_PROVENANCE_ENVELOPE_BYTES,
        "provenance envelope",
    )?;
    let envelope = DsseEnvelope::from_json(&provenance_bytes).map_err(|error| {
        ProductError::operation(format!("invalid provenance envelope: {error}"))
    })?;
    let verified = envelope
        .verify_for_capsule(&capsule_bytes, &policy)
        .map_err(|error| {
            ProductError::operation(format!("provenance verification failed: {error}"))
        })?;

    Ok(format!(
        "verified provenance {}: {} builder={} build_type={} matched [{}], require {}\n",
        capsule_path.display(),
        capsule.manifest().name(),
        verified.statement.predicate.run_details.builder.id,
        verified.statement.predicate.build_definition.build_type,
        verified.trust.matched_signers.join(","),
        verified.trust.required_signatures
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{
        pkcs8::{EncodePrivateKey, EncodePublicKey},
        SigningKey,
    };
    use pkcs8::LineEnding;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-tmp");
        fs::create_dir_all(&base).unwrap();
        let path = base.join(format!("provenance-{label}-{}-{nonce}", std::process::id()));
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

    fn pack_capsule(dir: &Path, file_name: &str, payload: &[u8]) -> PathBuf {
        let runner = dir.join(format!("{file_name}.bin"));
        let capsule = dir.join(format!("{file_name}.scicap"));
        fs::write(&runner, payload).unwrap();
        let spec = format!("bin/run={}", runner.display());
        scicapsule::run(&[
            "pack".to_owned(),
            "--name".to_owned(),
            file_name.to_owned(),
            "--entrypoint".to_owned(),
            "bin/run".to_owned(),
            "--output".to_owned(),
            capsule.display().to_string(),
            spec,
        ])
        .unwrap();
        capsule
    }

    fn write_policy(output: &Path, required: u32, keys: &[(&str, &Path)]) {
        let mut pem_keys = Vec::new();
        for (name, path) in keys {
            pem_keys.push(((*name).to_owned(), fs::read_to_string(path).unwrap()));
        }
        let policy = TrustPolicy::from_named_pem_keys(required, pem_keys).unwrap();
        fs::write(output, policy.to_json().unwrap()).unwrap();
    }

    fn attest_args(capsule: &Path, output: &Path, keys: &[&Path]) -> Vec<String> {
        let mut args = vec![
            "attest-provenance".to_owned(),
            capsule.display().to_string(),
        ];
        for key in keys {
            args.push("--key".to_owned());
            args.push(key.display().to_string());
        }
        args.extend([
            "--builder-id".to_owned(),
            "https://builder.example/v1".to_owned(),
            "--build-type".to_owned(),
            "https://build.example/scicapsule/v1".to_owned(),
            "--source".to_owned(),
            "https://github.com/example/source".to_owned(),
            "--source-sha256".to_owned(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            "--output".to_owned(),
            output.display().to_string(),
        ]);
        args
    }

    #[test]
    fn parser_requires_explicit_provenance_inputs() {
        let error = parse(&["attest-provenance".to_owned(), "demo.scicap".to_owned()]).unwrap_err();
        assert!(error.usage);
        assert!(error.to_string().contains("--key"));

        let verify_error = parse(&[
            "verify-provenance".to_owned(),
            "demo.scicap".to_owned(),
            "--policy".to_owned(),
            "policy.json".to_owned(),
        ])
        .unwrap_err();
        assert!(verify_error.to_string().contains("--provenance"));
    }

    #[test]
    fn attest_and_verify_provenance_with_threshold() {
        let dir = test_dir("round-trip");
        let capsule = pack_capsule(&dir, "demo", b"runner");
        let (private_a, public_a) = write_keys(&dir, 71);
        let (private_b, public_b) = write_keys(&dir, 72);
        let provenance = dir.join("demo.intoto.json");
        let policy = dir.join("policy.json");
        write_policy(
            &policy,
            2,
            &[
                ("builder-a", public_a.as_path()),
                ("builder-b", public_b.as_path()),
            ],
        );

        let created = run(&attest_args(
            &capsule,
            &provenance,
            &[private_a.as_path(), private_b.as_path()],
        ))
        .unwrap();
        assert!(created.contains("2 DSSE signature(s)"));

        let verified = run(&[
            "verify-provenance".to_owned(),
            capsule.display().to_string(),
            "--provenance".to_owned(),
            provenance.display().to_string(),
            "--policy".to_owned(),
            policy.display().to_string(),
        ])
        .unwrap();
        assert!(verified.contains("builder=https://builder.example/v1"));
        assert!(verified.contains("matched [builder-a,builder-b]"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn provenance_for_different_capsule_is_rejected() {
        let dir = test_dir("wrong-capsule");
        let capsule_a = pack_capsule(&dir, "a", b"runner-a");
        let capsule_b = pack_capsule(&dir, "b", b"runner-b");
        let (private, public) = write_keys(&dir, 73);
        let provenance = dir.join("a.intoto.json");
        let policy = dir.join("policy.json");
        write_policy(&policy, 1, &[("builder", public.as_path())]);
        run(&attest_args(&capsule_a, &provenance, &[private.as_path()])).unwrap();

        let error = run(&[
            "verify-provenance".to_owned(),
            capsule_b.display().to_string(),
            "--provenance".to_owned(),
            provenance.display().to_string(),
            "--policy".to_owned(),
            policy.display().to_string(),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("subject SHA-256"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn provenance_sidecars_reject_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = test_dir("symlink");
        let capsule = pack_capsule(&dir, "demo", b"runner");
        let (private, public) = write_keys(&dir, 74);
        let provenance = dir.join("demo.intoto.json");
        let policy = dir.join("policy.json");
        write_policy(&policy, 1, &[("builder", public.as_path())]);
        run(&attest_args(&capsule, &provenance, &[private.as_path()])).unwrap();

        let linked = dir.join("linked.intoto.json");
        symlink(&provenance, &linked).unwrap();
        let error = run(&[
            "verify-provenance".to_owned(),
            capsule.display().to_string(),
            "--provenance".to_owned(),
            linked.display().to_string(),
            "--policy".to_owned(),
            policy.display().to_string(),
        ])
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("safely open provenance envelope"));
        fs::remove_dir_all(dir).unwrap();
    }
}
