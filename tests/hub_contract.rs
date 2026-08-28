#![cfg(unix)]

use ed25519_dalek::{
    pkcs8::{EncodePrivateKey, EncodePublicKey},
    SigningKey,
};
use pkcs8::LineEnding;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn cli(args: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_scicapsule"))
        .args(args)
        .output()
        .expect("run scicapsule")
}

fn expect_success(args: &[String]) -> Output {
    let output = cli(args);
    assert!(
        output.status.success(),
        "command failed: {:?}\nstdout:\n{}\nstderr:\n{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn write_keypair(dir: &Path, seed: u8, label: &str) -> (PathBuf, PathBuf) {
    let signing_key = SigningKey::from_bytes(&[seed; ed25519_dalek::SECRET_KEY_LENGTH]);
    let private = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("encode private key")
        .to_string();
    let public = signing_key
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("encode public key");
    let private_path = dir.join(format!("{label}-private.pem"));
    let public_path = dir.join(format!("{label}-public.pem"));
    fs::write(&private_path, private).expect("write private key");
    fs::write(&public_path, public).expect("write public key");
    (private_path, public_path)
}

fn pack_capsule(dir: &Path, script: &[u8]) -> PathBuf {
    let source = dir.join("run.sh");
    let capsule = dir.join("demo.scicap");
    fs::write(&source, script).expect("write script");
    expect_success(&[
        "pack".to_owned(),
        "--name".to_owned(),
        "demo".to_owned(),
        "--entrypoint".to_owned(),
        "bin/run".to_owned(),
        "--output".to_owned(),
        capsule.display().to_string(),
        format!("bin/run={}", source.display()),
    ]);
    capsule
}

fn sign(capsule: &Path, private_key: &Path, signature: &Path) {
    expect_success(&[
        "sign".to_owned(),
        capsule.display().to_string(),
        "--key".to_owned(),
        private_key.display().to_string(),
        "--output".to_owned(),
        signature.display().to_string(),
    ]);
}

fn policy(public_key: &Path, output: &Path) {
    expect_success(&[
        "create-trust-policy".to_owned(),
        "--output".to_owned(),
        output.display().to_string(),
        "--require".to_owned(),
        "1".to_owned(),
        format!("release={}", public_key.display()),
    ]);
}

fn request(signature: &Path, output: &Path, environment: &[String], arguments: &[String]) {
    let mut args = vec![
        "create-hub-request".to_owned(),
        "--output".to_owned(),
        output.display().to_string(),
        "--signature".to_owned(),
        signature.display().to_string(),
        "--timeout-seconds".to_owned(),
        "5".to_owned(),
    ];
    for entry in environment {
        args.push("--env".to_owned());
        args.push(entry.clone());
    }
    if !arguments.is_empty() {
        args.push("--".to_owned());
        args.extend(arguments.iter().cloned());
    }
    expect_success(&args);
}

fn hub_run(capsule: &Path, policy: &Path, request: &Path, result: &Path) -> Output {
    cli(&[
        "hub-run".to_owned(),
        "--capsule".to_owned(),
        capsule.display().to_string(),
        "--policy".to_owned(),
        policy.display().to_string(),
        "--request".to_owned(),
        request.display().to_string(),
        "--result".to_owned(),
        result.display().to_string(),
    ])
}

#[test]
fn trusted_hub_contract_executes_exact_capsule_and_emits_machine_result() {
    let dir = tempfile::tempdir().expect("tempdir");
    let capsule = pack_capsule(
        dir.path(),
        b"#!/bin/sh\n[ \"$SCICAPSULE_HUB_TEST\" = \"ok\" ] || exit 31\n[ \"$1\" = \"--literal\" ] || exit 32\n[ \"$2\" = '$(false)' ] || exit 33\nexit 0\n",
    );
    let (private, public) = write_keypair(dir.path(), 101, "release");
    let signature = dir.path().join("release.sig");
    let policy_path = dir.path().join("policy.json");
    let request_path = dir.path().join("request.json");
    let result_path = dir.path().join("result.json");

    sign(&capsule, &private, &signature);
    policy(&public, &policy_path);
    request(
        &signature,
        &request_path,
        &["SCICAPSULE_HUB_TEST=ok".to_owned()],
        &["--literal".to_owned(), "$(false)".to_owned()],
    );

    let output = hub_run(&capsule, &policy_path, &request_path, &result_path);
    assert!(
        output.status.success(),
        "hub-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let result_bytes = fs::read(&result_path).expect("read result");
    let result: Value = serde_json::from_slice(&result_bytes).expect("parse result");
    let capsule_bytes = fs::read(&capsule).expect("read capsule");
    let expected_digest = format!("{:x}", Sha256::digest(&capsule_bytes));

    assert_eq!(result["schema_version"], 1);
    assert_eq!(result["status"], "succeeded");
    assert_eq!(result["capsule_sha256"], expected_digest);
    assert_eq!(result["capsule_name"], "demo");
    assert_eq!(result["entrypoint"], "bin/run");
    assert_eq!(result["matched_signers"], serde_json::json!(["release"]));
    assert_eq!(result["required_signatures"], 1);
    assert!(!String::from_utf8_lossy(&result_bytes).contains(&dir.path().display().to_string()));
}

#[test]
fn untrusted_hub_request_fails_before_payload_and_does_not_create_result() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("marker");
    let capsule = pack_capsule(dir.path(), b"#!/bin/sh\nprintf ran > \"$MARKER\"\n");
    let (_trusted_private, trusted_public) = write_keypair(dir.path(), 102, "trusted");
    let (untrusted_private, _untrusted_public) = write_keypair(dir.path(), 103, "untrusted");
    let untrusted_signature = dir.path().join("untrusted.sig");
    let policy_path = dir.path().join("policy.json");
    let request_path = dir.path().join("request.json");
    let result_path = dir.path().join("result.json");

    sign(&capsule, &untrusted_private, &untrusted_signature);
    policy(&trusted_public, &policy_path);
    request(
        &untrusted_signature,
        &request_path,
        &[format!("MARKER={}", marker.display())],
        &[],
    );

    let output = hub_run(&capsule, &policy_path, &request_path, &result_path);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Hub execution trust failed"));
    assert!(!marker.exists(), "untrusted payload executed");
    assert!(!result_path.exists(), "failure fabricated a success result");
}

#[test]
fn preexisting_hub_result_blocks_payload_before_side_effects() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("marker");
    let capsule = pack_capsule(dir.path(), b"#!/bin/sh\nprintf ran > \"$MARKER\"\n");
    let (private, public) = write_keypair(dir.path(), 104, "release");
    let signature = dir.path().join("release.sig");
    let policy_path = dir.path().join("policy.json");
    let request_path = dir.path().join("request.json");
    let result_path = dir.path().join("result.json");

    sign(&capsule, &private, &signature);
    policy(&public, &policy_path);
    request(
        &signature,
        &request_path,
        &[format!("MARKER={}", marker.display())],
        &[],
    );
    fs::write(&result_path, b"occupied").expect("occupy result path");

    let output = hub_run(&capsule, &policy_path, &request_path, &result_path);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already exists"));
    assert!(
        !marker.exists(),
        "payload executed despite occupied result path"
    );
    assert_eq!(
        fs::read(&result_path).expect("read occupied result"),
        b"occupied"
    );
}
