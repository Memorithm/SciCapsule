use std::process::Command;

#[test]
fn hub_evidence_v2_binary_rejects_missing_inputs() {
    let binary = env!("CARGO_BIN_EXE_scicapsule-hub-evidence-v2");
    let output = Command::new(binary).output().expect("run v2 binary");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("--capsule is required"));
}

#[test]
fn hub_evidence_v2_binary_rejects_relative_runtime_path_before_execution() {
    let temp = tempfile::tempdir().expect("tempdir");
    let capsule = temp.path().join("capsule.scicap");
    let policy = temp.path().join("policy.json");
    let request = temp.path().join("request.json");
    let result = temp.path().join("result.json");

    std::fs::write(&capsule, b"not-a-capsule").expect("capsule fixture");
    std::fs::write(&policy, b"{}").expect("policy fixture");
    std::fs::write(
        &request,
        br#"{"schema_version":1,"signatures":[{"version":1}],"max_bytes":1024}"#,
    )
    .expect("request fixture");

    let binary = env!("CARGO_BIN_EXE_scicapsule-hub-evidence-v2");
    let output = Command::new(binary)
        .args([
            "--capsule",
            capsule.to_str().expect("capsule path"),
            "--policy",
            policy.to_str().expect("policy path"),
            "--request",
            request.to_str().expect("request path"),
            "--result",
            result.to_str().expect("result path"),
            "--scicapsule-program",
            "relative-scicapsule",
        ])
        .output()
        .expect("run v2 binary");

    assert!(!output.status.success());
    assert!(!result.exists());
}
