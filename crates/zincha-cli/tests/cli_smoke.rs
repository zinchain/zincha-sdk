use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn zincha() -> Command {
    Command::new(env!("CARGO_BIN_EXE_zincha"))
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "expected success\nstdout:\n{}\nstderr:\n{}",
        stdout(output),
        stderr(output)
    );
}

fn assert_failure(output: &Output) {
    assert!(
        !output.status.success(),
        "expected failure\nstdout:\n{}\nstderr:\n{}",
        stdout(output),
        stderr(output)
    );
}

fn json_stdout(output: &Output) -> Value {
    assert_success(output);
    serde_json::from_slice(&output.stdout).expect("stdout JSON")
}

fn generated_keypair() -> (String, String) {
    let output = zincha()
        .args(["--json", "keygen", "--unsafe-print-secret"])
        .output()
        .expect("run keygen");
    let payload = json_stdout(&output);
    let data = &payload["data"];
    (
        data["secret_key"].as_str().expect("secret key").to_string(),
        data["address"].as_str().expect("address").to_string(),
    )
}

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("zincha-cli-{label}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&path).expect("create temp dir");
    path
}

#[test]
fn help_and_version_are_available() {
    let help = zincha().arg("--help").output().expect("run help");
    assert_success(&help);
    assert!(stdout(&help).contains("Public Zincha developer CLI"));

    let version = zincha().arg("--version").output().expect("run version");
    assert_success(&version);
    assert!(stdout(&version).starts_with("zincha 0.1.0"));
}

#[test]
fn cursor_paged_query_help_uses_cursor_not_offset() {
    for command in [
        "account-transactions",
        "contract-transactions",
        "token-transactions",
        "agents",
        "pending-tasks",
        "tools",
        "contracts",
        "tokens",
        "arbitrators",
        "market-rates",
        "capabilities",
        "capability-search",
    ] {
        let output = zincha()
            .args(["query", command, "--help"])
            .output()
            .unwrap_or_else(|error| panic!("run query {command} help: {error}"));
        assert_success(&output);
        let help = stdout(&output);
        assert!(help.contains("--cursor"), "{help}");
        assert!(!help.contains("--offset"), "{help}");
    }
}

#[test]
fn keygen_json_prints_wallet_material_when_explicitly_requested() {
    let output = zincha()
        .args(["--json", "keygen", "--unsafe-print-secret"])
        .output()
        .expect("run keygen");
    let payload = json_stdout(&output);

    assert_eq!(payload["ok"], true);
    assert_eq!(payload["command"], "keygen");
    let data = &payload["data"];
    assert_eq!(data["secret_key"].as_str().expect("secret key").len(), 64);
    assert_eq!(data["public_key"].as_str().expect("public key").len(), 64);
    assert!(data["address"].as_str().expect("address").starts_with("zn"));
}

#[test]
fn keygen_out_refuses_to_overwrite_without_force() {
    let dir = temp_dir("keygen-out");
    let key_path = dir.join("wallet.key");

    let first = zincha()
        .arg("keygen")
        .arg("--out")
        .arg(&key_path)
        .output()
        .expect("run keygen out");
    assert_success(&first);
    let secret = fs::read_to_string(&key_path).expect("read secret");
    assert_eq!(secret.trim().len(), 64);

    let overwrite = zincha()
        .arg("keygen")
        .arg("--out")
        .arg(&key_path)
        .output()
        .expect("run overwrite");
    assert_failure(&overwrite);
    assert!(stderr(&overwrite).contains("refusing to overwrite"));

    let forced = zincha()
        .arg("keygen")
        .arg("--out")
        .arg(&key_path)
        .arg("--force")
        .output()
        .expect("run force overwrite");
    assert_success(&forced);

    fs::remove_dir_all(dir).expect("remove temp dir");
}

#[test]
fn wallet_address_derives_from_secret_key() {
    let (secret_key, address) = generated_keypair();

    let output = zincha()
        .args(["--json", "wallet", "address", "--secret-key", &secret_key])
        .output()
        .expect("run wallet address");
    let payload = json_stdout(&output);

    assert_eq!(payload["ok"], true);
    assert_eq!(payload["command"], "wallet-address");
    assert_eq!(payload["data"]["address"], address);
    assert_eq!(
        payload["data"]["public_key"]
            .as_str()
            .expect("public key")
            .len(),
        64
    );
}

#[test]
fn tx_transfer_builds_signed_transaction_without_network_submission() {
    let (sender_secret, sender_address) = generated_keypair();
    let (_recipient_secret, recipient_address) = generated_keypair();

    let output = zincha()
        .args([
            "--json",
            "tx",
            "transfer",
            "--secret-key",
            &sender_secret,
            "--to",
            &recipient_address,
            "--amount",
            "1000",
            "--fee",
            "1",
            "--nonce",
            "0",
        ])
        .output()
        .expect("run tx transfer");
    let payload = json_stdout(&output);

    assert_eq!(payload["ok"], true);
    assert_eq!(payload["command"], "tx-transfer");
    assert_eq!(payload["data"]["sender"], sender_address);
    assert_eq!(payload["data"]["hash"].as_str().expect("hash").len(), 64);
    assert!(
        payload["data"]["signed_tx_hex"]
            .as_str()
            .expect("signed tx hex")
            .len()
            > 64
    );
    assert!(payload["data"]["submission"].is_null());
}

#[test]
fn tx_transfer_rejects_partial_validity_window() {
    let (sender_secret, _sender_address) = generated_keypair();
    let (_recipient_secret, recipient_address) = generated_keypair();

    let output = zincha()
        .args([
            "--json",
            "tx",
            "transfer",
            "--secret-key",
            &sender_secret,
            "--to",
            &recipient_address,
            "--amount",
            "1000",
            "--fee",
            "1",
            "--nonce",
            "0",
            "--reference-block-height",
            "1",
        ])
        .output()
        .expect("run tx transfer");

    assert_failure(&output);
    assert!(stderr(&output).contains("must be provided together"));
}

#[test]
fn unknown_release_alias_fails_before_network_access() {
    let output = zincha()
        .args(["--release", "not-a-release", "--json", "info"])
        .output()
        .expect("run unknown release");

    assert_failure(&output);
    assert!(stderr(&output).contains("unknown release alias not-a-release"));
}
