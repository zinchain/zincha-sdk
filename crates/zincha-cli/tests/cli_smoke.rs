use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::Arc;
use std::thread;
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

fn generated_key_material() -> (String, String, String) {
    let output = zincha()
        .args(["--json", "keygen", "--unsafe-print-secret"])
        .output()
        .expect("run keygen");
    let payload = json_stdout(&output);
    let data = &payload["data"];
    (
        data["secret_key"].as_str().expect("secret key").to_string(),
        data["public_key"].as_str().expect("public key").to_string(),
        data["address"].as_str().expect("address").to_string(),
    )
}

struct MockResponse {
    method: &'static str,
    path: String,
    data: Value,
}

fn bound_mock_server() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let url = format!("http://{}", listener.local_addr().expect("mock address"));
    (listener, url)
}

fn serve_mock(listener: TcpListener, responses: Vec<MockResponse>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for expected in responses {
            let (mut stream, _) = listener.accept().expect("accept mock request");
            let request = read_http_request(&mut stream);
            let first_line = request.lines().next().expect("request line");
            assert!(
                first_line.starts_with(&format!("{} {} ", expected.method, expected.path)),
                "unexpected request line: {first_line}"
            );
            let body = serde_json::to_vec(&serde_json::json!({
                "success": true,
                "data": expected.data,
            }))
            .expect("encode mock response");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            )
            .expect("write mock headers");
            stream.write_all(&body).expect("write mock body");
        }
    })
}

fn serve_tls_mock(
    listener: TcpListener,
    responses: Vec<MockResponse>,
    certificate: rustls::pki_types::CertificateDer<'static>,
    private_key: Vec<u8>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 server")
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate],
                rustls::pki_types::PrivatePkcs8KeyDer::from(private_key).into(),
            )
            .expect("server certificate");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        for expected in responses {
            let (stream, _) = listener.accept().expect("accept TLS mock request");
            let connection = rustls::ServerConnection::new(config.clone()).expect("TLS server");
            let mut stream = rustls::StreamOwned::new(connection, stream);
            let request = read_http_request(&mut stream);
            let first_line = request.lines().next().expect("request line");
            assert!(
                first_line.starts_with(&format!("{} {} ", expected.method, expected.path)),
                "unexpected request line: {first_line}"
            );
            let body = serde_json::to_vec(&serde_json::json!({
                "success": true,
                "data": expected.data,
            }))
            .expect("encode mock response");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            )
            .expect("write TLS mock headers");
            stream.write_all(&body).expect("write TLS mock body");
            stream.flush().expect("flush TLS mock response");
        }
    })
}

fn test_tls_identity() -> (rustls::pki_types::CertificateDer<'static>, Vec<u8>, Value) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("generate test key");
    let mut parameters =
        rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("certificate params");
    parameters.not_before = rcgen::date_time_ymd(2026, 1, 1);
    parameters.not_after = rcgen::date_time_ymd(2030, 1, 1);
    let certificate = parameters
        .self_signed(&key)
        .expect("self-signed certificate");
    let (_, parsed) =
        x509_parser::parse_x509_certificate(certificate.der()).expect("parse certificate");
    let pin = serde_json::json!({
        "sha256": hex::encode(Sha256::digest(certificate.der())),
        "not_before_ms": parsed.validity().not_before.timestamp() * 1_000,
        "not_after_ms": parsed.validity().not_after.timestamp() * 1_000,
    });
    (certificate.der().clone(), key.serialize_der(), pin)
}

fn read_http_request(stream: &mut impl Read) -> String {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    let mut expected_len = None;
    loop {
        let read = stream.read(&mut buffer).expect("read mock request");
        assert!(read > 0, "request closed before completion");
        bytes.extend_from_slice(&buffer[..read]);
        if expected_len.is_none() {
            if let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&bytes[..header_end]);
                let content_len = headers
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length: ")
                            .or_else(|| line.strip_prefix("Content-Length: "))
                    })
                    .map(|value| value.parse::<usize>().expect("content length"))
                    .unwrap_or(0);
                expected_len = Some(header_end + 4 + content_len);
            }
        }
        if expected_len.is_some_and(|length| bytes.len() >= length) {
            return String::from_utf8(bytes).expect("UTF-8 request");
        }
        assert!(bytes.len() <= 128 * 1024, "mock request exceeded bound");
    }
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
fn conversation_help_exposes_the_complete_participant_workflow() {
    let output = zincha()
        .args(["conversation", "--help"])
        .output()
        .expect("run conversation help");
    assert_success(&output);
    let help = stdout(&output);
    for command in [
        "profile",
        "delegation-info",
        "authorize",
        "deauthorize",
        "open",
        "renew",
        "status",
        "get",
        "send",
        "messages",
        "watch",
        "acknowledge",
        "outbox-flush",
        "decrypt",
        "revoke-session",
    ] {
        assert!(help.contains(command), "missing {command} in:\n{help}");
    }
}

#[test]
fn conversation_cli_opens_private_state_and_durably_sends() {
    let (account_secret, _account_public, account_address) = generated_key_material();
    let (_provider_secret, _provider_public, provider_address) = generated_key_material();
    let (_service_secret, service_public, service_address) = generated_key_material();
    let subject_id = "ab".repeat(32);
    let conversation_id = "cd".repeat(32);
    let message_id = "22222222-2222-4222-8222-222222222222";
    let (conversation_listener, _) = bound_mock_server();
    let conversation_port = conversation_listener.local_addr().unwrap().port();
    let (certificate, private_key, pin) = test_tls_identity();
    let profile = serde_json::json!({
        "version": 2,
        "service_id": "marketplace.example/conversations",
        "interfaces": [{
            "type": "zincha_tls_v1",
            "host": "127.0.0.1",
            "port": conversation_port,
            "certificate_pins": [pin],
        }],
        "privacy_modes": ["platform_readable", "end_to_end"],
        "protocol_versions": [1],
    });
    let service = serve_tls_mock(
        conversation_listener,
        vec![
            MockResponse {
                method: "GET",
                path: "/v1/profile".into(),
                data: profile.clone(),
            },
            MockResponse {
                method: "GET",
                path: "/v1/delegation-info".into(),
                data: serde_json::json!({
                    "protocol_version": 1,
                    "service_id": "marketplace.example/conversations",
                    "network": "testnet",
                    "chain_id": "zincha-test",
                    "active_key": { "public_key": service_public, "address": service_address },
                    "next_key": null,
                    "required_scopes": ["task_read", "task_lifecycle_read"],
                    "required_scope_mask": 3,
                    "default_grant_lifetime_ms": 2_592_000_000_u64,
                    "maximum_grant_lifetime_ms": 7_776_000_000_u64,
                }),
            },
            MockResponse {
                method: "POST",
                path: "/v1/auth/challenges".into(),
                data: serde_json::json!({
                    "challenge_id": "11111111-1111-4111-8111-111111111111",
                    "challenge": "bounded-test-challenge",
                    "expires_at_ms": 4_000_000_000_000_i64,
                }),
            },
            MockResponse {
                method: "POST",
                path: "/v1/auth/sessions".into(),
                data: serde_json::json!({
                    "access_token": "private-test-session-token",
                    "expires_at_ms": 4_000_000_000_000_i64,
                }),
            },
            MockResponse {
                method: "POST",
                path: "/v1/conversations/resolve".into(),
                data: serde_json::json!({
                    "id": conversation_id,
                    "tenant_id": "marketplace",
                    "subject": {
                        "network": "testnet",
                        "chain_id": "zincha-test",
                        "kind": "task",
                        "id": subject_id,
                    },
                    "home_service_id": "marketplace.example/conversations",
                    "privacy_mode": "platform_readable",
                    "snapshot": {},
                    "created_at_ms": 1,
                    "updated_at_ms": 1,
                }),
            },
            MockResponse {
                method: "GET",
                path: "/v1/profile".into(),
                data: profile.clone(),
            },
            MockResponse {
                method: "POST",
                path: format!("/v1/conversations/{conversation_id}/messages"),
                data: serde_json::json!({
                    "conversation_id": conversation_id,
                    "sequence": 1,
                    "message_id": message_id,
                    "sender": account_address,
                    "client_timestamp_ms": 1,
                    "accepted_at_ms": 2,
                    "reply_to": null,
                    "key_epoch": null,
                    "payload": { "encoding": "plaintext", "parts": [{ "type": "text", "text": "hello" }] },
                    "payload_digest": "00".repeat(32),
                    "signing_key_id": "11111111-1111-4111-8111-111111111111",
                    "signature": "11".repeat(64),
                }),
            },
        ],
        certificate,
        private_key,
    );

    let (node_listener, node_url) = bound_mock_server();
    let profile_bytes = serde_json::to_vec(&profile).expect("encode profile");
    let agent = serde_json::json!({
        "address": provider_address,
        "metadata": profile_bytes,
    });
    let node = serve_mock(
        node_listener,
        vec![
            MockResponse {
                method: "GET",
                path: format!("/v1/agents/{provider_address}"),
                data: agent.clone(),
            },
            MockResponse {
                method: "GET",
                path: format!("/v1/agents/{provider_address}"),
                data: agent,
            },
        ],
    );

    let dir = temp_dir("conversation-flow");
    let state_path = dir.join("conversation.json");
    let open = zincha()
        .args([
            "--api-url",
            &node_url,
            "--json",
            "conversation",
            "open",
            "--provider",
            &provider_address,
            "--secret-key",
            &account_secret,
            "--subject-kind",
            "task",
            "--subject-id",
            &subject_id,
            "--state",
        ])
        .arg(&state_path)
        .output()
        .expect("open conversation");
    let opened = json_stdout(&open);
    assert_eq!(opened["command"], "conversation-open");
    assert_eq!(opened["data"]["conversation"]["id"], conversation_id);
    let rendered_open = stdout(&open);
    assert!(!rendered_open.contains("private-test-session-token"));
    assert!(!rendered_open.contains(&account_secret));
    assert!(state_path.is_file());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&state_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let send = zincha()
        .args([
            "--api-url",
            &node_url,
            "--json",
            "conversation",
            "send",
            "--state",
        ])
        .arg(&state_path)
        .args(["--text", "hello"])
        .output()
        .expect("send conversation message");
    let sent = json_stdout(&send);
    assert_eq!(sent["command"], "conversation-send");
    assert_eq!(sent["data"]["message"]["sequence"], 1);
    assert_eq!(sent["data"]["queued"], false);
    let outbox = dir.join("conversation.json.outbox.json");
    assert_eq!(fs::read_to_string(&outbox).unwrap(), "[]");

    let status = zincha()
        .args(["--json", "conversation", "status", "--state"])
        .arg(&state_path)
        .output()
        .expect("inspect conversation state");
    let status_payload = json_stdout(&status);
    assert_eq!(status_payload["data"]["last_observed_sequence"], 1);
    assert!(!stdout(&status).contains("private-test-session-token"));

    node.join().expect("node mock completed");
    service.join().expect("conversation mock completed");
    fs::remove_dir_all(dir).expect("remove temp dir");
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
fn tx_reactivate_validator_matches_the_canonical_298_byte_vector() {
    let golden: Value = serde_json::from_str(include_str!(
        "../../../sdk/testdata/golden-staking-validator.json"
    ))
    .expect("staking golden vector");
    let transaction = &golden["validator_reactivate"]["transaction"];
    let secret_key = golden["secret_hex"].as_str().expect("secret key");
    let fee = transaction["fee_micro_zin"].as_u64().unwrap().to_string();
    let nonce = transaction["nonce"].as_u64().unwrap().to_string();
    let timestamp = transaction["timestamp"].as_u64().unwrap().to_string();
    let reference_block_height = transaction["reference_block_height"]
        .as_u64()
        .unwrap()
        .to_string();

    let output = zincha()
        .args([
            "--json",
            "tx",
            "reactivate-validator",
            "--secret-key",
            secret_key,
            "--fee",
            &fee,
            "--nonce",
            &nonce,
            "--chain-id",
            transaction["chain_id"].as_str().unwrap(),
            "--timestamp-ms",
            &timestamp,
            "--reference-block-height",
            &reference_block_height,
            "--reference-block-hash",
            transaction["reference_block_hash"].as_str().unwrap(),
            "--ttl-blocks",
            "100",
        ])
        .output()
        .expect("run tx reactivate-validator");
    let payload = json_stdout(&output);
    let signed_tx_hex = payload["data"]["signed_tx_hex"]
        .as_str()
        .expect("signed transaction hex");

    assert_eq!(payload["command"], "tx-reactivate-validator");
    assert_eq!(signed_tx_hex, transaction["signed_tx_hex"]);
    assert_eq!(signed_tx_hex.len() / 2, 298);
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
