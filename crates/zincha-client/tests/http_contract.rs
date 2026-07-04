use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use zincha_client::{signed_request_parts, RequestOptions, TransactionHistoryQuery, ZinchaClient};
use zincha_primitives::crypto::{hash_bytes, Keypair};

#[derive(Debug)]
struct RecordedRequest {
    method: String,
    path: String,
    headers: String,
    body: String,
}

fn serve_once(
    status: &'static str,
    response_body: &'static str,
) -> (String, JoinHandle<RecordedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
    let addr = listener.local_addr().expect("test server address");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept request");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");

        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = stream.read(&mut chunk).expect("read request");
            assert!(read > 0, "client closed before full request");
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(header_end) = find_header_end(&buffer) {
                let headers = String::from_utf8_lossy(&buffer[..header_end]);
                let content_length = content_length(&headers);
                if buffer.len() >= header_end + content_length {
                    break;
                }
            }
        }

        let header_end = find_header_end(&buffer).expect("request headers");
        let headers = String::from_utf8_lossy(&buffer[..header_end]);
        let content_length = content_length(&headers);
        let request_line = headers.lines().next().expect("request line");
        let mut request_parts = request_line.split_whitespace();
        let method = request_parts.next().expect("method").to_string();
        let path = request_parts.next().expect("path").to_string();
        let body =
            String::from_utf8_lossy(&buffer[header_end..header_end + content_length]).to_string();

        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{response_body}",
            response_body.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");

        RecordedRequest {
            method,
            path,
            headers: headers.to_string(),
            body,
        }
    });

    (format!("http://{addr}"), handle)
}

fn header_value<'a>(headers: &'a str, name: &str) -> &'a str {
    headers
        .lines()
        .find_map(|line| {
            let (header_name, value) = line.split_once(':')?;
            header_name
                .eq_ignore_ascii_case(name)
                .then_some(value.trim())
        })
        .unwrap_or_else(|| panic!("missing header {name}\n{headers}"))
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().expect("valid content-length"))
        })
        .unwrap_or(0)
}

#[tokio::test]
async fn chain_info_gets_public_endpoint_and_unwraps_data() {
    let (url, server) = serve_once(
        "200 OK",
        r#"{"success":true,"data":{"chain_id":"zincha-vega-1","block_height":42},"error":null}"#,
    );
    let client = ZinchaClient::new(&url).expect("client");

    let info = client.chain_info().await.expect("chain info");

    assert_eq!(info["chain_id"], "zincha-vega-1");
    assert_eq!(info["block_height"], 42);
    let request = server.join().expect("server thread");
    assert_eq!(request.method, "GET");
    assert_eq!(request.path, "/v1/chain/info");
    assert!(request.body.is_empty());
}

#[tokio::test]
async fn submit_signed_transaction_uses_openapi_path_and_body() {
    let (url, server) = serve_once(
        "200 OK",
        r#"{"success":true,"data":{"accepted":true,"hash":"abcd"},"error":null}"#,
    );
    let client = ZinchaClient::new(&url).expect("client");

    let response = client
        .submit_signed_transaction_hex("abcd")
        .await
        .expect("submit response");

    assert_eq!(response["accepted"], true);
    let request = server.join().expect("server thread");
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/v1/tx/submit");
    let body: Value = serde_json::from_str(&request.body).expect("json body");
    assert_eq!(body, serde_json::json!({"signed_tx_hex": "abcd"}));
}

#[tokio::test]
async fn faucet_uses_openapi_path_and_amount_fields() {
    let (url, server) = serve_once(
        "200 OK",
        r#"{"success":true,"data":{"status":"queued"},"error":null}"#,
    );
    let client = ZinchaClient::new(&url).expect("client");

    let response = client
        .request_faucet("zn1recipient", Some(1_000_000), Some(1))
        .await
        .expect("faucet response");

    assert_eq!(response["status"], "queued");
    let request = server.join().expect("server thread");
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/v1/faucet");
    let body: Value = serde_json::from_str(&request.body).expect("json body");
    assert_eq!(
        body,
        serde_json::json!({
            "address": "zn1recipient",
            "amount_micro_zin": 1_000_000,
            "amount_zin": 1,
        })
    );
}

#[tokio::test]
async fn transaction_history_helpers_use_cursor_pagination_without_offset() {
    let (url, server) = serve_once(
        "200 OK",
        r#"{"success":true,"data":{"items":[],"pagination":{"total":0,"limit":5,"has_more":false,"next_cursor":null,"cursor":"abcdef"}},"error":null}"#,
    );
    let client = ZinchaClient::new(&url).expect("client");

    let response = client
        .account_transactions(
            "zn1account",
            TransactionHistoryQuery::new().limit(5).cursor("abcdef"),
        )
        .await
        .expect("account history");

    assert_eq!(response["items"], serde_json::json!([]));
    let request = server.join().expect("server thread");
    assert_eq!(request.method, "GET");
    assert_eq!(
        request.path,
        "/v1/accounts/zn1account/transactions?limit=5&cursor=abcdef"
    );
    assert!(!request.path.contains("offset"));

    let (url, server) = serve_once(
        "200 OK",
        r#"{"success":true,"data":{"items":[],"pagination":{"total":0,"limit":2,"has_more":false,"next_cursor":null,"cursor":"c0ffee"}},"error":null}"#,
    );
    let client = ZinchaClient::new(&url).expect("client");

    client
        .contract_transactions(
            "zn1contract",
            TransactionHistoryQuery::new().limit(2).cursor("c0ffee"),
        )
        .await
        .expect("contract history");

    let request = server.join().expect("server thread");
    assert_eq!(request.method, "GET");
    assert_eq!(
        request.path,
        "/v1/contracts/zn1contract/transactions?limit=2&cursor=c0ffee"
    );
    assert!(!request.path.contains("offset"));

    let (url, server) = serve_once(
        "200 OK",
        r#"{"success":true,"data":{"items":[],"pagination":{"total":0,"limit":3,"has_more":false,"next_cursor":null,"cursor":"1234"}},"error":null}"#,
    );
    let client = ZinchaClient::new(&url).expect("client");

    client
        .token_transactions("11", TransactionHistoryQuery::new().limit(3).cursor("1234"))
        .await
        .expect("token history");

    let request = server.join().expect("server thread");
    assert_eq!(request.method, "GET");
    assert_eq!(
        request.path,
        "/v1/tokens/11/transactions?limit=3&cursor=1234"
    );
    assert!(!request.path.contains("offset"));
}

#[tokio::test]
async fn task_opportunity_helper_uses_public_unsigned_route() {
    let task_id = "aa".repeat(32);
    let response_body = format!(
        r#"{{"success":true,"data":{{"task_id":"{task_id}","description":"public brief"}},"error":null}}"#
    );
    let response_body: &'static str = Box::leak(response_body.into_boxed_str());
    let (url, server) = serve_once("200 OK", response_body);
    let client = ZinchaClient::new(&url).expect("client");

    let response = client
        .task_opportunity(&task_id)
        .await
        .expect("task opportunity");

    assert_eq!(response["task_id"], task_id);
    assert_eq!(response["description"], "public brief");
    let request = server.join().expect("server thread");
    assert_eq!(request.method, "GET");
    assert_eq!(request.path, format!("/v1/tasks/{task_id}/opportunity"));
    let lower_headers = request.headers.to_ascii_lowercase();
    assert!(!lower_headers.contains("x-zincha-address:"));
    assert!(!lower_headers.contains("x-zincha-signature:"));
}

#[tokio::test]
async fn task_helper_uses_signed_participant_auth() {
    let task_id = "aa".repeat(32);
    let response_body =
        format!(r#"{{"success":true,"data":{{"task_id":"{task_id}"}},"error":null}}"#);
    let response_body: &'static str = Box::leak(response_body.into_boxed_str());
    let (url, server) = serve_once("200 OK", response_body);
    let signer = Keypair::from_secret_bytes(&[9u8; 32]);
    let signer_address = signer.address().to_string();
    let signer_public_key = hex::encode(signer.public_key().as_bytes());
    let client = ZinchaClient::builder()
        .base_url(&url)
        .signer(signer)
        .build()
        .expect("client");

    let response = client.task(&task_id).await.expect("task detail");

    assert_eq!(response["task_id"], task_id);
    let request = server.join().expect("server thread");
    assert_eq!(request.method, "GET");
    assert_eq!(request.path, format!("/v1/tasks/{task_id}"));
    assert_eq!(
        header_value(&request.headers, "x-zincha-address"),
        signer_address
    );
    assert_eq!(
        header_value(&request.headers, "x-zincha-public-key"),
        signer_public_key
    );
    assert!(!header_value(&request.headers, "x-zincha-body-sha256").is_empty());
    assert!(!header_value(&request.headers, "x-zincha-signature").is_empty());
}

#[tokio::test]
async fn api_error_envelopes_are_reported() {
    let (url, server) = serve_once(
        "429 Too Many Requests",
        r#"{"success":false,"data":{"retry_after_secs":10},"error":"rate limited"}"#,
    );
    let client = ZinchaClient::new(&url).expect("client");

    let error = client.chain_info().await.expect_err("rate limited");

    let message = error.to_string();
    assert!(message.contains("HTTP 429"), "{message}");
    assert!(message.contains("rate limited"), "{message}");
    let request = server.join().expect("server thread");
    assert_eq!(request.method, "GET");
    assert_eq!(request.path, "/v1/chain/info");
}

#[tokio::test]
async fn success_false_envelopes_fail_even_with_http_200() {
    let (url, server) = serve_once(
        "200 OK",
        r#"{"success":false,"data":null,"error":"chain unavailable"}"#,
    );
    let client = ZinchaClient::new(&url).expect("client");

    let error = client.chain_info().await.expect_err("chain unavailable");

    let message = error.to_string();
    assert!(message.contains("chain unavailable"), "{message}");
    let request = server.join().expect("server thread");
    assert_eq!(request.method, "GET");
    assert_eq!(request.path, "/v1/chain/info");
}

#[test]
fn signed_request_parts_use_exact_server_message() {
    let secret = [7u8; 32];
    let signer = Keypair::from_secret_bytes(&secret);
    let body = br#"{"amount":1}"#;
    let body_hash = hash_bytes(body).to_hex();

    let parts = signed_request_parts(
        &signer,
        "post",
        "/v1/accounts/znabc/tasks?limit=1",
        body,
        Some(1_700_000_000_123),
        Some("00112233445566778899aabbccddeeff"),
    )
    .expect("signed parts");

    assert_eq!(parts.body_sha256, body_hash);
    assert_eq!(parts.timestamp_ms, 1_700_000_000_123);
    assert_eq!(parts.nonce, "00112233445566778899aabbccddeeff");
    assert_eq!(parts.address, signer.address().to_string());
    assert_eq!(
        parts.public_key,
        hex::encode(signer.public_key().as_bytes())
    );
    assert_eq!(
        parts.message,
        format!(
            "zincha-rpc-signed-request-v1\nPOST\n/v1/accounts/znabc/tasks?limit=1\n1700000000123\n00112233445566778899aabbccddeeff\n{}\n{}\n{}",
            body_hash,
            signer.address(),
            hex::encode(signer.public_key().as_bytes())
        )
    );
    assert_eq!(
        parts.signature,
        hex::encode(signer.sign(parts.message.as_bytes()).to_bytes())
    );
}

#[tokio::test]
async fn signed_request_hashes_the_exact_body_bytes_it_sends() {
    let (url, server) = serve_once(
        "200 OK",
        r#"{"success":true,"data":{"accepted":true},"error":null}"#,
    );
    let signer = Keypair::from_secret_bytes(&[8u8; 32]);
    let signer_address = signer.address().to_string();
    let signer_public_key = hex::encode(signer.public_key().as_bytes());
    let client = ZinchaClient::builder()
        .base_url(&url)
        .signer(signer)
        .build()
        .expect("client");

    let response: Value = client
        .request(
            reqwest::Method::POST,
            "/v1/participant/jobs",
            RequestOptions::default()
                .body_json(serde_json::json!({"signed": true, "amount": 7}))
                .signed()
                .timestamp_ms(1_700_000_000_999)
                .nonce("ffeeddccbbaa99887766554433221100"),
        )
        .await
        .expect("signed response");

    assert_eq!(response["accepted"], true);
    let request = server.join().expect("server thread");
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/v1/participant/jobs");
    assert_eq!(
        header_value(&request.headers, "x-zincha-body-sha256"),
        hash_bytes(request.body.as_bytes()).to_hex()
    );
    assert_eq!(
        header_value(&request.headers, "x-zincha-timestamp-ms"),
        "1700000000999"
    );
    assert_eq!(
        header_value(&request.headers, "x-zincha-nonce"),
        "ffeeddccbbaa99887766554433221100"
    );
    assert_eq!(
        header_value(&request.headers, "x-zincha-address"),
        signer_address
    );
    assert_eq!(
        header_value(&request.headers, "x-zincha-public-key"),
        signer_public_key
    );
}
