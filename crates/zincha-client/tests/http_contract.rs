use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use zincha_client::ZinchaClient;

#[derive(Debug)]
struct RecordedRequest {
    method: String,
    path: String,
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

        RecordedRequest { method, path, body }
    });

    (format!("http://{addr}"), handle)
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
