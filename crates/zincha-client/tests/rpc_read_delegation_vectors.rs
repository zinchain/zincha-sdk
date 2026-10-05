use zincha_client::delegated_request_headers;
use zincha_primitives::crypto::Keypair;

#[test]
fn delegated_request_signature_matches_cross_language_vector() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../sdk/testdata/golden-rpc-read-delegation-v1.json"
    ))
    .unwrap();
    let request = &vector["delegated_request"];
    let secret: [u8; 32] = hex::decode(vector["delegate_secret_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let signer = Keypair::from_secret_bytes(&secret);
    let body = hex::decode(request["body_hex"].as_str().unwrap()).unwrap();
    let headers = delegated_request_headers(
        &signer,
        request["method"].as_str().unwrap(),
        request["request_target"].as_str().unwrap(),
        &body,
        vector["delegation_id"].as_str().unwrap(),
        Some(request["timestamp_ms"].as_u64().unwrap()),
        Some(request["nonce"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(headers["x-zincha-address"], vector["delegate_address"]);
    assert_eq!(
        headers["x-zincha-public-key"],
        vector["delegate_public_key"]
    );
    assert_eq!(headers["x-zincha-body-sha256"], request["body_sha256"]);
    assert_eq!(headers["x-zincha-signature"], request["signature"]);
}
