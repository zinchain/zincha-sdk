use serde_json::{json, Value};
use zincha_primitives::crypto::{Address, Hash256, Keypair};
use zincha_primitives::primitives::SignedTransaction;
use zincha_primitives::wallet::AgentWallet;

const CHAIN_ID: &str = "zincha-vega-1";
const FEE: u64 = 1_000;

fn fixture_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../sdk/testdata/golden-token-operations.json")
}

fn wallet(nonce: u64, timestamp: u64) -> AgentWallet {
    let mut wallet = AgentWallet::new(Keypair::from_secret_bytes(&[7u8; 32]), CHAIN_ID, "");
    wallet.set_nonce(nonce);
    wallet.set_timestamp_ms(timestamp);
    wallet.set_transaction_validity_window(
        42,
        Hash256::from_hex(&"11".repeat(32)).expect("reference hash"),
        100,
    );
    wallet
}

fn transaction_vector(signed: &SignedTransaction) -> Value {
    json!({
        "tx_type": signed.transaction.tx_type.as_str(),
        "recipient": signed.transaction.recipient.to_string(),
        "fee_micro_zin": signed.transaction.fee,
        "nonce": signed.transaction.nonce,
        "chain_id": signed.transaction.chain_id,
        "timestamp": signed.transaction.timestamp,
        "reference_block_height": signed.transaction.reference_block_height,
        "reference_block_hash": signed.transaction.reference_block_hash.to_hex(),
        "max_valid_block_height": signed.transaction.max_valid_block_height,
        "unsigned_tx_hex": hex::encode(
            bincode::serialize(&signed.transaction).expect("serialize unsigned transaction")
        ),
        "transaction_hash": signed.hash.to_hex(),
        "signature_hex": hex::encode(signed.signature.to_bytes()),
        "signed_tx_hex": hex::encode(
            bincode::serialize(signed).expect("serialize signed transaction")
        ),
    })
}

#[test]
fn token_destination_builders_match_rust_wallet_semantics() {
    let path = fixture_path();
    let mut fixture: Value = serde_json::from_slice(
        &std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("decode {}: {error}", path.display()));

    let token_id = Hash256::from_hex(
        fixture["token_id"]
            .as_str()
            .expect("fixture token_id string"),
    )
    .expect("fixture token id");
    let recipient = Address::from_hex(
        fixture["recipient"]
            .as_str()
            .expect("fixture recipient string"),
    )
    .expect("fixture recipient");
    let spender = Address::from_hex(fixture["spender"].as_str().expect("fixture spender string"))
        .expect("fixture spender");

    let transfer = wallet(7, 1_700_000_001_001)
        .build_transfer_token(token_id, recipient.clone(), 123_456, FEE)
        .expect("build token transfer");
    let approve = wallet(8, 1_700_000_001_002)
        .build_approve_token(token_id, spender.clone(), 77_000, FEE)
        .expect("build token approval");
    let mint = wallet(9, 1_700_000_001_003)
        .build_mint_token(token_id, recipient.clone(), 250_000, FEE)
        .expect("build token mint");

    assert_eq!(transfer.transaction.recipient, recipient);
    assert_eq!(approve.transaction.recipient, spender);
    assert_eq!(mint.transaction.recipient, recipient);

    let expected = [
        ("transfer", transaction_vector(&transfer)),
        ("approve", transaction_vector(&approve)),
        ("mint", transaction_vector(&mint)),
    ];

    if std::env::var_os("ZINCHA_WRITE_SDK_GOLDEN").is_some() {
        for (operation, transaction) in expected {
            fixture[operation]["transaction"] = transaction;
        }
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&fixture).expect("encode fixture"),
        )
        .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
        return;
    }

    for (operation, transaction) in expected {
        assert_eq!(
            fixture[operation]["transaction"], transaction,
            "{operation}"
        );
    }
}
