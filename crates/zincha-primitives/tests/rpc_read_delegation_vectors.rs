use zincha_primitives::{
    crypto::{Address, Hash256},
    primitives::{
        rpc_read_delegate_address, rpc_read_delegation_id, RpcReadDelegationGrantData,
        RpcReadDelegationRevokeData,
    },
};

#[test]
fn rpc_read_delegation_matches_cross_language_vector() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../sdk/testdata/golden-rpc-read-delegation-v1.json"
    ))
    .unwrap();
    let delegator = Address::from_hex(vector["delegator"].as_str().unwrap()).unwrap();
    let public_key: [u8; 32] = hex::decode(vector["delegate_public_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let service_id = vector["service_id"].as_str().unwrap();
    let id = rpc_read_delegation_id(&delegator, &public_key, service_id);
    assert_eq!(id.to_hex(), vector["delegation_id"]);
    assert_eq!(
        rpc_read_delegate_address(&public_key).unwrap().to_string(),
        vector["delegate_address"]
    );
    let grant = RpcReadDelegationGrantData {
        delegate_public_key: public_key,
        service_id: service_id.to_string(),
        scope_mask: vector["scope_mask"].as_u64().unwrap(),
        expires_at_ms: vector["expires_at_ms"].as_u64().unwrap(),
    };
    assert_eq!(
        hex::encode(bincode::serialize(&grant).unwrap()),
        vector["grant_data_hex"]
    );
    let revoke = RpcReadDelegationRevokeData {
        delegation_id: Hash256::from_hex(vector["delegation_id"].as_str().unwrap()).unwrap(),
    };
    assert_eq!(
        hex::encode(bincode::serialize(&revoke).unwrap()),
        vector["revoke_data_hex"]
    );
}
