use zincha_primitives::primitives::{
    ToolInvokeData, ToolRegisterData, ToolResultAcceptData, ToolResultDisputeData,
    ToolResultResolveData, ToolResultSubmitData, ToolSubscriptionResumeData, ToolUpdateData,
};

#[test]
fn tool_payload_decoders_match_current_wire_vectors_and_reject_extra_bytes() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/golden-agent-tool-lifecycle.json")).unwrap();
    macro_rules! check {
        ($name:literal, $payload:ty) => {{
            let mut encoded = hex::decode(vectors[$name]["data_hex"].as_str().unwrap()).unwrap();
            let decoded = <$payload>::decode(&encoded).expect("canonical tool payload");
            assert_eq!(bincode::serialize(&decoded).unwrap(), encoded);
            encoded.push(0);
            assert!(
                <$payload>::decode(&encoded).is_err(),
                "{} accepted trailing bytes",
                $name
            );
        }};
    }
    check!("tool_register", ToolRegisterData);
    check!("tool_update", ToolUpdateData);
    check!("tool_invoke", ToolInvokeData);
    check!("tool_subscription_resume", ToolSubscriptionResumeData);
    check!("tool_result_submit", ToolResultSubmitData);
    check!("tool_result_accept", ToolResultAcceptData);
    check!("tool_result_dispute", ToolResultDisputeData);
    check!("tool_result_resolve", ToolResultResolveData);
}

#[test]
fn tool_invoke_rejects_invalid_gas_limits_before_returning_a_payload() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/golden-agent-tool-lifecycle.json")).unwrap();
    let bytes = hex::decode(vectors["tool_invoke"]["data_hex"].as_str().unwrap()).unwrap();
    let mut payload = ToolInvokeData::decode(&bytes).unwrap();
    for gas_limit in [
        0,
        zincha_primitives::primitives::contract::MAX_CONTRACT_GAS + 1,
    ] {
        payload.gas_limit = gas_limit;
        let error = ToolInvokeData::decode(&bincode::serialize(&payload).unwrap()).unwrap_err();
        assert!(error.to_string().contains("gas_limit"));
    }
}
