use serde::Serialize;
use serde_json::Value;
use zincha_primitives::crypto::{Address, Hash256};
use zincha_primitives::primitives::agreement::{
    AgreementAcceptData, AgreementCancelData, AgreementCreateData, AgreementDisputeData,
    AgreementDisputePartyOutcome, AgreementDisputeReputationEffect, AgreementExecuteData,
    AgreementPayoutShare, AgreementResolveData, MilestoneDef,
};

fn encoded<T: Serialize>(value: &T) -> String {
    hex::encode(bincode::serialize(value).expect("agreement payload should serialize"))
}

#[test]
fn agreement_lifecycle_fixture_matches_rust_bincode() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../sdk/testdata/golden-agreement-lifecycle.json"
    ))
    .unwrap();
    let a = Address::from_raw_hex(&"11".repeat(20)).unwrap();
    let b = Address::from_raw_hex(&"22".repeat(20)).unwrap();
    let c = Address::from_raw_hex(&"33".repeat(20)).unwrap();
    let agreement_id = Hash256::from_hex(&"aa".repeat(32)).unwrap();

    let payloads = [
        (
            "create",
            encoded(&AgreementCreateData {
                parties: vec![a.clone(), b.clone(), c.clone()],
                terms: b"deliver audited model".to_vec(),
                escrow_amount: 1_000_000,
                expires_at: 1_900_000_000_000,
                arbitrator: Some(Address::from_raw_hex(&"44".repeat(20)).unwrap()),
                milestones: vec![
                    MilestoneDef {
                        description: "prototype".into(),
                        amount: 400_000,
                    },
                    MilestoneDef {
                        description: "production".into(),
                        amount: 600_000,
                    },
                ],
                service_provider: b.clone(),
                settlement_allocations: vec![
                    AgreementPayoutShare {
                        recipient: b.clone(),
                        share_bps: 7_500,
                    },
                    AgreementPayoutShare {
                        recipient: c,
                        share_bps: 2_500,
                    },
                ],
                settlement_approver: Some(a.clone()),
            }),
        ),
        ("accept", encoded(&AgreementAcceptData { agreement_id })),
        (
            "execute",
            encoded(&AgreementExecuteData {
                agreement_id,
                result_hash: Hash256::from_hex(&"bb".repeat(32)).unwrap(),
                milestone_index: 1,
            }),
        ),
        (
            "dispute",
            encoded(&AgreementDisputeData {
                agreement_id,
                reason: "result failed review".into(),
                milestone_index: Some(1),
            }),
        ),
        (
            "resolve",
            encoded(&AgreementResolveData {
                agreement_id,
                payouts: vec![
                    AgreementPayoutShare {
                        recipient: a.clone(),
                        share_bps: 2_000,
                    },
                    AgreementPayoutShare {
                        recipient: b.clone(),
                        share_bps: 8_000,
                    },
                ],
                reputation_effects: vec![
                    AgreementDisputeReputationEffect {
                        party: a,
                        outcome: AgreementDisputePartyOutcome::Lost,
                    },
                    AgreementDisputeReputationEffect {
                        party: b,
                        outcome: AgreementDisputePartyOutcome::Won,
                    },
                ],
                reason: "provider evidence prevailed".into(),
                milestone_index: Some(1),
            }),
        ),
        ("cancel", encoded(&AgreementCancelData { agreement_id })),
    ];

    for (name, data_hex) in payloads {
        assert_eq!(
            data_hex,
            fixture[name]["data_hex"].as_str().unwrap(),
            "{name}"
        );
    }
}
