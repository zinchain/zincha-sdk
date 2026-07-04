use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};

use crate::crypto::{hash_bytes, Address, Hash256, Keypair, PublicKey, Signature};

macro_rules! define_tx_types {
    ($( $name:ident = ($code:literal, $label:literal), )+) => {
        /// Supported transaction types on the Zincha chain.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum TxType {
            $( $name, )+
        }

        impl TxType {
            const RETIRED_CONTRACT_UPGRADE_WIRE_CODE: u32 = 40;

            pub const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$name => $label, )+
                }
            }

            pub const fn wire_code(self) -> u32 {
                match self {
                    $( Self::$name => $code, )+
                }
            }

            fn from_str_name(name: &str) -> Option<Self> {
                match name {
                    $( $label => Some(Self::$name), )+
                    _ => None,
                }
            }

            fn from_wire_code(code: u32) -> std::result::Result<Self, String> {
                match code {
                    $( $code => Ok(Self::$name), )+
                    Self::RETIRED_CONTRACT_UPGRADE_WIRE_CODE => Err(
                        crate::primitives::contract::contract_upgrade_unsupported_error(),
                    ),
                    other => Err(format!("Unknown transaction type code {}", other)),
                }
            }
        }
    };
}

define_tx_types! {
    Transfer = (0, "transfer"),
    EntityLink = (1, "entity_link"),
    AgentRegister = (2, "agent_register"),
    AgentUpdate = (3, "agent_update"),
    TaskSubmit = (4, "task_submit"),
    TaskFulfill = (5, "task_fulfill"),
    TaskCancel = (6, "task_cancel"),
    ReputationUpdate = (7, "reputation_update"),
    TaskAccept = (63, "task_accept"),
    TaskDispute = (64, "task_dispute"),
    TaskResolve = (65, "task_resolve"),
    TaskFinalize = (66, "task_finalize"),
    ToolRegister = (8, "tool_register"),
    ToolInvoke = (9, "tool_invoke"),
    ToolResultSubmit = (10, "tool_result_submit"),
    ToolResultAccept = (11, "tool_result_accept"),
    ToolResultDispute = (12, "tool_result_dispute"),
    ToolResultResolve = (13, "tool_result_resolve"),
    ToolJobExpire = (14, "tool_job_expire"),
    ToolSubscriptionPlanCreate = (15, "tool_subscription_plan_create"),
    ToolSubscriptionPlanUpdate = (16, "tool_subscription_plan_update"),
    ToolSubscriptionStart = (17, "tool_subscription_start"),
    ToolSubscriptionTopUp = (18, "tool_subscription_top_up"),
    ToolSubscriptionCancel = (19, "tool_subscription_cancel"),
    ToolSubscriptionResume = (20, "tool_subscription_resume"),
    ToolSubscriptionRenew = (21, "tool_subscription_renew"),
    ToolUpdate = (22, "tool_update"),
    AgreementCreate = (23, "agreement_create"),
    AgreementAccept = (24, "agreement_accept"),
    AgreementExecute = (25, "agreement_execute"),
    AgreementDispute = (26, "agreement_dispute"),
    AgreementResolve = (27, "agreement_resolve"),
    AgreementCancel = (28, "agreement_cancel"),
    ArbitratorRegister = (29, "arbitrator_register"),
    ValidatorRegister = (30, "validator_register"),
    ValidatorExit = (31, "validator_exit"),
    ValidatorVrfCommit = (32, "validator_vrf_commit"),
    ValidatorVrfContribution = (33, "validator_vrf_contribution"),
    Stake = (34, "stake"),
    Unstake = (35, "unstake"),
    TaskDecompose = (36, "task_decompose"),
    Batch = (37, "batch"),
    ContractDeploy = (38, "contract_deploy"),
    ContractCall = (39, "contract_call"),
    TokenCreate = (41, "token_create"),
    TokenTransfer = (42, "token_transfer"),
    TokenApprove = (43, "token_approve"),
    TokenMint = (44, "token_mint"),
    TokenUpdateAuthority = (45, "token_update_authority"),
    TokenBurn = (46, "token_burn"),
    AgentDeregister = (47, "agent_deregister"),
    ToolDeregister = (48, "tool_deregister"),
    ArbitratorDeregister = (49, "arbitrator_deregister"),
    ContractDeactivate = (50, "contract_deactivate"),
    TokenDestroy = (51, "token_destroy"),
    ToolUsageReport = (52, "tool_usage_report"),
    ToolUsageAccept = (53, "tool_usage_accept"),
    ToolUsageDispute = (54, "tool_usage_dispute"),
    ToolUsageResolve = (55, "tool_usage_resolve"),
    ToolUsageExpire = (56, "tool_usage_expire"),
    ValidatorUpdate = (57, "validator_update"),
    ContractVerify = (58, "contract_verify"),
    ContractPublishAbi = (59, "contract_publish_abi"),
    ContractRouteUpdate = (60, "contract_route_update"),
    ContractRouteCall = (61, "contract_route_call"),
    ProtocolParamsUpdate = (62, "protocol_params_update"),
    CapabilityPropose = (67, "capability_propose"),
    CapabilityApprove = (68, "capability_approve"),
    CapabilityReject = (69, "capability_reject"),
    CapabilityDeprecate = (70, "capability_deprecate"),
}

impl Serialize for TxType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(self.as_str())
        } else {
            serializer.serialize_u32(self.wire_code())
        }
    }
}

impl<'de> Deserialize<'de> for TxType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let name = String::deserialize(deserializer)?;
            Self::from_str_name(&name)
                .ok_or_else(|| D::Error::custom(format!("Unknown transaction type {}", name)))
        } else {
            let code = u32::deserialize(deserializer)?;
            Self::from_wire_code(code).map_err(D::Error::custom)
        }
    }
}

/// Explicit destination for generic stake and unstake transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StakeTarget {
    Agent,
    Validator,
    RequesterAutoMatch,
}

impl StakeTarget {
    pub fn decode(data: &[u8]) -> std::result::Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }
}

/// A single operation within a batch transaction.
///
/// Inherits sender, chain_id, and nonce from the outer Transaction.
/// Each operation is executed sequentially; if any fails, the entire
/// batch is rolled back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchOperation {
    /// The operation type.
    pub tx_type: TxType,
    /// Recipient (for transfers) or zero address.
    pub recipient: Address,
    /// Amount in micro-ZIN.
    pub amount: u64,
    /// Opaque payload (same format as Transaction.data for this tx_type).
    pub data: Vec<u8>,
}

/// Data payload for Batch transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchData {
    /// The operations to execute atomically. Max 16 per batch.
    pub operations: Vec<BatchOperation>,
}

/// The unsigned transaction body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction type.
    pub tx_type: TxType,
    /// Sender address.
    pub sender: Address,
    /// Recipient address (zero address for non-transfer types).
    pub recipient: Address,
    /// Amount in micro-ZIN.
    pub amount: u64,
    /// Fee in micro-ZIN. This is the maximum total fee the sender will pay.
    /// In EIP-1559 mode: acts as max_fee = gas_used × max_fee_per_gas.
    /// Excess is refunded after execution.
    pub fee: u64,
    /// Maximum priority fee per gas unit (tip to validator, micro-ZIN).
    /// 0 = no priority tip.
    pub max_priority_fee_per_gas: u64,
    /// Sender nonce (monotonically increasing per-account).
    pub nonce: u64,
    /// Unix timestamp in milliseconds.
    pub timestamp: u64,
    /// Recent canonical block height this transaction was built against.
    ///
    /// A zero value means the transaction uses the legacy timestamp-derived
    /// validity window. Non-zero validity windows are consensus-enforced.
    pub reference_block_height: u64,
    /// Hash of `reference_block_height`.
    ///
    /// A zero hash is allowed only when `max_valid_block_height` is zero.
    pub reference_block_hash: Hash256,
    /// Last block height that may include this transaction.
    ///
    /// Zero means the transaction relies on timestamp drift plus mempool age
    /// pruning for compatibility with offline signing and existing tests.
    pub max_valid_block_height: u64,
    /// Opaque payload data (agent registration, task params, etc.)
    pub data: Vec<u8>,
    /// Chain ID to prevent replay across chains.
    pub chain_id: String,
}

impl Transaction {
    /// Compute the canonical hash of this transaction (for signing).
    pub fn hash(&self) -> Hash256 {
        let encoded = bincode::serialize(self).expect("Transaction serialization failed");
        hash_bytes(&encoded)
    }

    /// Create a signed transaction by signing with the given keypair.
    pub fn sign(self, keypair: &Keypair) -> SignedTransaction {
        let hash = self.hash();
        let signature = keypair.sign(hash.as_bytes());
        let public_key = keypair.public_key();
        SignedTransaction {
            transaction: self,
            signature,
            public_key,
            hash,
        }
    }

    pub fn has_explicit_validity_window(&self) -> bool {
        self.max_valid_block_height != 0
    }

    pub fn is_expired_at_block(&self, block_number: u64) -> bool {
        self.has_explicit_validity_window() && block_number > self.max_valid_block_height
    }

    pub fn blocks_until_expiry_at(&self, block_number: u64) -> Option<u64> {
        if self.has_explicit_validity_window() {
            Some(self.max_valid_block_height.saturating_sub(block_number))
        } else {
            None
        }
    }

    pub fn set_validity_window(
        &mut self,
        reference_block_height: u64,
        reference_block_hash: Hash256,
        ttl_blocks: u64,
    ) {
        self.reference_block_height = reference_block_height;
        self.reference_block_hash = reference_block_hash;
        self.max_valid_block_height = reference_block_height.saturating_add(ttl_blocks.max(1));
    }

    /// Create a new transfer transaction.
    pub fn new_transfer(
        sender: Address,
        recipient: Address,
        amount: u64,
        fee: u64,
        nonce: u64,
        chain_id: &str,
    ) -> Self {
        Self {
            tx_type: TxType::Transfer,
            sender,
            recipient,
            amount,
            fee,
            max_priority_fee_per_gas: 0,
            nonce,
            timestamp: current_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Hash256::zero(),
            max_valid_block_height: 0,
            data: vec![],
            chain_id: chain_id.to_string(),
        }
    }
}

/// A transaction with a valid Ed25519 signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransaction {
    pub transaction: Transaction,
    pub signature: Signature,
    pub public_key: PublicKey,
    pub hash: Hash256,
}

impl SignedTransaction {
    /// Verify the signature against the transaction hash and public key.
    /// Also verifies that the public key maps to the sender address.
    pub fn verify(&self) -> crate::error::Result<()> {
        // Verify the hash matches the transaction
        let expected_hash = self.transaction.hash();
        if expected_hash != self.hash {
            return Err(crate::error::ZinchaError::InvalidTransaction(
                "Transaction hash mismatch".to_string(),
            ));
        }

        // Verify the public key maps to the sender address
        let derived_address = self.public_key.to_address();
        if derived_address != self.transaction.sender {
            return Err(crate::error::ZinchaError::InvalidTransaction(
                "Public key does not match sender address".to_string(),
            ));
        }

        // Verify the Ed25519 signature
        self.public_key
            .verify(self.hash.as_bytes(), &self.signature)?;

        Ok(())
    }

    /// Get the transaction hash.
    pub fn tx_hash(&self) -> Hash256 {
        self.hash
    }

    /// Get the sender address.
    pub fn sender(&self) -> &Address {
        &self.transaction.sender
    }

    /// Get the total cost (amount + fee).
    pub fn total_cost(&self) -> u64 {
        self.transaction.amount.saturating_add(self.transaction.fee)
    }

    /// Byte size of the serialized transaction (for gas metering).
    pub fn byte_size(&self) -> usize {
        bincode::serialize(self).map_or(0, |b| b.len())
    }

    /// Construct a deterministic synthetic inner transaction for a batch
    /// operation. These hashes are internal execution identifiers used to keep
    /// batch-local post-pass bookkeeping collision-free.
    pub fn synthetic_batch_operation(
        batch_tx: &SignedTransaction,
        op_index: usize,
        nonce: u64,
        operation: &BatchOperation,
    ) -> Self {
        let inner_tx = Transaction {
            tx_type: operation.tx_type,
            sender: batch_tx.transaction.sender.clone(),
            recipient: operation.recipient.clone(),
            amount: operation.amount,
            fee: 0,
            max_priority_fee_per_gas: 0,
            nonce,
            timestamp: batch_tx.transaction.timestamp,
            reference_block_height: batch_tx.transaction.reference_block_height,
            reference_block_hash: batch_tx.transaction.reference_block_hash,
            max_valid_block_height: batch_tx.transaction.max_valid_block_height,
            data: operation.data.clone(),
            chain_id: batch_tx.transaction.chain_id.clone(),
        };
        Self {
            transaction: inner_tx,
            signature: batch_tx.signature.clone(),
            public_key: batch_tx.public_key.clone(),
            hash: synthetic_batch_operation_hash(batch_tx.tx_hash(), op_index),
        }
    }
}

pub fn synthetic_batch_operation_hash(batch_tx_hash: Hash256, op_index: usize) -> Hash256 {
    let mut bytes = Vec::with_capacity(32 + std::mem::size_of::<u64>() + 24);
    bytes.extend_from_slice(b"zincha_batch_inner_tx_v1");
    bytes.extend_from_slice(batch_tx_hash.as_bytes());
    bytes.extend_from_slice(&(op_index as u64).to_be_bytes());
    hash_bytes(&bytes)
}

fn current_timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
pub(crate) fn serialize_legacy_signed_transaction_without_priority_fee(
    signed_tx: &SignedTransaction,
) -> Vec<u8> {
    #[derive(Serialize)]
    struct LegacyTransactionWithoutPriorityFee {
        tx_type: TxType,
        sender: Address,
        recipient: Address,
        amount: u64,
        fee: u64,
        nonce: u64,
        timestamp: u64,
        data: Vec<u8>,
        chain_id: String,
    }

    #[derive(Serialize)]
    struct LegacySignedTransactionWithoutPriorityFee {
        transaction: LegacyTransactionWithoutPriorityFee,
        signature: Signature,
        public_key: PublicKey,
        hash: Hash256,
    }

    bincode::serialize(&LegacySignedTransactionWithoutPriorityFee {
        transaction: LegacyTransactionWithoutPriorityFee {
            tx_type: signed_tx.transaction.tx_type,
            sender: signed_tx.transaction.sender.clone(),
            recipient: signed_tx.transaction.recipient.clone(),
            amount: signed_tx.transaction.amount,
            fee: signed_tx.transaction.fee,
            nonce: signed_tx.transaction.nonce,
            timestamp: signed_tx.transaction.timestamp,
            data: signed_tx.transaction.data.clone(),
            chain_id: signed_tx.transaction.chain_id.clone(),
        },
        signature: signed_tx.signature.clone(),
        public_key: signed_tx.public_key.clone(),
        hash: signed_tx.hash,
    })
    .expect("legacy signed transaction bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let kp = Keypair::generate();
        let tx = Transaction::new_transfer(
            kp.address(),
            Address::treasury(),
            1_000_000,
            10,
            0,
            "zincha-test-1",
        );
        let signed = tx.sign(&kp);
        assert!(signed.verify().is_ok());
    }

    #[test]
    fn test_wrong_key_fails_verify() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let tx = Transaction::new_transfer(
            kp1.address(),
            Address::treasury(),
            1_000_000,
            10,
            0,
            "zincha-test-1",
        );
        // Sign with kp1 but tamper the public key field
        let mut signed = tx.sign(&kp1);
        signed.public_key = kp2.public_key();
        assert!(signed.verify().is_err());
    }

    #[test]
    fn test_tx_hash_deterministic() {
        let kp = Keypair::from_secret_bytes(&[1u8; 32]);
        let tx1 = Transaction {
            tx_type: TxType::Transfer,
            sender: kp.address(),
            recipient: Address::treasury(),
            amount: 500,
            fee: 10,
            max_priority_fee_per_gas: 0,
            nonce: 0,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            reference_block_height: 0,
            reference_block_hash: Hash256::zero(),
            max_valid_block_height: 0,
            data: vec![],
            chain_id: "test".to_string(),
        };
        let tx2 = tx1.clone();
        assert_eq!(tx1.hash(), tx2.hash());
    }

    #[test]
    fn test_explicit_validity_window_helpers() {
        let kp = Keypair::generate();
        let mut tx = Transaction::new_transfer(
            kp.address(),
            Address::treasury(),
            1_000_000,
            10,
            0,
            "zincha-test-1",
        );
        let reference_hash = Hash256::from_bytes([7u8; 32]);
        tx.set_validity_window(10, reference_hash, 4);

        assert!(tx.has_explicit_validity_window());
        assert_eq!(tx.reference_block_height, 10);
        assert_eq!(tx.reference_block_hash, reference_hash);
        assert_eq!(tx.max_valid_block_height, 14);
        assert!(!tx.is_expired_at_block(14));
        assert!(tx.is_expired_at_block(15));
        assert_eq!(tx.blocks_until_expiry_at(12), Some(2));
        assert_eq!(tx.blocks_until_expiry_at(15), Some(0));
    }

    #[test]
    fn test_tx_type_json_roundtrip_uses_canonical_names() {
        let encoded = serde_json::to_string(&TxType::ContractRouteUpdate).expect("serialize");
        assert_eq!(encoded, "\"contract_route_update\"");
        let decoded: TxType = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, TxType::ContractRouteUpdate);
    }

    #[test]
    fn test_tx_type_binary_roundtrip_preserves_historic_wire_codes() {
        let encoded = bincode::serialize(&TxType::TokenCreate).expect("serialize");
        assert_eq!(encoded, bincode::serialize(&41u32).expect("u32 serialize"));
        let decoded: TxType = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(decoded, TxType::TokenCreate);
    }

    #[test]
    fn test_retired_contract_upgrade_wire_code_is_rejected() {
        let retired = bincode::serialize(&40u32).expect("serialize retired code");
        let error = bincode::deserialize::<TxType>(&retired).expect_err("retired code must fail");
        assert!(
            error
                .to_string()
                .contains("ContractUpgrade is not supported"),
            "unexpected retired-code error: {}",
            error
        );
    }

    #[test]
    fn test_signed_transaction_deserialize_rejects_legacy_omitted_priority_fee() {
        let kp = Keypair::generate();
        let signed = Transaction::new_transfer(
            kp.address(),
            Address::treasury(),
            1_000_000,
            10,
            0,
            "zincha-test-1",
        )
        .sign(&kp);
        let legacy_bytes = serialize_legacy_signed_transaction_without_priority_fee(&signed);
        bincode::deserialize::<SignedTransaction>(&legacy_bytes)
            .expect_err("legacy signed transaction bytes must fail");
    }
}
