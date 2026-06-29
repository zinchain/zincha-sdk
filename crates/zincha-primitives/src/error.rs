use thiserror::Error;

/// Top-level error type for the Zincha chain.
#[derive(Error, Debug)]
pub enum ZinchaError {
    // --- Crypto ---
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    // --- Transaction ---
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },

    #[error("Invalid nonce: expected {expected}, got {got}")]
    InvalidNonce { expected: u64, got: u64 },

    #[error("Transaction already exists: {0}")]
    DuplicateTransaction(String),

    // --- Block ---
    #[error("Invalid block: {0}")]
    InvalidBlock(String),

    #[error("Invalid block hash: expected {expected}, got {got}")]
    InvalidBlockHash { expected: String, got: String },

    #[error("Block parent not found: {0}")]
    ParentNotFound(String),

    #[error("Invalid merkle root")]
    InvalidMerkleRoot,

    // --- Agent ---
    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    #[error("Agent already registered: {0}")]
    AgentAlreadyRegistered(String),

    #[error("Invalid agent capability: {0}")]
    InvalidCapability(String),

    #[error("Insufficient stake: minimum {minimum}, provided {provided}")]
    InsufficientStake { minimum: u64, provided: u64 },

    // --- Task ---
    #[error("Task not found: {0}")]
    TaskNotFound(String),

    #[error("Task already fulfilled: {0}")]
    TaskAlreadyFulfilled(String),

    #[error("No matching agent for task: {0}")]
    NoMatchingAgent(String),

    #[error("Task expired: {0}")]
    TaskExpired(String),

    // --- Consensus ---
    #[error("Not a registered validator: {0}")]
    NotValidator(String),

    #[error("Invalid computation proof: {0}")]
    InvalidComputationProof(String),

    #[error("Consensus failure: {0}")]
    ConsensusFailure(String),

    // --- Storage ---
    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    // --- Network ---
    #[error("Network error: {0}")]
    Network(String),

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Rate limited: {0}")]
    RateLimited(String),

    #[error("Protected orderflow route unavailable: {0}")]
    OrderflowRouteUnavailable(String),

    // --- Config ---
    #[error("Configuration error: {0}")]
    Config(String),

    // --- Generic ---
    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, ZinchaError>;

// Conversion impls for downstream crate errors
impl From<bincode::Error> for ZinchaError {
    fn from(e: bincode::Error) -> Self {
        ZinchaError::Serialization(e.to_string())
    }
}

impl From<serde_json::Error> for ZinchaError {
    fn from(e: serde_json::Error) -> Self {
        ZinchaError::Serialization(e.to_string())
    }
}
