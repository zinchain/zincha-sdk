use serde::{Deserialize, Serialize};

use super::agent::Capability;
use crate::crypto::{hash_bytes, Address, Hash256};

/// Status of an task in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum TaskStatus {
    Pending,
    Matched,
    InProgress,
    Submitted,
    Disputed,
    Fulfilled,
    Failed,
    Expired,
    Cancelled,
    /// Parent task has been decomposed into subtasks.
    /// It stays in this state until all subtasks are fulfilled,
    /// then automatically transitions to Fulfilled.
    Decomposed,
}

/// An task: a declarative expression of what an agent wants accomplished.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub task_id: Hash256,
    pub requester: Address,
    pub description: String,
    /// Verified 128-dim embedding (validator-computed from description text).
    pub description_embedding: Vec<f32>,
    /// Optional neural embedding from client (e.g., MiniLM). Additive bonus only.
    #[serde(default)]
    pub neural_embedding: Vec<f32>,
    pub required_capabilities: Vec<Capability>,
    pub max_fee: u64,
    pub priority: u8,
    pub deadline: u64,
    pub parameters: Vec<u8>,
    pub status: TaskStatus,
    pub matched_agent: Option<Address>,
    pub submitted_at_block: u64,
    pub agreed_fee: u64,
    #[serde(default)]
    pub challenge_window_ms: u64,
    pub result_hash: Option<Hash256>,
    #[serde(default)]
    pub submitted_at: Option<u64>,
    #[serde(default)]
    pub challenge_deadline: Option<u64>,
    #[serde(default)]
    pub dispute_reason: Option<String>,
    #[serde(default)]
    pub disputed_at: Option<u64>,
    #[serde(default)]
    pub arbitrator: Option<Address>,
    #[serde(default)]
    pub arbitrator_fee_bps: u16,
    #[serde(default)]
    pub arbitration_deadline_at: Option<u64>,
    #[serde(default)]
    pub arbitration_reassignments: u8,
    #[serde(default)]
    pub prior_arbitrators: Vec<Address>,
    /// Resolution metadata persists after settlement so the durable watch
    /// worker can reconstruct TaskResolved after a replay-gap recovery.
    #[serde(default)]
    pub resolved_by: Option<Address>,
    #[serde(default)]
    pub resolution_agent_wins: Option<bool>,
    #[serde(default)]
    pub resolution_reason: Option<String>,
    #[serde(default)]
    pub resolved_at: Option<u64>,
    pub tools_used: Vec<Hash256>,
    /// Tools from tools_used that were verified via AccessToken proof
    /// (token_id resolved on-chain → token.invoker == fulfilling agent).
    /// Only verified tools receive quality propagation in ReputationUpdate.
    #[serde(default)]
    pub verified_tools: Vec<Hash256>,
    /// If this task was decomposed, the IDs of its subtasks.
    pub subtask_ids: Vec<Hash256>,
    /// If this is a subtask, the parent task ID.
    pub parent_task: Option<Hash256>,
    /// If this is a subtask, indices of other subtasks that must
    /// complete before this one can be fulfilled (DAG dependencies).
    pub dependencies: Vec<u32>,
    /// Result hashes from dependency subtasks, provided at fulfillment
    /// to prove the agent had access to upstream results.
    pub input_refs: Vec<Hash256>,
    /// Requester's matching preferences (weights, filters, discovery boost).
    pub match_preferences: MatchPreferences,
    /// Whether the requester has submitted a reputation rating for this task.
    /// Prevents double-rating: once true, further ReputationUpdate txs are rejected.
    #[serde(default)]
    pub rated: bool,
    /// Whether this task's original requester submission unit has been
    /// neutralized out of requester trust/auto-match scoring because the
    /// matched counterparty later resolved into the same entity.
    #[serde(default)]
    pub requester_submission_neutralized: bool,
    /// Storage deposit locked for this task entry (micro-ZIN).
    /// Refunded to requester when task is fulfilled, cancelled, or expired.
    #[serde(default)]
    pub storage_deposit: u64,
}

impl Task {
    pub fn is_expired(&self, current_time_ms: u64) -> bool {
        current_time_ms > self.deadline
    }

    pub fn is_matchable(&self) -> bool {
        self.status == TaskStatus::Pending
    }

    /// Check if this is a subtask (has a parent task).
    pub fn is_subtask(&self) -> bool {
        self.parent_task.is_some()
    }

    pub fn clear_submission_lifecycle(&mut self) {
        self.submitted_at = None;
        self.challenge_deadline = None;
        self.dispute_reason = None;
        self.disputed_at = None;
        self.arbitration_deadline_at = None;
        self.arbitration_reassignments = 0;
        self.prior_arbitrators.clear();
        self.arbitrator = None;
        self.arbitrator_fee_bps = 0;
    }

    pub fn clear_resolution_metadata(&mut self) {
        self.resolved_by = None;
        self.resolution_agent_wins = None;
        self.resolution_reason = None;
        self.resolved_at = None;
    }
}

/// Requester-configurable matching preferences.
///
/// Controls how agents are ranked for this task. All weights
/// are normalized to sum to 1.0 internally, so relative values
/// matter, not absolute.
///
/// Defaults: quality-balanced (semantic 30%, reputation 30%,
/// price 20%, freshness 10%, stake 10%).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchPreferences {
    /// Weight for semantic similarity (description match). Range: 0-100.
    pub w_semantic: u8,
    /// Weight for reputation score (quality, reliability). Range: 0-100.
    pub w_reputation: u8,
    /// Weight for price competitiveness (lower price = higher score). Range: 0-100.
    pub w_price: u8,
    /// Weight for freshness/discovery (boosts newer agents). Range: 0-100.
    pub w_freshness: u8,
    /// Weight for stake (skin in the game). Range: 0-100.
    pub w_stake: u8,
    /// Minimum reputation score to consider (0.0 = accept new agents).
    pub min_reputation: f64,
    /// Maximum acceptable fee in micro-ZIN (0 = no limit).
    pub max_price: u64,
    /// Number of resolved tasks (completed + failed) below which an agent gets a
    /// discovery boost.
    /// Default: 10. Set to 0 to disable discovery boost.
    pub discovery_threshold: u32,
    /// Bonus score (0-50) added for agents below the discovery threshold.
    /// Helps new agents surface despite having no reputation.
    pub discovery_boost: u8,
}

impl Default for MatchPreferences {
    fn default() -> Self {
        MatchPreferences {
            w_semantic: 30,
            w_reputation: 30,
            w_price: 20,
            w_freshness: 10,
            w_stake: 10,
            min_reputation: 0.0,
            max_price: 0,
            discovery_threshold: 10,
            discovery_boost: 15,
        }
    }
}

impl MatchPreferences {
    /// Normalized weights (sum to 1.0).
    pub fn weights(&self) -> (f64, f64, f64, f64, f64) {
        let total = (u16::from(self.w_semantic)
            + u16::from(self.w_reputation)
            + u16::from(self.w_price)
            + u16::from(self.w_freshness)
            + u16::from(self.w_stake))
        .max(1) as f64;
        (
            self.w_semantic as f64 / total,
            self.w_reputation as f64 / total,
            self.w_price as f64 / total,
            self.w_freshness as f64 / total,
            self.w_stake as f64 / total,
        )
    }

    /// Preset: prioritize quality over everything else.
    pub fn quality_first() -> Self {
        MatchPreferences {
            w_reputation: 50,
            w_semantic: 30,
            w_price: 5,
            w_freshness: 5,
            w_stake: 10,
            min_reputation: 3.0,
            ..Default::default()
        }
    }

    /// Preset: prioritize lowest price.
    pub fn cheapest() -> Self {
        MatchPreferences {
            w_price: 60,
            w_reputation: 15,
            w_semantic: 15,
            w_freshness: 5,
            w_stake: 5,
            ..Default::default()
        }
    }

    /// Preset: discover new agents (maximize freshness boost).
    pub fn discover_new() -> Self {
        MatchPreferences {
            w_freshness: 40,
            w_semantic: 30,
            w_price: 15,
            w_reputation: 10,
            w_stake: 5,
            discovery_boost: 30,
            discovery_threshold: 20,
            ..Default::default()
        }
    }
}

/// Data payload for TaskSubmit transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSubmitData {
    pub description: String,
    /// Optional client-provided neural embedding (e.g. MiniLM).
    /// The verified base embedding is always computed on-chain from text.
    #[serde(default)]
    pub neural_embedding: Option<Vec<f32>>,
    pub required_capabilities: Vec<Capability>,
    pub max_fee: u64,
    pub priority: u8,
    pub deadline: u64,
    pub parameters: Vec<u8>,
    /// Matching preferences (weights, filters, discovery boost).
    /// If not provided, defaults are used.
    #[serde(default)]
    pub match_preferences: MatchPreferences,
}

impl TaskSubmitData {
    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

impl TaskAcceptData {
    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

impl TaskDisputeData {
    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

impl TaskResolveData {
    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

impl TaskFinalizeData {
    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// Data payload for TaskFulfill transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskFulfillData {
    pub task_id: Hash256,
    pub result_hash: Hash256,
    pub result_data: Vec<u8>,
    pub tools_used: Vec<Hash256>,
    /// Result hashes from dependency subtasks (for subtask fulfillment).
    /// Proves the agent had access to upstream results.
    pub input_refs: Vec<Hash256>,
    /// Receipt proofs for verified tool attribution. Each entry contains
    /// an AccessTokenReceipt (issuance facts) plus a Merkle inclusion proof
    /// against the block header's `tool_receipt_root`. The handler verifies
    /// the proof, then checks invoker, tool_id, consumption, and self-use.
    ///
    /// Receipts survive access token pruning because they're committed in
    /// block data, not in ephemeral state. A 3-day DAG decomposition can
    /// still claim verified attribution for tools invoked on day 1.
    #[serde(default)]
    pub receipt_proofs: Vec<crate::primitives::tool::ReceiptWithProof>,
}

/// Data payload for TaskAccept transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAcceptData {
    pub task_id: Hash256,
}

/// Data payload for TaskDispute transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskDisputeData {
    pub task_id: Hash256,
    pub reason: String,
}

/// Data payload for TaskResolve transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskResolveData {
    pub task_id: Hash256,
    pub agent_wins: bool,
    pub reason: String,
}

/// Data payload for TaskFinalize transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskFinalizeData {
    pub task_id: Hash256,
}

/// A single subtask definition within a decomposition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubTaskDef {
    /// Human-readable description of this subtask.
    pub description: String,
    /// Capabilities required for this subtask.
    pub required_capabilities: Vec<Capability>,
    /// Indices of other subtasks that must complete first (0-based).
    /// Empty means no dependencies — the subtask can run immediately.
    pub dependencies: Vec<u32>,
    /// Portion of the parent's max_fee allocated to this subtask (micro-ZIN).
    pub escrow: u64,
}

/// Data payload for TaskDecompose transactions.
///
/// Decomposes a Pending/Matched task into multiple subtasks, each
/// independently matched and fulfilled. The parent task transitions to
/// Decomposed status and is fulfilled when all subtasks complete.
///
/// The subtasks form a DAG (directed acyclic graph) via their dependency
/// indices. The chain validates that:
/// - Total subtask escrow ≤ parent's max_fee
/// - Dependencies form a valid DAG (no cycles, indices in range)
/// - Parent task is in Pending or Matched state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskDecomposeData {
    /// The task to decompose.
    pub task_id: Hash256,
    /// The subtask definitions. Order matters — dependencies reference by index.
    pub subtasks: Vec<SubTaskDef>,
}

/// Canonical deterministic subtask ID derivation used by TaskDecompose.
///
/// This must stay shared between execution, scheduling, and tests so same-block
/// follow-up transactions fence on the exact keys that decomposition creates.
pub fn derive_subtask_id(parent_task_id: Hash256, index: usize) -> Hash256 {
    hash_bytes(format!("{}:subtask:{}", parent_task_id.to_hex(), index).as_bytes())
}
