use serde::{Deserialize, Deserializer, Serialize};

use crate::crypto::{Address, Hash256};

/// An extensible, string-based capability identifier.
///
/// Capabilities use namespaced dot-notation strings (e.g. `"ai.text.generation"`,
/// `"finance.trading.options"`, `"legal.contract.review-us"`). The string wire
/// type is stable and open: agents, tools, and tasks may use custom capability
/// strings without requiring a prior catalog registration.
///
/// Well-known capabilities are provided as constants in `Capability::*` for
/// convenience. The capability catalog is discovery and curation metadata, not
/// the authoritative set of protocol-valid capability values.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Capability(pub String);

impl Capability {
    pub fn new(s: &str) -> Self {
        Capability(s.to_lowercase())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    // ── Well-known capabilities ──────────────────────────────────
    // These are conventions, not restrictions. Custom strings are valid.

    pub fn text_generation() -> Self {
        Self::new("ai.text.generation")
    }
    pub fn image_generation() -> Self {
        Self::new("ai.image.generation")
    }
    pub fn code_execution() -> Self {
        Self::new("ai.code.execution")
    }
    pub fn data_analysis() -> Self {
        Self::new("ai.data.analysis")
    }
    pub fn web_search() -> Self {
        Self::new("ai.web.search")
    }
    pub fn translation() -> Self {
        Self::new("ai.text.translation")
    }
    pub fn summarization() -> Self {
        Self::new("ai.text.summarization")
    }
    pub fn trading() -> Self {
        Self::new("finance.trading")
    }
    pub fn reasoning() -> Self {
        Self::new("ai.reasoning")
    }
    pub fn tool_use() -> Self {
        Self::new("ai.tool.use")
    }
    pub fn audio_processing() -> Self {
        Self::new("ai.audio.processing")
    }
    pub fn video_processing() -> Self {
        Self::new("ai.video.processing")
    }
    pub fn embedding() -> Self {
        Self::new("ai.embedding")
    }
    pub fn fine_tuning() -> Self {
        Self::new("ai.fine-tuning")
    }
    pub fn validation() -> Self {
        Self::new("ai.validation")
    }
}

impl<'de> Deserialize<'de> for Capability {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(Capability(raw.to_lowercase()))
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for Capability {
    fn from(s: &str) -> Self {
        Capability::new(s)
    }
}

/// Reputation data for an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationData {
    /// Overall reputation score (0.0 - 100.0).
    pub score: f64,
    /// Total number of tasks completed successfully.
    pub tasks_completed: u64,
    /// Total number of tasks failed.
    pub tasks_failed: u64,
    /// Cumulative quality score from task evaluations.
    pub cumulative_quality: f64,
    /// Number of disputes won.
    pub disputes_won: u64,
    /// Number of disputes lost.
    pub disputes_lost: u64,
    /// Timestamp of the last reputation update.
    pub last_updated: u64,
    /// Total value (micro-ZIN) of completed tasks. Used to weight reputation
    /// so that high-value tasks matter more than trivial ones.
    #[serde(default)]
    pub total_value_completed: u64,
    /// Cumulative value-weighted quality: sum of (quality × fee) for each rated task.
    /// Divide by total_value_rated to get the value-weighted average quality.
    #[serde(default)]
    pub value_weighted_quality: f64,
    /// Number of quality ratings received (from ReputationUpdate).
    /// This is the correct denominator for avg_quality — NOT tasks_completed,
    /// because not every completed task gets rated by the requester.
    #[serde(default)]
    pub ratings_received: u64,
    /// Total value (micro-ZIN) of rated tasks. This is the correct denominator
    /// for weighted_avg_quality — NOT total_value_completed, because not every
    /// completed task gets rated.
    #[serde(default)]
    pub total_value_rated: u64,
}

impl Default for ReputationData {
    fn default() -> Self {
        Self {
            score: 0.0,
            tasks_completed: 0,
            tasks_failed: 0,
            cumulative_quality: 0.0,
            disputes_won: 0,
            disputes_lost: 0,
            last_updated: 0,
            total_value_completed: 0,
            value_weighted_quality: 0.0,
            ratings_received: 0,
            total_value_rated: 0,
        }
    }
}

impl ReputationData {
    /// Half-life for reputation decay in milliseconds (30 days).
    /// After 30 days of inactivity, the effective score is halved.
    const DECAY_HALF_LIFE_MS: f64 = 30.0 * 24.0 * 3600.0 * 1000.0;

    /// Total resolved work seen by the market.
    ///
    /// This counts both successful and failed tasks. Matching freshness and
    /// discovery should reflect how much exposure an agent has already had,
    /// not just how many successful completions they can point to.
    pub fn resolved_task_count(&self) -> u64 {
        self.tasks_completed.saturating_add(self.tasks_failed)
    }

    /// Reliability ratio: completed / (completed + failed).
    pub fn reliability(&self) -> f64 {
        let total = self.resolved_task_count();
        if total == 0 {
            return 0.0;
        }
        self.tasks_completed as f64 / total as f64
    }

    /// Simple average quality (unweighted).
    /// Divides cumulative_quality by ratings_received (not tasks_completed),
    /// because not every completed task gets rated.
    pub fn avg_quality(&self) -> f64 {
        if self.ratings_received == 0 {
            return 0.0;
        }
        self.cumulative_quality / self.ratings_received as f64
    }

    /// Value-weighted average quality: high-value tasks count more.
    /// Divides value_weighted_quality by total_value_rated (not total_value_completed),
    /// because not every completed task gets rated.
    pub fn weighted_avg_quality(&self) -> f64 {
        if self.total_value_rated == 0 {
            return 0.0;
        }
        self.value_weighted_quality / self.total_value_rated as f64
    }

    /// Effective score after time-based decay.
    ///
    /// The raw score decays exponentially based on time since last activity.
    /// Half-life: 30 days. An agent with score=80 who hasn't been active
    /// for 30 days has effective_score=40. After 60 days, 20. And so on.
    ///
    /// Active agents are unaffected — each task completion or rating
    /// resets last_updated, so the decay factor is ~1.0.
    ///
    /// Pass current_time_ms=0 to skip decay (returns raw score).
    pub fn effective_score(&self, current_time_ms: u64) -> f64 {
        if current_time_ms == 0 || self.last_updated == 0 || self.score == 0.0 {
            return self.score;
        }
        let elapsed_ms = current_time_ms.saturating_sub(self.last_updated) as f64;
        let decay = (0.5_f64).powf(elapsed_ms / Self::DECAY_HALF_LIFE_MS);
        self.score * decay
    }

    /// Days since last activity (for display purposes).
    pub fn days_inactive(&self, current_time_ms: u64) -> f64 {
        if self.last_updated == 0 {
            return 0.0;
        }
        let elapsed_ms = current_time_ms.saturating_sub(self.last_updated) as f64;
        elapsed_ms / (24.0 * 3600.0 * 1000.0)
    }

    /// Record a successful task completion (called automatically at fulfillment).
    /// Gives a small score bump for reliability (showing up and finishing work),
    /// separate from the larger quality bump in record_rating.
    ///
    /// This ensures agents build reputation from completing work even if
    /// requesters don't submit ratings. Without this, an agent who completes
    /// 100 tasks but is never rated has score=0 and gets 0 from the
    /// reputation dimension in matching (40% default weight).
    ///
    /// The completion bump is intentionally small (0.5 × weight) compared to
    /// the rating bump (quality × weight × 0.1, up to 1.0 × weight for 10/10).
    /// This avoids the BUG-006 double-counting issue: completion rewards
    /// reliability, rating rewards quality — different signals, no overlap.
    pub fn record_completion(&mut self, fee: u64, timestamp: u64) {
        self.tasks_completed = self.tasks_completed.saturating_add(1);
        self.total_value_completed = self.total_value_completed.saturating_add(fee);

        // Small reliability-based score bump (value-weighted like ratings)
        let weight = (fee as f64 / 1_000_000.0).clamp(0.01, 10.0);
        self.score = (self.score + 0.5 * weight).clamp(0.0, 100.0);

        self.last_updated = timestamp;
    }

    /// Record a quality rating from a requester (called via ReputationUpdate tx).
    /// Value-weighted: the task's fee determines how much this rating matters.
    ///
    /// The score delta is centered around quality=5.0 (neutral):
    ///   quality > 5 → positive delta (good work increases score)
    ///   quality = 5 → zero delta (only the completion bump from record_completion)
    ///   quality < 5 → negative delta (bad work decreases score)
    ///   quality = 0 → maximum penalty (−0.5 × weight, cancels the completion bump)
    ///
    /// This prevents low-quality agents from accumulating reputation by
    /// merely finishing tasks — the rating quality must be above the midpoint
    /// to produce net-positive reputation change.
    pub fn record_rating(&mut self, quality: f64, fee: u64, timestamp: u64) {
        let q = quality.clamp(0.0, 10.0);
        self.cumulative_quality += q;
        self.ratings_received = self.ratings_received.saturating_add(1);
        self.value_weighted_quality += q * fee as f64;
        self.total_value_rated = self.total_value_rated.saturating_add(fee);

        let weight = (fee as f64 / 1_000_000.0).clamp(0.01, 10.0);
        // Centered at 5.0: (q - 5) ranges from -5 to +5
        // Scale factor 0.1: delta ranges from -0.5*weight to +0.5*weight
        // This means quality=0 exactly cancels record_completion's +0.5*weight
        let delta = (q - 5.0) * weight * 0.1;
        self.score = (self.score + delta).clamp(0.0, 100.0);
        self.last_updated = timestamp;
    }

    /// Record a failed task.
    pub fn record_failure(&mut self, fee: u64, timestamp: u64) {
        self.tasks_failed = self.tasks_failed.saturating_add(1);
        let weight = (fee as f64 / 1_000_000.0).clamp(0.01, 10.0);
        self.score = (self.score - 5.0 * weight).clamp(0.0, 100.0);
        self.last_updated = timestamp;
    }
}

/// Reputation data for task requesters.
///
/// Tracks requester behavior so agents can evaluate whether to accept work
/// from this requester. A requester with a high cancellation rate, unfair
/// ratings, or abusive failed-outcome reporting may be avoided by quality
/// agents. Task disputes are part of the live settlement protocol and feed a
/// dedicated auto-match gate once the requester has enough history to judge.
///
/// Decomposition converts one parent submission into multiple executable
/// subtask work items. The parent's original submission remains counted, and
/// decomposition adds `subtasks - 1` more submitted work items so fulfillment
/// and cancellation rates stay bounded as subtasks complete. If a matched work
/// item later collapses into the same entity as the requester, that submission
/// unit is explicitly neutralized out of requester trust and auto-match
/// scoring without deleting the raw submission telemetry.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RequesterReputation {
    /// Total executable task work items submitted.
    /// A decomposed parent contributes one original submission plus one
    /// additional submitted work item for each extra subtask beyond the first.
    pub tasks_submitted: u64,
    /// Submission units retroactively neutralized out of requester scoring
    /// because the matched counterparty later resolved into the same entity.
    #[serde(default)]
    pub same_entity_submission_units_neutralized: u64,
    /// Tasks that were fulfilled successfully.
    pub tasks_fulfilled: u64,
    /// Tasks the requester cancelled after matching (wastes agent time).
    pub tasks_cancelled: u64,
    /// Matched tasks that expired because the counterparty agent timed out.
    /// This is telemetry only and does not count as requester cancellation.
    #[serde(default)]
    pub matched_agent_timeouts: u64,
    /// Total successful quality ratings given to agents.
    /// Failed outcome reports are tracked separately so honest
    /// requester rejection reports do not poison requester fairness.
    pub ratings_given: u64,
    /// Total failed outcome reports (`requester_accepted=false`) submitted after
    /// fulfillment. These remain separate from rating fairness, but very high
    /// rates still feed dedicated requester auto-match enforcement.
    #[serde(default)]
    pub failed_reports_given: u64,
    /// Average quality score given (0.0-10.0). Consistently low scores
    /// may indicate an unfair rater. This averages only successful ratings.
    pub avg_rating_given: f64,
    /// Number of ratings at the punitive floor (0/10 or 1/10).
    /// Tracks raters who use only the harshest scores.
    #[serde(default)]
    pub lowest_ratings_given: u64,
    /// Number of ratings at the collusive ceiling (10/10).
    /// Tracks raters who always mark work as perfect.
    #[serde(default)]
    pub perfect_ratings_given: u64,
    /// Total escrow budget committed across submitted tasks (micro-ZIN).
    #[serde(default)]
    pub total_escrowed: u64,
    /// Total settled spend on fulfilled third-party tasks (micro-ZIN).
    /// This is telemetry only. It does not count toward requester
    /// auto-match backing because counterparties may be collusive.
    #[serde(default)]
    pub total_settled_spend: u64,
    /// Persistent bond locked to keep this requester eligible for automatic
    /// matching in a permissionless network. Fresh addresses must bond before
    /// they can use the auto-match path, making address churn economically
    /// costly instead of nearly free.
    #[serde(default)]
    pub auto_match_bonded_amount: u64,
    /// Number of task-scoped disputes initiated by this requester.
    /// This is a live settlement-path field and feeds the dedicated requester
    /// dispute-rate auto-match gate.
    #[serde(default)]
    pub task_disputes_initiated: u64,
    /// Number of agreement disputes initiated by this requester.
    #[serde(default)]
    pub agreement_disputes_initiated: u64,
    /// Timestamp of last activity.
    pub last_active: u64,
    /// Locked collateral backing this retained requester reputation row.
    #[serde(default)]
    pub storage_deposit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RequesterAutoMatchPolicy {
    pub eligible: bool,
    pub economic_backing_policy_active: bool,
    pub trust_policy_active: bool,
    pub fairness_policy_active: bool,
    pub cancellation_policy_active: bool,
    pub dispute_policy_active: bool,
    pub failed_report_policy_active: bool,
    pub blocked_by_economic_backing: bool,
    pub blocked_by_trust: bool,
    pub blocked_by_rating_fairness: bool,
    pub blocked_by_cancellation_rate: bool,
    pub blocked_by_dispute_rate: bool,
    pub blocked_by_failed_report_rate: bool,
    pub min_auto_match_backing: u64,
    pub required_additional_backing: u64,
    pub min_trust_score: f64,
    pub min_tasks_for_trust: u64,
    pub min_rating_fairness: f64,
    pub min_ratings_for_fairness: u64,
    pub max_cancellation_rate: f64,
    pub min_tasks_for_cancellation_rate: u64,
    pub max_dispute_rate: f64,
    pub min_tasks_for_dispute_rate: u64,
    pub max_failed_report_rate: f64,
    pub min_reviewed_outcomes_for_failed_report_rate: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RequesterReputationView {
    pub trust_score: f64,
    pub tasks_submitted: u64,
    pub third_party_tasks_submitted: u64,
    pub same_entity_submission_units_neutralized: u64,
    pub tasks_fulfilled: u64,
    pub tasks_cancelled: u64,
    pub matched_agent_timeouts: u64,
    pub fulfillment_rate: f64,
    pub cancellation_rate: f64,
    pub ratings_given: u64,
    pub failed_reports_given: u64,
    pub reviewed_outcomes: u64,
    pub failed_report_rate: f64,
    pub avg_rating_given: f64,
    pub rating_fairness: f64,
    pub lowest_ratings_given: u64,
    pub perfect_ratings_given: u64,
    pub total_spent: u64,
    pub total_escrowed: u64,
    pub auto_match_bonded_amount: u64,
    pub economic_backing: u64,
    pub disputes_initiated: u64,
    pub agreement_disputes_initiated: u64,
    pub dispute_rate: f64,
    pub last_active: u64,
    pub storage_deposit: u64,
    pub auto_match_policy: RequesterAutoMatchPolicy,
}

/// Public reputation view for agent read surfaces.
///
/// `stored_score` is the raw persisted score before stake-backing and time
/// decay. `backed_score` and `effective_score` are the usable values the
/// protocol actually consumes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentReputationView {
    pub stored_score: f64,
    pub stake_backed_score_cap: f64,
    pub backed_score: f64,
    pub effective_score: f64,
    pub tasks_completed: u64,
    pub tasks_failed: u64,
    pub cumulative_quality: f64,
    pub disputes_won: u64,
    pub disputes_lost: u64,
    pub last_updated: u64,
    pub total_value_completed: u64,
    pub value_weighted_quality: f64,
    pub ratings_received: u64,
    pub total_value_rated: u64,
    pub avg_quality: f64,
    pub weighted_avg_quality: f64,
    pub reliability: f64,
    pub days_inactive: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dispute_loss_ratio: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dispute_penalty: Option<f64>,
}

/// Canonical public agent view used by REST and contract-host JSON reads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPublicView {
    pub address: Address,
    pub name: String,
    pub description: String,
    pub description_embedding: Vec<f32>,
    #[serde(default)]
    pub neural_embedding: Vec<f32>,
    pub model_hash: Hash256,
    pub capabilities: Vec<Capability>,
    pub owner: Address,
    pub stake: u64,
    pub reputation: AgentReputationView,
    pub registered_at_block: u64,
    pub registered_at: u64,
    pub active: bool,
    #[serde(default)]
    pub deregistered_at: u64,
    pub metadata: Vec<u8>,
    #[serde(default)]
    pub feedback: Vec<FeedbackEntry>,
    #[serde(default)]
    pub feedback_embedding: Vec<f32>,
    /// Recent cached reputation events kept on the agent profile.
    /// This is NOT the full append-only audit log.
    #[serde(default)]
    pub recent_reputation_events: Vec<ReputationEvent>,
    /// Total number of reputation events in the canonical append-only history.
    pub reputation_history_total: u64,
    #[serde(default)]
    pub min_fee: u64,
    #[serde(default)]
    pub fee_schedule: Vec<(String, u64)>,
    #[serde(default)]
    pub storage_deposit: u64,
}

impl RequesterReputation {
    /// Submission units that remain eligible to affect requester trust,
    /// cancellation, dispute, and auto-match policy.
    pub fn third_party_tasks_submitted(&self) -> u64 {
        self.tasks_submitted
            .saturating_sub(self.same_entity_submission_units_neutralized)
    }

    /// Fulfillment rate: how often the requester's tasks get completed.
    /// Low rate may indicate unreasonable requirements or unfair cancellation.
    pub fn fulfillment_rate(&self) -> f64 {
        let denominator = self.third_party_tasks_submitted();
        if denominator == 0 {
            return 0.0;
        }
        self.tasks_fulfilled as f64 / denominator as f64
    }

    /// Cancellation rate: how often the requester cancels after matching.
    /// Counterparty agent timeouts are tracked separately and excluded.
    pub fn cancellation_rate(&self) -> f64 {
        let denominator = self.third_party_tasks_submitted();
        if denominator == 0 {
            return 0.0;
        }
        self.tasks_cancelled as f64 / denominator as f64
    }

    /// Task dispute rate: how often this requester escalates after
    /// submitting work. This feeds a dedicated auto-match gate once the
    /// requester has enough history to judge.
    pub fn dispute_rate(&self) -> f64 {
        let denominator = self.third_party_tasks_submitted();
        if denominator == 0 {
            return 0.0;
        }
        self.task_disputes_initiated as f64 / denominator as f64
    }

    fn rating_confidence(&self) -> f64 {
        (self.ratings_given as f64 / 8.0).min(1.0)
    }

    pub fn reviewed_outcomes(&self) -> u64 {
        self.ratings_given.saturating_add(self.failed_reports_given)
    }

    /// Failed fulfilled-outcome report rate across all reviewed outcomes.
    ///
    /// This is intentionally kept separate from rating fairness because
    /// `requester_accepted=false` is not semantically the same as a low score.
    pub fn failed_report_rate(&self) -> f64 {
        let denominator = self.reviewed_outcomes();
        if denominator == 0 {
            return 0.0;
        }
        self.failed_reports_given as f64 / denominator as f64
    }

    /// Rating fairness: 0-1.0 where 1.0 = gives reasonable ratings.
    /// This is confidence-weighted toward neutral for new requesters, but it
    /// explicitly penalizes punitive floor-only ratings, perfect-score spam,
    /// and bimodal 0/10 vs 10/10 behavior.
    pub fn rating_fairness(&self) -> f64 {
        if self.ratings_given == 0 {
            return 0.5;
        } // neutral for new requesters

        let avg = self.avg_rating_given.clamp(0.0, 10.0);
        let mut raw = if avg < 2.0 {
            0.2
        } else if avg < 3.0 {
            0.4
        } else if avg < 4.0 {
            0.7
        } else if avg > 9.5 {
            0.45
        } else if avg > 9.0 {
            0.75
        } else {
            1.0
        };

        let lowest_share = self.lowest_ratings_given as f64 / self.ratings_given as f64;
        let perfect_share = self.perfect_ratings_given as f64 / self.ratings_given as f64;
        raw -= lowest_share * 0.25;
        raw -= perfect_share * 0.25;
        if lowest_share > 0.2 && perfect_share > 0.2 {
            raw -= 0.35 * ((lowest_share.min(perfect_share) / 0.5).min(1.0));
        }

        let raw = raw.clamp(0.0, 1.0);
        let confidence = self.rating_confidence();
        0.5 + (raw - 0.5) * confidence
    }

    /// Overall requester trustworthiness score (0-100).
    ///
    /// This remains a broad summary metric. Auto-match eligibility also applies
    /// explicit economic-backing, fairness, and cancellation-rate gates so one
    /// dimension cannot hide abusive behavior in another. Failed fulfilled-
    /// outcome reports and dispute escalation are enforced separately so they
    /// do not have to be conflated with rating fairness or broad trust.
    pub fn trust_score(&self) -> f64 {
        let scored_submissions = self.third_party_tasks_submitted();
        if scored_submissions == 0 {
            return 50.0;
        } // neutral for new
        let fulfillment = self.fulfillment_rate() * 35.0;
        let no_cancel = (1.0 - self.cancellation_rate()) * 25.0;
        let fairness = self.rating_fairness() * 20.0;
        let neutral_reserved = 10.0;
        let volume = ((scored_submissions as f64 + 1.0).ln() * 4.0).min(10.0);
        fulfillment + no_cancel + fairness + neutral_reserved + volume
    }

    pub fn actual_spend(&self) -> u64 {
        self.total_settled_spend
    }

    /// Durable requester backing used by the auto-match gate.
    /// This is bond-only; settled spend remains telemetry because counterparties
    /// may be collusive in a permissionless network.
    pub fn economic_backing(&self) -> u64 {
        self.auto_match_bonded_amount
    }

    /// Shortfall to the configured bond-only requester auto-match backing.
    pub fn required_additional_auto_match_backing(
        &self,
        params: &crate::config::MatchingProtocolParams,
    ) -> u64 {
        params
            .requester_min_auto_match_backing
            .saturating_sub(self.economic_backing())
    }

    pub fn auto_match_policy(
        &self,
        params: &crate::config::MatchingProtocolParams,
    ) -> RequesterAutoMatchPolicy {
        let trust_score = self.trust_score();
        let rating_fairness = self.rating_fairness();
        let min_trust = params.requester_min_trust_score.clamp(0.0, 100.0);
        let min_fairness = params.requester_min_rating_fairness.clamp(0.0, 1.0);
        let max_cancellation_rate = params.requester_max_cancellation_rate.clamp(0.0, 1.0);
        let max_dispute_rate = params.requester_max_dispute_rate.clamp(0.0, 1.0);
        let max_failed_report_rate = params.requester_max_failed_report_rate.clamp(0.0, 1.0);
        let min_backing = params.requester_min_auto_match_backing;
        let economic_backing = self.economic_backing();
        let required_additional_backing = min_backing.saturating_sub(economic_backing);
        let scored_submissions = self.third_party_tasks_submitted();
        let cancellation_rate = self.cancellation_rate();
        let dispute_rate = self.dispute_rate();
        let reviewed_outcomes = self.reviewed_outcomes();
        let failed_report_rate = self.failed_report_rate();
        let economic_backing_policy_active = min_backing > 0;
        let blocked_by_economic_backing =
            economic_backing_policy_active && economic_backing < min_backing;
        let trust_policy_active = scored_submissions >= params.requester_min_tasks_for_trust;
        let fairness_policy_active =
            self.ratings_given >= params.requester_min_ratings_for_fairness;
        let cancellation_policy_active = max_cancellation_rate < 1.0
            && scored_submissions >= params.requester_min_tasks_for_trust;
        let dispute_policy_active =
            max_dispute_rate < 1.0 && scored_submissions >= params.requester_min_tasks_for_trust;
        let failed_report_policy_active = max_failed_report_rate < 1.0
            && reviewed_outcomes >= params.requester_min_reviewed_outcomes_for_failed_report_rate;
        let blocked_by_trust = trust_policy_active && trust_score < min_trust;
        let blocked_by_rating_fairness = fairness_policy_active && rating_fairness < min_fairness;
        let blocked_by_cancellation_rate =
            cancellation_policy_active && cancellation_rate > max_cancellation_rate;
        let blocked_by_dispute_rate = dispute_policy_active && dispute_rate > max_dispute_rate;
        let blocked_by_failed_report_rate =
            failed_report_policy_active && failed_report_rate > max_failed_report_rate;

        RequesterAutoMatchPolicy {
            eligible: !blocked_by_economic_backing
                && !blocked_by_trust
                && !blocked_by_rating_fairness
                && !blocked_by_cancellation_rate
                && !blocked_by_dispute_rate
                && !blocked_by_failed_report_rate,
            economic_backing_policy_active,
            trust_policy_active,
            fairness_policy_active,
            cancellation_policy_active,
            dispute_policy_active,
            failed_report_policy_active,
            blocked_by_economic_backing,
            blocked_by_trust,
            blocked_by_rating_fairness,
            blocked_by_cancellation_rate,
            blocked_by_dispute_rate,
            blocked_by_failed_report_rate,
            min_auto_match_backing: min_backing,
            required_additional_backing,
            min_trust_score: min_trust,
            min_tasks_for_trust: params.requester_min_tasks_for_trust,
            min_rating_fairness: min_fairness,
            min_ratings_for_fairness: params.requester_min_ratings_for_fairness,
            max_cancellation_rate,
            min_tasks_for_cancellation_rate: params.requester_min_tasks_for_trust,
            max_dispute_rate,
            min_tasks_for_dispute_rate: params.requester_min_tasks_for_trust,
            max_failed_report_rate,
            min_reviewed_outcomes_for_failed_report_rate: params
                .requester_min_reviewed_outcomes_for_failed_report_rate,
        }
    }

    pub fn read_view(
        &self,
        params: &crate::config::MatchingProtocolParams,
    ) -> RequesterReputationView {
        RequesterReputationView {
            trust_score: self.trust_score(),
            tasks_submitted: self.tasks_submitted,
            third_party_tasks_submitted: self.third_party_tasks_submitted(),
            same_entity_submission_units_neutralized: self.same_entity_submission_units_neutralized,
            tasks_fulfilled: self.tasks_fulfilled,
            tasks_cancelled: self.tasks_cancelled,
            matched_agent_timeouts: self.matched_agent_timeouts,
            fulfillment_rate: self.fulfillment_rate(),
            cancellation_rate: self.cancellation_rate(),
            ratings_given: self.ratings_given,
            failed_reports_given: self.failed_reports_given,
            reviewed_outcomes: self.reviewed_outcomes(),
            failed_report_rate: self.failed_report_rate(),
            avg_rating_given: self.avg_rating_given,
            rating_fairness: self.rating_fairness(),
            lowest_ratings_given: self.lowest_ratings_given,
            perfect_ratings_given: self.perfect_ratings_given,
            total_spent: self.actual_spend(),
            total_escrowed: self.total_escrowed,
            auto_match_bonded_amount: self.auto_match_bonded_amount,
            economic_backing: self.economic_backing(),
            disputes_initiated: self.task_disputes_initiated,
            agreement_disputes_initiated: self.agreement_disputes_initiated,
            dispute_rate: self.dispute_rate(),
            last_active: self.last_active,
            storage_deposit: self.storage_deposit,
            auto_match_policy: self.auto_match_policy(params),
        }
    }

    /// Whether this requester is eligible for automatic capability routing under
    /// the current chain-wide requester-reputation enforcement policy.
    pub fn allows_auto_match(&self, params: &crate::config::MatchingProtocolParams) -> bool {
        self.auto_match_policy(params).eligible
    }

    pub fn record_submission(&mut self, escrowed_fee: u64, timestamp: u64) {
        self.tasks_submitted = self.tasks_submitted.saturating_add(1);
        self.total_escrowed = self.total_escrowed.saturating_add(escrowed_fee);
        self.last_active = timestamp;
    }

    pub fn record_decomposition(&mut self, subtask_count: u64, timestamp: u64) {
        self.tasks_submitted = self
            .tasks_submitted
            .saturating_add(subtask_count.saturating_sub(1));
        self.last_active = timestamp;
    }

    pub fn record_fulfillment(&mut self, settled_spend: u64, timestamp: u64) {
        self.tasks_fulfilled = self.tasks_fulfilled.saturating_add(1);
        self.total_settled_spend = self.total_settled_spend.saturating_add(settled_spend);
        self.last_active = timestamp;
    }

    pub fn record_cancellation(&mut self, timestamp: u64) {
        self.tasks_cancelled = self.tasks_cancelled.saturating_add(1);
        self.last_active = timestamp;
    }

    pub fn record_matched_agent_timeout(&mut self, timestamp: u64) {
        self.matched_agent_timeouts = self.matched_agent_timeouts.saturating_add(1);
        self.last_active = timestamp;
    }

    pub fn record_auto_match_bond(&mut self, amount: u64, timestamp: u64) {
        self.auto_match_bonded_amount = self.auto_match_bonded_amount.saturating_add(amount);
        self.last_active = timestamp;
    }

    pub fn record_rating_given(&mut self, quality: f64, timestamp: u64) {
        self.ratings_given = self.ratings_given.saturating_add(1);
        // Running average
        let q = quality.clamp(0.0, 10.0);
        if q <= 1.0 {
            self.lowest_ratings_given = self.lowest_ratings_given.saturating_add(1);
        }
        if q >= 10.0 {
            self.perfect_ratings_given = self.perfect_ratings_given.saturating_add(1);
        }
        self.avg_rating_given = if self.ratings_given == 1 {
            q
        } else {
            (self.avg_rating_given * (self.ratings_given - 1) as f64 + q)
                / self.ratings_given as f64
        };
        self.last_active = timestamp;
    }

    pub fn record_failed_report(&mut self, timestamp: u64) {
        self.failed_reports_given = self.failed_reports_given.saturating_add(1);
        self.last_active = timestamp;
    }

    pub fn record_same_entity_submission_neutralization(&mut self, timestamp: u64) {
        let remaining = self
            .tasks_submitted
            .saturating_sub(self.same_entity_submission_units_neutralized);
        if remaining > 0 {
            self.same_entity_submission_units_neutralized = self
                .same_entity_submission_units_neutralized
                .saturating_add(1);
        }
        self.last_active = timestamp;
    }

    pub fn record_dispute(&mut self, timestamp: u64) {
        self.task_disputes_initiated = self.task_disputes_initiated.saturating_add(1);
        self.last_active = timestamp;
    }

    pub fn record_agreement_dispute(&mut self, timestamp: u64) {
        self.agreement_disputes_initiated = self.agreement_disputes_initiated.saturating_add(1);
        self.last_active = timestamp;
    }
}

/// On-chain identity for an AI agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// The agent's on-chain address.
    pub address: Address,
    /// Human-readable name.
    pub name: String,
    /// Natural-language description of what this agent does.
    /// Used for Layer 2 semantic matching against task descriptions.
    pub description: String,
    /// Verified 128-dim embedding of the description, computed by validators
    /// from the agent's text fields using the deterministic feature hasher.
    /// This is the base semantic signal used in matching — cannot be gamed.
    pub description_embedding: Vec<f32>,
    /// Optional neural embedding supplied by the client (e.g., MiniLM 384-dim).
    /// Used as an additive bonus in matching ONLY when the task also has a
    /// neural embedding of the same dimensionality. Not verified by validators.
    #[serde(default)]
    pub neural_embedding: Vec<f32>,
    /// SHA-256 hash of the model weights or configuration.
    pub model_hash: Hash256,
    /// Declared capabilities.
    pub capabilities: Vec<Capability>,
    /// Address of the entity that deployed this agent.
    pub owner: Address,
    /// Amount of ZIN staked (in micro-ZIN).
    pub stake: u64,
    /// Reputation data.
    pub reputation: ReputationData,
    /// Registration block number.
    pub registered_at_block: u64,
    /// Registration timestamp (ms).
    pub registered_at: u64,
    /// Whether the agent is currently active.
    pub active: bool,
    /// Timestamp (ms) when the agent was explicitly deregistered/refunded.
    /// Zero means the record is still only active or paused.
    #[serde(default)]
    pub deregistered_at: u64,
    /// Arbitrary metadata (JSON-encoded).
    pub metadata: Vec<u8>,
    /// Recent feedback entries from requesters (ring buffer, max 50).
    /// Explicit layer: readable by other agents and requesters.
    #[serde(default)]
    pub feedback: Vec<FeedbackEntry>,
    /// Aggregated feedback embedding — blended from all feedback text.
    /// Implicit layer: mixed into matching to refine the agent's semantic
    /// profile based on what reviewers say about them.
    #[serde(default)]
    pub feedback_embedding: Vec<f32>,
    /// Recent reputation events cached on the agent profile (ring buffer, max 100).
    /// The canonical full audit log lives in the state-level append-only index
    /// that backs `/v1/agents/:address/reputation-history`.
    #[serde(default)]
    pub reputation_history: Vec<ReputationEvent>,
    /// Minimum fee (micro-ZIN) this agent will accept for any task.
    /// Tasks with max_fee below this are filtered out during matching.
    /// Set to 0 to accept any fee (default).
    #[serde(default)]
    pub min_fee: u64,
    /// Per-capability fee schedule (micro-ZIN).
    /// Agents can declare different rates for different capabilities.
    /// e.g., {"ai.text.generation": 50_000_000, "ai.code.execution": 100_000_000}
    /// Used by the fee estimation API and surfaced in agent profiles.
    #[serde(default)]
    pub fee_schedule: Vec<(String, u64)>,
    /// Storage deposit locked for this agent entry (micro-ZIN).
    /// Refunded to owner when agent is deregistered.
    #[serde(default)]
    pub storage_deposit: u64,
}

impl AgentIdentity {
    /// Create a new agent identity (before on-chain registration).
    pub fn new(
        address: Address,
        name: String,
        description: String,
        description_embedding: Vec<f32>,
        model_hash: Hash256,
        capabilities: Vec<Capability>,
        owner: Address,
    ) -> Self {
        Self {
            address,
            name,
            description,
            description_embedding,
            neural_embedding: vec![],
            model_hash,
            capabilities,
            owner,
            stake: 0,
            reputation: ReputationData::default(),
            registered_at_block: 0,
            registered_at: 0,
            active: true,
            deregistered_at: 0,
            metadata: vec![],
            feedback: vec![],
            feedback_embedding: vec![],
            reputation_history: vec![],
            min_fee: 0,
            fee_schedule: vec![],
            storage_deposit: 0,
        }
    }

    /// Add a feedback entry and update the aggregate feedback embedding.
    ///
    /// The feedback ring buffer is capped at MAX_FEEDBACK_ENTRIES.
    /// The aggregate embedding is a value-weighted average of all feedback
    /// embeddings — high-value task feedback counts more.
    pub fn add_feedback(&mut self, entry: FeedbackEntry) {
        // Ring buffer: drop oldest if full
        if self.feedback.len() >= MAX_FEEDBACK_ENTRIES {
            self.feedback.remove(0);
        }

        // Update aggregate feedback embedding (exponential moving average).
        // Higher-value task feedback has more influence on the embedding.
        if !entry.embedding.is_empty() {
            let weight = (entry.task_fee as f64 / 1_000_000.0).clamp(0.1, 10.0);
            let dim = entry.embedding.len();

            if self.feedback_embedding.is_empty() {
                // First feedback: just copy the embedding directly
                self.feedback_embedding = entry.embedding.clone();
            } else if self.feedback_embedding.len() == dim {
                // Exponential moving average with value-weighted alpha.
                // Higher-value tasks shift the embedding more.
                let alpha = (weight / (weight + 5.0)) as f32;
                for (i, val) in self.feedback_embedding.iter_mut().enumerate() {
                    *val = *val * (1.0 - alpha) + entry.embedding[i] * alpha;
                }
            }
        }

        self.feedback.push(entry);
    }

    /// Record a reputation event in the agent's recent profile cache.
    ///
    /// Ring buffer capped at MAX_REPUTATION_EVENTS — oldest entries are
    /// dropped when full. The canonical full audit log is stored separately
    /// in the state manager's append-only reputation-event index.
    pub fn add_reputation_event(&mut self, event: ReputationEvent) {
        if self.reputation_history.len() >= MAX_REPUTATION_EVENTS {
            self.reputation_history.remove(0);
        }
        self.reputation_history.push(event);
    }

    /// Effective embedding for matching: blend of description + feedback.
    ///
    /// The agent's declared description embedding is blended with the
    /// aggregate feedback embedding. As feedback accumulates, the agent's
    /// effective matching profile shifts toward what reviewers say about
    /// them rather than just what they claim about themselves.
    ///
    /// Blend weight is derived from explicit chain-level matching parameters.
    pub fn effective_embedding(&self, params: &crate::config::MatchingProtocolParams) -> Vec<f32> {
        if self.feedback_embedding.is_empty() || self.description_embedding.is_empty() {
            return self.description_embedding.clone();
        }
        if self.feedback_embedding.len() != self.description_embedding.len() {
            return self.description_embedding.clone();
        }

        // More feedback entries = more weight on feedback embedding
        let feedback_count = self.feedback.len() as f64;
        let saturation_count = params.feedback_blend_saturation_count.max(1) as f64;
        let feedback_weight =
            (feedback_count / saturation_count).min(params.feedback_blend_max_weight);
        let desc_weight = 1.0 - feedback_weight;

        self.description_embedding
            .iter()
            .zip(self.feedback_embedding.iter())
            .map(|(&d, &f)| d * desc_weight as f32 + f * feedback_weight as f32)
            .collect()
    }

    /// Maximum usable reputation currently backed by locked agent stake.
    pub fn reputation_score_cap(&self, params: &crate::config::MatchingProtocolParams) -> f64 {
        let stake_per_point = params.agent_stake_per_reputation_point;
        if stake_per_point == 0 {
            return 100.0;
        }
        (self.stake as f64 / stake_per_point as f64).clamp(0.0, 100.0)
    }

    /// Current raw score after applying the stake-backed reputation cap.
    pub fn backed_reputation_score(&self, params: &crate::config::MatchingProtocolParams) -> f64 {
        self.reputation.score.min(self.reputation_score_cap(params))
    }

    /// Usable reputation after both time decay and stake-backed capping.
    pub fn effective_reputation_score(
        &self,
        current_time_ms: u64,
        params: &crate::config::MatchingProtocolParams,
    ) -> f64 {
        self.reputation
            .effective_score(current_time_ms)
            .min(self.reputation_score_cap(params))
    }

    /// Enforce the stake-backed cap on the stored raw score.
    pub fn clamp_reputation_to_backing(&mut self, params: &crate::config::MatchingProtocolParams) {
        let cap = self.reputation_score_cap(params);
        if self.reputation.score > cap {
            self.reputation.score = cap;
        }
    }

    pub fn read_view(
        &self,
        current_time_ms: u64,
        params: &crate::config::MatchingProtocolParams,
    ) -> AgentPublicView {
        self.read_view_with_reputation_history_total(
            current_time_ms,
            params,
            self.reputation_history.len() as u64,
        )
    }

    pub fn read_view_with_reputation_history_total(
        &self,
        current_time_ms: u64,
        params: &crate::config::MatchingProtocolParams,
        reputation_history_total: u64,
    ) -> AgentPublicView {
        let total_disputes = self
            .reputation
            .disputes_won
            .saturating_add(self.reputation.disputes_lost);
        let dispute_loss_ratio = if total_disputes > 0 {
            Some(self.reputation.disputes_lost as f64 / total_disputes as f64)
        } else {
            None
        };
        let dispute_penalty = dispute_loss_ratio
            .map(|loss_ratio| loss_ratio * 5.0 * (self.reputation.disputes_lost as f64).min(10.0));

        AgentPublicView {
            address: self.address.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
            description_embedding: self.description_embedding.clone(),
            neural_embedding: self.neural_embedding.clone(),
            model_hash: self.model_hash,
            capabilities: self.capabilities.clone(),
            owner: self.owner.clone(),
            stake: self.stake,
            reputation: AgentReputationView {
                stored_score: self.reputation.score,
                stake_backed_score_cap: self.reputation_score_cap(params),
                backed_score: self.backed_reputation_score(params),
                effective_score: self.effective_reputation_score(current_time_ms, params),
                tasks_completed: self.reputation.tasks_completed,
                tasks_failed: self.reputation.tasks_failed,
                cumulative_quality: self.reputation.cumulative_quality,
                disputes_won: self.reputation.disputes_won,
                disputes_lost: self.reputation.disputes_lost,
                last_updated: self.reputation.last_updated,
                total_value_completed: self.reputation.total_value_completed,
                value_weighted_quality: self.reputation.value_weighted_quality,
                ratings_received: self.reputation.ratings_received,
                total_value_rated: self.reputation.total_value_rated,
                avg_quality: self.reputation.avg_quality(),
                weighted_avg_quality: self.reputation.weighted_avg_quality(),
                reliability: self.reputation.reliability(),
                days_inactive: self.reputation.days_inactive(current_time_ms),
                dispute_loss_ratio,
                dispute_penalty,
            },
            registered_at_block: self.registered_at_block,
            registered_at: self.registered_at,
            active: self.active,
            deregistered_at: self.deregistered_at,
            metadata: self.metadata.clone(),
            feedback: self.feedback.clone(),
            feedback_embedding: self.feedback_embedding.clone(),
            recent_reputation_events: self.reputation_history.clone(),
            reputation_history_total,
            min_fee: self.min_fee,
            fee_schedule: self.fee_schedule.clone(),
            storage_deposit: self.storage_deposit,
        }
    }

    /// Check if agent has a specific capability.
    pub fn has_capability(&self, cap: &Capability) -> bool {
        self.capabilities.contains(cap)
    }

    /// Check if agent has all specified capabilities.
    pub fn has_all_capabilities(&self, caps: &[Capability]) -> bool {
        caps.iter().all(|c| self.has_capability(c))
    }

    /// Base matching score from reputation and stake (without semantic component).
    /// Used when no embedding is available for comparison.
    pub fn base_score(&self) -> f64 {
        let mut score = self.reputation.score * 0.6
            + self.reputation.reliability() * 100.0 * 0.3
            + (self.stake as f64 / 1_000_000.0).min(100.0) * 0.1;

        let total_disputes = self.reputation.disputes_won + self.reputation.disputes_lost;
        if total_disputes > 0 {
            let loss_ratio = self.reputation.disputes_lost as f64 / total_disputes as f64;
            score -= loss_ratio * 5.0 * (self.reputation.disputes_lost as f64).min(10.0);
        }

        score.max(0.0)
    }

    fn quoted_price_score(quoted_fee: u64, fee_budget: u64) -> f64 {
        if fee_budget > 0 {
            let fee_ratio = (quoted_fee as f64 / fee_budget as f64).min(1.0);
            (1.0 - fee_ratio) * 100.0
        } else {
            50.0
        }
    }

    fn eligible_for_discovery_boost(
        &self,
        current_block: u64,
        params: &crate::config::MatchingProtocolParams,
    ) -> bool {
        let blocks_since_registration = current_block.saturating_sub(self.registered_at_block);
        blocks_since_registration >= params.discovery_min_age_blocks
            && self.stake >= params.discovery_min_stake
    }

    fn matching_score_core(
        &self,
        semantic_similarity: f64,
        prefs: &crate::primitives::task::MatchPreferences,
        price_score: f64,
        now_ms: u64,
        current_block: u64,
        params: &crate::config::MatchingProtocolParams,
    ) -> f64 {
        let (ws, wr, wp, wf, wk) = prefs.weights();

        let semantic = semantic_similarity.clamp(0.0, 1.0) * 100.0;
        let reputation = self.effective_reputation_score(now_ms, params).min(100.0);
        let resolved_tasks = self.reputation.resolved_task_count();

        // Freshness: less-exposed agents score higher, but with diminishing
        // returns. Failed tasks count too — an agent should not stay "new"
        // forever just because their work keeps failing.
        // Uses sqrt curve so the boost tapers off quickly:
        //   0 resolved tasks → 100, 4 → 80, 25 → 50, 100+ → 0
        let freshness = (1.0 - (resolved_tasks as f64 / 100.0).min(1.0).sqrt()) * 100.0;

        // Stake: skin in the game, capped at 100
        let stake = (self.stake as f64 / 1_000_000.0).min(100.0);

        let mut score =
            semantic * ws + reputation * wr + price_score * wp + freshness * wf + stake * wk;

        if prefs.discovery_threshold > 0
            && resolved_tasks < prefs.discovery_threshold as u64
            && self.eligible_for_discovery_boost(current_block, params)
        {
            score += prefs.discovery_boost as f64;
        }

        let total_disputes = self.reputation.disputes_won + self.reputation.disputes_lost;
        if total_disputes > 0 {
            let loss_ratio = self.reputation.disputes_lost as f64 / total_disputes as f64;
            let penalty = loss_ratio * 5.0 * (self.reputation.disputes_lost as f64).min(10.0);
            score -= penalty;
        }

        score.max(0.0)
    }

    /// Full matching score using the deterministic quote chosen for a task.
    ///
    /// Price competitiveness is derived from the agent's current quoted fee
    /// relative to the requester's effective budget instead of historical
    /// realized earnings. This keeps preview, live matching, and settlement
    /// aligned on the same pricing inputs. Callers must pass the verified
    /// chain matching parameters explicitly.
    pub fn matching_score(
        &self,
        semantic_similarity: f64,
        prefs: &crate::primitives::task::MatchPreferences,
        quoted_fee: u64,
        fee_budget: u64,
        now_ms: u64,
        current_block: u64,
        params: &crate::config::MatchingProtocolParams,
    ) -> f64 {
        self.matching_score_core(
            semantic_similarity,
            prefs,
            Self::quoted_price_score(quoted_fee, fee_budget),
            now_ms,
            current_block,
            params,
        )
    }
}

/// Data payload for an AgentRegister transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRegisterData {
    pub name: String,
    /// Natural-language description of the agent's capabilities and specialization.
    pub description: String,
    /// Optional client-provided neural embedding (e.g. MiniLM).
    /// The verified base embedding is always computed on-chain from text.
    #[serde(default)]
    pub neural_embedding: Option<Vec<f32>>,
    pub model_hash: Hash256,
    pub capabilities: Vec<Capability>,
    pub metadata: Vec<u8>,
    /// Minimum fee the agent will accept (micro-ZIN). 0 = accept any.
    #[serde(default)]
    pub min_fee: u64,
    /// Per-capability fee schedule: [(capability_string, fee_micro_zin)].
    #[serde(default)]
    pub fee_schedule: Vec<(String, u64)>,
}

impl AgentRegisterData {
    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// Data payload for an AgentUpdate transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentUpdateData {
    pub name: Option<String>,
    pub description: Option<String>,
    /// Optional replacement neural embedding. Use `Some(vec![])` to clear it.
    #[serde(default)]
    pub neural_embedding: Option<Vec<f32>>,
    pub model_hash: Option<Hash256>,
    pub capabilities: Option<Vec<Capability>>,
    pub metadata: Option<Vec<u8>>,
    pub active: Option<bool>,
    #[serde(default)]
    pub min_fee: Option<u64>,
    #[serde(default)]
    pub fee_schedule: Option<Vec<(String, u64)>>,
}

impl AgentUpdateData {
    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// Data payload for a ReputationUpdate transaction.
/// Only valid if the sender is the requester for the referenced fulfilled task.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationUpdateData {
    /// The task that was fulfilled.
    pub task_id: Hash256,
    /// Quality score (0.0 - 10.0).
    pub quality_score: f64,
    /// Whether the requester accepted the fulfilled outcome.
    /// `false` means the protocol still considers the task delivered and
    /// settled, but the requester judged the result unacceptable.
    pub requester_accepted: bool,
    /// Qualitative text feedback (optional, max 500 chars).
    /// Stored on-chain and used for:
    ///   - Explicit: visible in agent profiles and tool reviews
    ///   - Implicit: embedding blended into agent's matching profile
    #[serde(default)]
    pub feedback: String,
}

impl ReputationUpdateData {
    pub fn validate(&self) -> std::result::Result<(), String> {
        if !self.quality_score.is_finite() {
            return Err(format!(
                "quality_score must be finite, got {}",
                self.quality_score
            ));
        }
        if !(0.0..=10.0).contains(&self.quality_score) {
            return Err(format!(
                "quality_score must be within [0.0, 10.0], got {}",
                self.quality_score
            ));
        }
        Ok(())
    }
}

/// A single feedback entry stored on an agent's profile.
/// Capped at MAX_FEEDBACK_ENTRIES per agent (ring buffer).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackEntry {
    /// Who wrote this feedback.
    pub reviewer: Address,
    /// The task this feedback is for.
    pub task_id: Hash256,
    /// Numeric quality score (0.0-10.0).
    pub quality: f64,
    /// Whether the requester accepted the fulfilled outcome.
    pub requester_accepted: bool,
    /// Qualitative text feedback.
    pub text: String,
    /// Pre-computed embedding of the feedback text.
    pub embedding: Vec<f32>,
    /// When the feedback was submitted (ms since epoch).
    pub timestamp: u64,
    /// Value of the task (micro-ZIN) — for weighting.
    pub task_fee: u64,
}

/// Maximum feedback entries stored per agent (ring buffer — oldest dropped).
pub const MAX_FEEDBACK_ENTRIES: usize = 50;

/// Maximum recent reputation events cached on an agent profile.
pub const MAX_REPUTATION_EVENTS: usize = 100;

/// Categories of events that affect an agent's reputation score.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReputationEventType {
    /// Task fulfilled successfully after final settlement.
    TaskCompleted,
    /// Requester rated the agent's work quality (record_rating via ReputationUpdate tx).
    QualityRating,
    /// System-detected delivery failure (expiry/timeout), not a requester rating.
    TaskFailed,
    /// Agreement milestone or full delivery completed (record_completion via AgreementExecute tx).
    AgreementCompleted,
    /// Agent won a dispute (disputes_won incremented via AgreementResolve tx).
    DisputeWon,
    /// Agent lost a dispute (disputes_lost incremented via AgreementResolve tx).
    DisputeLost,
    /// Active agreement expired without delivery (record_failure via background task).
    AgreementExpired,
}

/// A single auditable reputation event.
///
/// Stored in the canonical append-only agent reputation log and mirrored into
/// each agent profile's recent-event cache. Each event captures the score
/// before and after, making it possible to reconstruct the reputation
/// trajectory from the full-history index.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReputationEvent {
    /// What kind of reputation change occurred.
    pub event_type: ReputationEventType,
    /// Reference to the triggering task or agreement.
    pub reference_id: Hash256,
    /// The other party involved (requester, proposer, arbitrator, etc.).
    pub counterparty: Address,
    /// Agent's reputation score before this event.
    pub score_before: f64,
    /// Agent's reputation score after this event.
    pub score_after: f64,
    /// The ZIN value involved (task fee, escrow amount, etc.).
    pub value: u64,
    /// Quality score as submitted by the requester, if this was a rating event.
    #[serde(default)]
    pub submitted_quality: Option<f64>,
    /// Quality score that actually affected reputation math, if this was a
    /// rating event. For `requester_accepted=false`, this is `0.0` even when the
    /// requester submitted a higher score.
    #[serde(default)]
    pub effective_quality: Option<f64>,
    /// Whether the requester accepted the fulfilled outcome, if this was a
    /// rating event.
    #[serde(default)]
    pub requester_accepted: Option<bool>,
    /// When this event occurred (ms since epoch).
    pub timestamp: u64,
    /// Locked collateral backing this retained reputation event and its
    /// mirrored recent-cache footprint on the agent profile.
    #[serde(default)]
    pub storage_deposit: u64,
}

impl ReputationEvent {
    pub fn score_change(
        event_type: ReputationEventType,
        reference_id: Hash256,
        counterparty: Address,
        score_before: f64,
        score_after: f64,
        value: u64,
        timestamp: u64,
    ) -> Self {
        Self {
            event_type,
            reference_id,
            counterparty,
            score_before,
            score_after,
            value,
            submitted_quality: None,
            effective_quality: None,
            requester_accepted: None,
            timestamp,
            storage_deposit: 0,
        }
    }

    pub fn quality_rating(
        reference_id: Hash256,
        counterparty: Address,
        score_before: f64,
        score_after: f64,
        value: u64,
        submitted_quality: f64,
        effective_quality: f64,
        requester_accepted: bool,
        timestamp: u64,
    ) -> Self {
        Self {
            event_type: ReputationEventType::QualityRating,
            reference_id,
            counterparty,
            score_before,
            score_after,
            value,
            submitted_quality: Some(submitted_quality),
            effective_quality: Some(effective_quality),
            requester_accepted: Some(requester_accepted),
            timestamp,
            storage_deposit: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Capability;

    #[test]
    fn test_capability_deserialize_normalizes_case() {
        let encoded = bincode::serialize(&Capability("AI.TEXT.GENERATION".to_string())).unwrap();
        let decoded: Capability = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded, Capability::new("ai.text.generation"));
    }
}
