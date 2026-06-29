use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MatchingProtocolParams {
    #[serde(default = "default_feedback_blend_saturation_count")]
    pub feedback_blend_saturation_count: u32,
    #[serde(default = "default_feedback_blend_max_weight")]
    pub feedback_blend_max_weight: f64,
    #[serde(default = "default_neural_bonus_weight")]
    pub neural_bonus_weight: f64,
    #[serde(default = "default_discovery_min_age_blocks")]
    pub discovery_min_age_blocks: u64,
    #[serde(default = "default_discovery_min_stake")]
    pub discovery_min_stake: u64,
    #[serde(default = "default_max_match_tools_per_agent")]
    pub max_match_tools_per_agent: u16,
    #[serde(default = "default_requester_min_trust_score")]
    pub requester_min_trust_score: f64,
    #[serde(default = "default_requester_max_cancellation_rate")]
    pub requester_max_cancellation_rate: f64,
    #[serde(default = "default_requester_max_dispute_rate")]
    pub requester_max_dispute_rate: f64,
    #[serde(default = "default_requester_max_failed_report_rate")]
    pub requester_max_failed_report_rate: f64,
    #[serde(default = "default_requester_min_auto_match_backing")]
    pub requester_min_auto_match_backing: u64,
    #[serde(default = "default_requester_min_tasks_for_trust")]
    pub requester_min_tasks_for_trust: u64,
    #[serde(default = "default_requester_min_rating_fairness")]
    pub requester_min_rating_fairness: f64,
    #[serde(default = "default_requester_min_ratings_for_fairness")]
    pub requester_min_ratings_for_fairness: u64,
    #[serde(default = "default_requester_min_reviewed_outcomes_for_failed_report_rate")]
    pub requester_min_reviewed_outcomes_for_failed_report_rate: u64,
    #[serde(default = "default_agent_stake_per_reputation_point")]
    pub agent_stake_per_reputation_point: u64,
}

impl Default for MatchingProtocolParams {
    fn default() -> Self {
        Self {
            feedback_blend_saturation_count: default_feedback_blend_saturation_count(),
            feedback_blend_max_weight: default_feedback_blend_max_weight(),
            neural_bonus_weight: default_neural_bonus_weight(),
            discovery_min_age_blocks: default_discovery_min_age_blocks(),
            discovery_min_stake: default_discovery_min_stake(),
            max_match_tools_per_agent: default_max_match_tools_per_agent(),
            requester_min_trust_score: default_requester_min_trust_score(),
            requester_max_cancellation_rate: default_requester_max_cancellation_rate(),
            requester_max_dispute_rate: default_requester_max_dispute_rate(),
            requester_max_failed_report_rate: default_requester_max_failed_report_rate(),
            requester_min_auto_match_backing: default_requester_min_auto_match_backing(),
            requester_min_tasks_for_trust: default_requester_min_tasks_for_trust(),
            requester_min_rating_fairness: default_requester_min_rating_fairness(),
            requester_min_ratings_for_fairness: default_requester_min_ratings_for_fairness(),
            requester_min_reviewed_outcomes_for_failed_report_rate:
                default_requester_min_reviewed_outcomes_for_failed_report_rate(),
            agent_stake_per_reputation_point: default_agent_stake_per_reputation_point(),
        }
    }
}

fn default_feedback_blend_saturation_count() -> u32 {
    20
}
fn default_feedback_blend_max_weight() -> f64 {
    0.3
}
fn default_neural_bonus_weight() -> f64 {
    0.3
}
fn default_discovery_min_age_blocks() -> u64 {
    100
}
fn default_discovery_min_stake() -> u64 {
    1_000_000
}
fn default_max_match_tools_per_agent() -> u16 {
    16
}
fn default_requester_min_trust_score() -> f64 {
    35.0
}
fn default_requester_max_cancellation_rate() -> f64 {
    0.5
}
fn default_requester_max_dispute_rate() -> f64 {
    0.5
}
fn default_requester_max_failed_report_rate() -> f64 {
    0.5
}
fn default_requester_min_auto_match_backing() -> u64 {
    5_000_000
}
fn default_requester_min_tasks_for_trust() -> u64 {
    4
}
fn default_requester_min_rating_fairness() -> f64 {
    0.5
}
fn default_requester_min_ratings_for_fairness() -> u64 {
    4
}
fn default_requester_min_reviewed_outcomes_for_failed_report_rate() -> u64 {
    4
}
fn default_agent_stake_per_reputation_point() -> u64 {
    100_000
}
