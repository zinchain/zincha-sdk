use serde::{Deserialize, Serialize};

use super::agent::Capability;
use crate::crypto::{Address, Hash256};

fn default_tool_sla_ms() -> u64 {
    3_600_000
} // 1 hour
fn default_tool_challenge_window_ms() -> u64 {
    900_000
} // 15 minutes
fn default_tool_max_result_metadata_bytes() -> u32 {
    4_096
}
fn default_tool_match_enabled() -> bool {
    true
}
fn default_subscription_period_ms() -> u64 {
    30 * 24 * 3_600_000
} // 30 days
fn default_subscription_auto_renew() -> bool {
    true
}

/// Settlement semantics for HTTP-backed tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpToolSettlementMode {
    /// Payment settles immediately at invocation time and the invoker receives
    /// an access token proving prepaid access.
    PrepaidAccess,
    /// Payment remains escrowed in a ToolJob until the provider submits a
    /// result and the requester accepts, the challenge window expires, or a
    /// dispute is resolved.
    ResultEscrowed,
    /// Payment remains reserved in a ToolUsageSession until the provider
    /// reports the metered units consumed. The requester then accepts, the
    /// challenge window expires, or a dispute is resolved.
    ///
    /// In this mode, `ToolEntry.price_per_call` is interpreted as the
    /// per-unit rate, and `ToolInvokeData.max_metered_units` is required.
    MeteredUsage,
    /// Payment remains escrowed in a ToolJob, but the provider may unlock the
    /// total price in sequential milestone tranches instead of one final
    /// result. Each milestone is accepted, auto-settled, or disputed
    /// independently. A failed milestone refunds the current and remaining
    /// unpaid milestone amounts to the requester.
    MilestoneEscrowed,
}

impl Default for HttpToolSettlementMode {
    fn default() -> Self {
        Self::PrepaidAccess
    }
}

/// Canonical execution route for a tool invocation.
///
/// `contract://` and `contractref://` tools always route through the
/// chain-observed contract execution path regardless of the stored HTTP
/// settlement_mode field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolInvokeRoute {
    ContractBacked,
    HttpPrepaidAccess,
    HttpResultEscrowed,
    HttpMeteredUsage,
    HttpMilestoneEscrowed,
}

/// Parsed contract-backed endpoint target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractEndpointTarget<'a> {
    Address {
        contract_address: Address,
        function: &'a str,
    },
    Route {
        deployer: Address,
        route_name: &'a str,
        function: &'a str,
    },
}

/// Arbitration policy for escrowed HTTP tool jobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolArbitrationPolicy {
    /// Use the protocol arbitrator selection logic at job-open time.
    Protocol,
}

impl Default for ToolArbitrationPolicy {
    fn default() -> Self {
        Self::Protocol
    }
}

/// Reputation data for a tool.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolReputation {
    /// Total paid invocations / access grants recorded on-chain.
    pub total_calls: u64,
    /// Successful verified outcomes.
    ///
    /// For contract-backed tools, this is the chain-observed execution result.
    /// HTTP tool invokes do not update this counter because the chain does not
    /// observe whether the off-chain service actually succeeded.
    pub successful_calls: u64,
    /// Failed verified outcomes.
    ///
    /// For contract-backed tools, this is the chain-observed execution result.
    /// HTTP tool invokes do not update this counter because the chain does not
    /// observe whether the off-chain service actually succeeded.
    pub failed_calls: u64,
    /// Cumulative quality score from ratings.
    pub cumulative_quality: f64,
    /// Number of quality ratings received (from ReputationUpdate).
    /// This is the correct denominator for avg_quality — NOT successful_calls,
    /// because not every invocation results in a rating.
    #[serde(default)]
    pub quality_ratings: u64,
    /// Total prepaid revenue earned in micro-ZIN.
    pub total_revenue: u64,
}

impl ToolReputation {
    /// Number of chain-verified outcome samples.
    pub fn verified_calls(&self) -> u64 {
        self.successful_calls.saturating_add(self.failed_calls)
    }

    /// Exact verified success rate (0.0 - 1.0), if the chain has any
    /// verified outcome samples for this tool.
    pub fn verified_success_rate(&self) -> Option<f64> {
        let verified_calls = self.verified_calls();
        if verified_calls == 0 {
            return None;
        }
        Some(self.successful_calls as f64 / verified_calls as f64)
    }

    /// Conservative verified reliability estimate (0.0 - 1.0).
    ///
    /// Uses a neutral Beta(1,1) prior so tools with no verified outcomes are
    /// treated as unknown (0.5) rather than perfect (1.0).
    pub fn success_rate(&self) -> f64 {
        (self.successful_calls as f64 + 1.0) / (self.verified_calls() as f64 + 2.0)
    }

    /// Average quality score (0.0 - 10.0).
    pub fn avg_quality(&self) -> f64 {
        if self.quality_ratings == 0 {
            return 0.0;
        }
        self.cumulative_quality / self.quality_ratings as f64
    }

    /// Record a granted invocation / access event without changing revenue.
    pub fn record_access_grant(&mut self) {
        self.total_calls = self.total_calls.saturating_add(1);
    }

    /// Record a prepaid tool access grant.
    pub fn record_paid_access(&mut self, revenue: u64) {
        self.record_access_grant();
        self.total_revenue = self.total_revenue.saturating_add(revenue);
    }

    /// Record subscription revenue that is not tied to a single invocation.
    pub fn record_subscription_revenue(&mut self, revenue: u64) {
        self.total_revenue = self.total_revenue.saturating_add(revenue);
    }

    /// Record settlement revenue that should not also increment total_calls.
    pub fn record_settlement_revenue(&mut self, revenue: u64) {
        self.total_revenue = self.total_revenue.saturating_add(revenue);
    }

    /// Record a verified outcome observed by the chain.
    pub fn record_verified_outcome(&mut self, success: bool) {
        if success {
            self.successful_calls = self.successful_calls.saturating_add(1);
        } else {
            self.failed_calls = self.failed_calls.saturating_add(1);
        }
    }
}

/// A registered tool on the Zincha network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolEntry {
    /// Unique tool identifier: hash(owner_address + ":" + name).
    pub tool_id: Hash256,
    /// Address of the agent that owns/provides this tool.
    pub owner: Address,
    /// Human-readable name.
    pub name: String,
    /// Description of what the tool does.
    pub description: String,
    /// API endpoint URL.
    pub endpoint: String,
    /// Price in micro-ZIN.
    ///
    /// For `PrepaidAccess`, `ResultEscrowed`, and `contract://` tools this is
    /// the flat per-invocation price. For `MeteredUsage`, this is the
    /// per-unit rate.
    pub price_per_call: u64,
    /// HTTP settlement semantics. `contract://` tools always use the chain's
    /// native deferred settlement path regardless of this field.
    #[serde(default)]
    pub settlement_mode: HttpToolSettlementMode,
    /// Maximum time the provider has to submit a result for escrowed HTTP jobs.
    #[serde(default = "default_tool_sla_ms")]
    pub sla_ms: u64,
    /// How long the requester can challenge a submitted result before it
    /// auto-settles to the provider.
    #[serde(default = "default_tool_challenge_window_ms")]
    pub challenge_window_ms: u64,
    /// Maximum size of `ToolResultSubmit.result_metadata`, in bytes.
    #[serde(default = "default_tool_max_result_metadata_bytes")]
    pub max_result_metadata_bytes: u32,
    /// Arbitration policy for disputed escrowed HTTP jobs.
    #[serde(default)]
    pub arbitration_policy: ToolArbitrationPolicy,
    /// Capabilities this tool provides (same namespace as agent capabilities).
    pub capabilities: Vec<Capability>,
    /// Whether this tool participates in automatic capability routing.
    ///
    /// Direct invocation still works when this is false; the flag only controls
    /// whether matching may use the tool to augment an agent's capabilities.
    #[serde(default = "default_tool_match_enabled")]
    pub match_enabled: bool,
    /// Semantic embedding of the description (128-dim, validator-computed).
    pub description_embedding: Vec<f32>,
    /// Optional neural embedding from client (e.g., MiniLM). Additive bonus in tool discovery.
    #[serde(default)]
    pub neural_embedding: Vec<f32>,
    /// Whether the tool is currently active and accepting calls.
    pub active: bool,
    /// Timestamp (ms) when the tool was explicitly deregistered/refunded.
    /// Zero means the record is still only active or paused.
    #[serde(default)]
    pub deregistered_at: u64,
    /// Version string (e.g. "1.0.0").
    pub version: String,
    /// Block at which the tool was registered.
    pub registered_at_block: u64,
    /// Reputation and usage statistics.
    pub reputation: ToolReputation,
    /// Storage deposit locked for this tool entry (micro-ZIN).
    /// Refunded to owner when tool is deregistered.
    #[serde(default)]
    pub storage_deposit: u64,
}

impl ToolEntry {
    pub fn is_contract_endpoint(endpoint: &str) -> bool {
        endpoint.starts_with("contract://")
            || endpoint.starts_with(crate::primitives::contract::CONTRACT_ROUTE_SCHEME)
    }

    pub fn is_contract_tool(&self) -> bool {
        Self::is_contract_endpoint(&self.endpoint)
    }

    /// Parse a `contract://<addr>/<fn>` endpoint into its target address
    /// and canonical function/export name.
    pub fn contract_target_for_endpoint(endpoint: &str) -> Option<(Address, &str)> {
        let path = endpoint.strip_prefix("contract://")?;
        let (addr_str, rest) = path.split_once('/')?;
        if rest.contains('?') {
            return None;
        }
        let function = rest;
        if function.is_empty() {
            return None;
        }
        Some((Address::from_hex(addr_str).ok()?, function))
    }

    /// Parse a `contractref://<deployer>/<route>/<fn>` endpoint into its route
    /// owner, canonical route name, and function/export name.
    pub fn contract_route_for_endpoint(endpoint: &str) -> Option<(Address, &str, &str)> {
        let path = endpoint.strip_prefix(crate::primitives::contract::CONTRACT_ROUTE_SCHEME)?;
        let mut parts = path.splitn(3, '/');
        let deployer = Address::from_hex(parts.next()?).ok()?;
        let route_name = parts.next()?;
        let function = parts.next()?;
        if route_name.is_empty() || function.is_empty() || function.contains('?') {
            return None;
        }
        crate::primitives::contract::validate_and_normalize_contract_route_name(route_name)
            .ok()
            .filter(|normalized| normalized == route_name)?;
        Some((deployer, route_name, function))
    }

    pub fn contract_endpoint_target(endpoint: &str) -> Option<ContractEndpointTarget<'_>> {
        if let Some((contract_address, function)) = Self::contract_target_for_endpoint(endpoint) {
            return Some(ContractEndpointTarget::Address {
                contract_address,
                function,
            });
        }
        if let Some((deployer, route_name, function)) = Self::contract_route_for_endpoint(endpoint)
        {
            return Some(ContractEndpointTarget::Route {
                deployer,
                route_name,
                function,
            });
        }
        None
    }

    pub fn validate_contract_endpoint(endpoint: &str) -> std::result::Result<(), String> {
        if !Self::is_contract_endpoint(endpoint) {
            return Ok(());
        }
        if endpoint.contains('?') {
            return Err(
                "contract-backed endpoints do not support query parameters or version selectors; use a new immutable contract address or a contractref://<deployer>/<route>/<function> alias instead"
                    .into(),
            );
        }
        match Self::contract_endpoint_target(endpoint) {
            Some(_) => {}
            None if endpoint.starts_with("contract://") => {
                return Err(
                    "Invalid contract:// endpoint; expected contract://<address>/<function>"
                        .to_string(),
                )
            }
            None => {
                return Err(
                    "Invalid contractref:// endpoint; expected contractref://<deployer>/<route>/<function>"
                        .to_string(),
                )
            }
        }
        Ok(())
    }

    /// Parse the target contract address from a `contract://<addr>/<fn>` endpoint.
    pub fn contract_target_address_for_endpoint(endpoint: &str) -> Option<Address> {
        Self::contract_target_for_endpoint(endpoint).map(|(address, _)| address)
    }

    /// Determine the canonical execution route for this tool.
    pub fn invoke_route_for(
        endpoint: &str,
        settlement_mode: HttpToolSettlementMode,
    ) -> ToolInvokeRoute {
        if Self::is_contract_endpoint(endpoint) {
            ToolInvokeRoute::ContractBacked
        } else {
            match settlement_mode {
                HttpToolSettlementMode::PrepaidAccess => ToolInvokeRoute::HttpPrepaidAccess,
                HttpToolSettlementMode::ResultEscrowed => ToolInvokeRoute::HttpResultEscrowed,
                HttpToolSettlementMode::MeteredUsage => ToolInvokeRoute::HttpMeteredUsage,
                HttpToolSettlementMode::MilestoneEscrowed => ToolInvokeRoute::HttpMilestoneEscrowed,
            }
        }
    }

    /// Whether this route can back subscription plans and invoke-time coverage.
    pub fn supports_subscriptions_for(
        endpoint: &str,
        settlement_mode: HttpToolSettlementMode,
    ) -> bool {
        matches!(
            Self::invoke_route_for(endpoint, settlement_mode),
            ToolInvokeRoute::HttpPrepaidAccess
                | ToolInvokeRoute::HttpResultEscrowed
                | ToolInvokeRoute::ContractBacked
        )
    }

    /// Determine the canonical execution route for this tool.
    pub fn invoke_route(&self) -> ToolInvokeRoute {
        Self::invoke_route_for(&self.endpoint, self.settlement_mode)
    }

    /// Whether this tool can back subscription plans and invoke-time coverage.
    pub fn supports_subscriptions(&self) -> bool {
        Self::supports_subscriptions_for(&self.endpoint, self.settlement_mode)
    }

    /// Whether `host_tool_invoke` can safely execute this tool inline.
    ///
    /// Contracts can only materialize prepaid HTTP access tokens directly.
    /// Deferred-settlement routes must go through the normal transaction
    /// handler so the chain can create the appropriate state machine objects.
    pub fn supports_contract_host_invoke(&self) -> bool {
        self.invoke_route() == ToolInvokeRoute::HttpPrepaidAccess
    }

    /// Parse the target contract address from a `contract://<addr>/<fn>` tool endpoint.
    pub fn contract_target_address(&self) -> Option<Address> {
        Self::contract_target_address_for_endpoint(&self.endpoint)
    }

    /// Economic recipient for subscription-period revenue.
    ///
    /// HTTP tools pay the owning agent directly. `contract://` tools pay the
    /// contract address so recurring subscription funds land in the same place
    /// as invoke-time overage payments.
    pub fn subscription_payment_recipient(&self) -> Option<Address> {
        if self.is_contract_tool() {
            self.contract_target_address()
        } else {
            Some(self.owner.clone())
        }
    }

    /// Check if the tool provides a specific capability.
    pub fn has_capability(&self, cap: &Capability) -> bool {
        self.capabilities.contains(cap)
    }

    /// Check if the tool provides all specified capabilities.
    pub fn has_all_capabilities(&self, caps: &[Capability]) -> bool {
        caps.iter().all(|c| self.has_capability(c))
    }

    /// Composite quality score for discovery ranking (default weights).
    pub fn discovery_score(&self) -> f64 {
        self.ranked_score(&ToolSearchPreferences::default())
    }

    /// Score this tool using caller-specified preferences.
    pub fn ranked_score(&self, prefs: &ToolSearchPreferences) -> f64 {
        let total = (prefs.w_reliability
            + prefs.w_price
            + prefs.w_quality
            + prefs.w_popularity
            + prefs.w_freshness)
            .max(1) as f64;

        let wr = prefs.w_reliability as f64 / total;
        let wp = prefs.w_price as f64 / total;
        let wq = prefs.w_quality as f64 / total;
        let wpo = prefs.w_popularity as f64 / total;
        let wf = prefs.w_freshness as f64 / total;

        // Reliability: conservative verified reliability estimate (0-100)
        let reliability = self.reputation.success_rate() * 100.0;

        // Price: inverse of price_per_call (cheaper = higher score).
        // Normalize: 0 ZIN → 100, 10 ZIN → 0
        let price_score = (1.0 - (self.price_per_call as f64 / 10_000_000.0).min(1.0)) * 100.0;

        // Quality: average quality rating (0-10 → 0-100)
        let quality = self.reputation.avg_quality() * 10.0;

        // Popularity: log scale of total calls (more calls = more trusted)
        let popularity = ((self.reputation.total_calls as f64 + 1.0).ln() * 15.0).min(100.0);

        // Freshness: new tools with few calls get a boost
        let freshness = if self.reputation.total_calls < prefs.discovery_threshold as u64 {
            100.0
        } else {
            (1.0 - (self.reputation.total_calls as f64 / 1000.0).min(1.0)) * 100.0
        };

        let mut score =
            reliability * wr + price_score * wp + quality * wq + popularity * wpo + freshness * wf;

        // Discovery boost for new tools
        if prefs.discovery_threshold > 0
            && self.reputation.total_calls < prefs.discovery_threshold as u64
        {
            score += prefs.discovery_boost as f64;
        }

        score
    }
}

/// Overage handling once a subscription exhausts its included allowances.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionOveragePolicy {
    /// Reject new invocations once included allowances are exhausted.
    Deny,
    /// Fall back to the tool's normal per-invocation price for uncovered usage.
    PayAsYouGo,
}

impl Default for SubscriptionOveragePolicy {
    fn default() -> Self {
        Self::Deny
    }
}

/// Lifecycle state for a subscriber's recurring entitlement to a tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolSubscriptionStatus {
    /// Subscription is usable in the current period and may auto-renew.
    Active,
    /// Renewals are temporarily blocked by provider/tool/plan inactivity.
    Paused,
    /// Current period ended and reserve funding was insufficient for renewal.
    PastDue,
    /// Auto-renew is disabled, but the already-paid current period is still active.
    CancelRequested,
    /// Subscription is fully terminated and no longer grants entitlements.
    Cancelled,
}

impl Default for ToolSubscriptionStatus {
    fn default() -> Self {
        Self::Active
    }
}

/// Provider-defined recurring billing plan for a tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolSubscriptionPlan {
    /// Unique plan identifier (creation tx hash).
    pub plan_id: Hash256,
    pub tool_id: Hash256,
    pub provider: Address,
    pub name: String,
    /// Flat recurring price paid at the start of each period.
    pub price_per_period: u64,
    /// Billing period length in milliseconds.
    #[serde(default = "default_subscription_period_ms")]
    pub period_ms: u64,
    /// Number of full-price invocations included per period.
    #[serde(default)]
    pub included_calls: u32,
    /// Additional per-period micro-ZIN credit applied to per-invocation prices.
    #[serde(default)]
    pub included_credits: u64,
    /// Behavior after included calls / credits are exhausted.
    #[serde(default)]
    pub overage_policy: SubscriptionOveragePolicy,
    pub active: bool,
    pub created_at: u64,
    pub created_at_block: u64,
    pub updated_at: u64,
    #[serde(default)]
    pub storage_deposit: u64,
}

/// Subscriber-specific recurring entitlement state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolSubscription {
    /// Canonical subscription slot identifier for a `(subscriber, tool_id)` pair.
    ///
    /// The slot may be reused across later restart cycles after a terminal
    /// cancellation so repeated start/cancel churn does not grow state
    /// unboundedly.
    pub subscription_id: Hash256,
    pub plan_id: Hash256,
    pub tool_id: Hash256,
    pub subscriber: Address,
    pub provider: Address,
    /// Frozen commercial terms copied from the selected plan at start time.
    pub price_per_period: u64,
    pub period_ms: u64,
    pub included_calls: u32,
    pub included_credits: u64,
    pub overage_policy: SubscriptionOveragePolicy,
    /// Current paid period bounds.
    pub current_period_start: u64,
    pub current_period_end: u64,
    pub next_renewal_at: u64,
    /// Remaining entitlements inside the current paid period.
    pub remaining_calls: u32,
    pub remaining_credits: u64,
    /// Restored entitlements from failed deferred-settlement invokes.
    ///
    /// These are consumed before the current period's normal allowances so
    /// failed jobs do not permanently burn subscription value even if the
    /// failure is discovered in a later billing period.
    #[serde(default)]
    pub compensating_calls: u32,
    #[serde(default)]
    pub compensating_credits: u64,
    /// Subscriber-funded reserve used for future renewals only.
    pub reserved_balance: u64,
    pub status: ToolSubscriptionStatus,
    #[serde(default = "default_subscription_auto_renew")]
    pub auto_renew: bool,
    pub created_at: u64,
    pub created_at_block: u64,
    #[serde(default)]
    pub storage_deposit: u64,
    #[serde(default)]
    pub cancelled_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SubscriptionCoverage {
    pub covered_amount: u64,
    pub uncovered_amount: u64,
    pub used_call: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SubscriptionAdvanceOutcome {
    pub renewed_periods: u32,
    pub provider_credit: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SubscriptionTerminalShutdownOutcome {
    pub reserve_refund: u64,
    pub compensation_refund: u64,
}

impl ToolSubscription {
    /// Start a fresh billing period from the selected plan.
    ///
    /// When reusing a cancelled slot, previously restored compensating value
    /// carries forward so failed deferred-settlement invokes do not lose their
    /// refund semantics.
    pub fn start_or_restart_from_plan(
        reusable: Option<&ToolSubscription>,
        subscription_id: Hash256,
        plan: &ToolSubscriptionPlan,
        subscriber: Address,
        now_ms: u64,
        current_block: u64,
        reserve_amount: u64,
        auto_renew: bool,
        additional_storage_deposit: u64,
    ) -> Self {
        let (compensating_calls, compensating_credits, existing_storage_deposit) = reusable
            .map(|subscription| {
                (
                    subscription.compensating_calls,
                    subscription.compensating_credits,
                    subscription.storage_deposit,
                )
            })
            .unwrap_or((0, 0, 0));

        Self {
            subscription_id,
            plan_id: plan.plan_id,
            tool_id: plan.tool_id,
            subscriber,
            provider: plan.provider.clone(),
            price_per_period: plan.price_per_period,
            period_ms: plan.period_ms,
            included_calls: plan.included_calls,
            included_credits: plan.included_credits,
            overage_policy: plan.overage_policy,
            current_period_start: now_ms,
            current_period_end: now_ms.saturating_add(plan.period_ms),
            next_renewal_at: now_ms.saturating_add(plan.period_ms),
            remaining_calls: plan.included_calls,
            remaining_credits: plan.included_credits,
            compensating_calls,
            compensating_credits,
            reserved_balance: reserve_amount,
            status: ToolSubscriptionStatus::Active,
            auto_renew,
            created_at: now_ms,
            created_at_block: current_block,
            storage_deposit: existing_storage_deposit.saturating_add(additional_storage_deposit),
            cancelled_at: None,
        }
    }

    /// Whether reserve funding can still be added without stranding it.
    pub fn can_accept_reserve_top_up(&self) -> bool {
        matches!(
            self.status,
            ToolSubscriptionStatus::Active
                | ToolSubscriptionStatus::Paused
                | ToolSubscriptionStatus::PastDue
        )
    }

    /// Whether the current period still grants invoke-time benefits.
    pub fn is_usable_at(&self, now_ms: u64) -> bool {
        now_ms < self.current_period_end
            && matches!(
                self.status,
                ToolSubscriptionStatus::Active | ToolSubscriptionStatus::CancelRequested
            )
    }

    /// Whether the subscription still carries restored deferred-settlement value.
    pub fn has_compensating_entitlement(&self) -> bool {
        self.compensating_calls > 0 || self.compensating_credits > 0
    }

    /// Monetary value carried by restored deferred-settlement entitlement.
    ///
    /// Included-call compensation is valued at the tool's current listed price,
    /// matching invoke-time semantics where each restored call covers the full
    /// current invocation amount.
    pub fn compensating_refund_value(&self, compensating_call_value: u64) -> u64 {
        self.compensating_credits
            .saturating_add(compensating_call_value.saturating_mul(self.compensating_calls as u64))
    }

    /// Whether this subscription still depends on a subscription-compatible tool route.
    pub fn requires_subscription_compatible_tool(&self) -> bool {
        self.status != ToolSubscriptionStatus::Cancelled
            || self.reserved_balance > 0
            || self.has_compensating_entitlement()
    }

    /// Whether this subscription can satisfy invoke-time coverage right now.
    ///
    /// Compensating entitlement remains usable after the paid billing period
    /// ends or after cancellation, because it represents value restored from a
    /// failed deferred-settlement invoke rather than current-period allowance.
    /// Paused subscriptions stay blocked until service availability is restored
    /// via the normal resume flow.
    pub fn is_invoke_usable_at(&self, now_ms: u64) -> bool {
        self.is_usable_at(now_ms)
            || (self.has_compensating_entitlement()
                && self.status != ToolSubscriptionStatus::Paused)
    }

    /// Consume current-period allowances against a single invocation price.
    pub fn consume_allowance(&mut self, tool_price: u64) -> SubscriptionCoverage {
        if self.compensating_calls > 0 {
            self.compensating_calls -= 1;
            return SubscriptionCoverage {
                covered_amount: tool_price,
                uncovered_amount: 0,
                used_call: true,
            };
        }

        if self.remaining_calls > 0 {
            self.remaining_calls -= 1;
            return SubscriptionCoverage {
                covered_amount: tool_price,
                uncovered_amount: 0,
                used_call: true,
            };
        }

        let covered_from_compensation = self.compensating_credits.min(tool_price);
        self.compensating_credits = self
            .compensating_credits
            .saturating_sub(covered_from_compensation);

        let uncovered_after_compensation = tool_price.saturating_sub(covered_from_compensation);
        let covered_from_period = self.remaining_credits.min(uncovered_after_compensation);
        self.remaining_credits = self.remaining_credits.saturating_sub(covered_from_period);
        let covered_amount = covered_from_compensation.saturating_add(covered_from_period);
        SubscriptionCoverage {
            covered_amount,
            uncovered_amount: tool_price.saturating_sub(covered_amount),
            used_call: false,
        }
    }

    /// Restore consumed allowance after a deferred-settlement invoke fails.
    ///
    /// Restored value goes into compensating buckets instead of the current
    /// period counters so a late refund does not inflate or mutate the period's
    /// base allowance accounting.
    pub fn restore_allowance_as_compensation(&mut self, covered_amount: u64, used_call: bool) {
        if used_call {
            self.compensating_calls = self.compensating_calls.saturating_add(1);
        } else if covered_amount > 0 {
            self.compensating_credits = self.compensating_credits.saturating_add(covered_amount);
        }
    }

    /// Terminally shut down a subscription because service can never return.
    ///
    /// This is stricter than a normal cancellation: it immediately disables
    /// future renewals, releases any subscriber-funded reserve, and cashes out
    /// restored deferred-settlement value so the record can purge cleanly.
    pub fn terminate_for_unrecoverable_service_loss(
        &mut self,
        now_ms: u64,
        compensating_call_value: u64,
    ) -> SubscriptionTerminalShutdownOutcome {
        let outcome = SubscriptionTerminalShutdownOutcome {
            reserve_refund: self.reserved_balance,
            compensation_refund: self.compensating_refund_value(compensating_call_value),
        };

        self.reserved_balance = 0;
        self.compensating_calls = 0;
        self.compensating_credits = 0;
        self.auto_renew = false;
        self.status = ToolSubscriptionStatus::Cancelled;
        if self.cancelled_at.is_none() {
            self.cancelled_at = Some(now_ms);
        }

        outcome
    }

    /// Advance billing periods deterministically using the subscription's reserve.
    ///
    /// Returns the amount that should be credited to the provider for completed
    /// renewals. Callers are responsible for applying that credit to balances.
    pub fn advance_periods(
        &mut self,
        now_ms: u64,
        service_available: bool,
    ) -> SubscriptionAdvanceOutcome {
        let mut outcome = SubscriptionAdvanceOutcome::default();

        if self.status == ToolSubscriptionStatus::CancelRequested
            && now_ms >= self.current_period_end
        {
            self.status = ToolSubscriptionStatus::Cancelled;
            return outcome;
        }

        if now_ms < self.current_period_end {
            return outcome;
        }

        if !self.auto_renew
            || matches!(
                self.status,
                ToolSubscriptionStatus::CancelRequested | ToolSubscriptionStatus::Cancelled
            )
        {
            self.status = ToolSubscriptionStatus::Cancelled;
            return outcome;
        }

        if !service_available {
            self.status = ToolSubscriptionStatus::Paused;
            return outcome;
        }

        if self.status == ToolSubscriptionStatus::Paused {
            // Paused subscriptions suspend the billing clock while service is
            // unavailable. Once service returns, renewal resumes from "now"
            // instead of back-billing the downtime window.
            self.current_period_start = now_ms;
            self.current_period_end = now_ms;
            self.next_renewal_at = now_ms;
        }

        let periods_due = now_ms
            .saturating_sub(self.current_period_end)
            .checked_div(self.period_ms)
            .unwrap_or(0)
            .saturating_add(1);

        let affordable_periods = if self.price_per_period == 0 {
            periods_due
        } else {
            periods_due.min(self.reserved_balance / self.price_per_period)
        };

        if affordable_periods == 0 {
            self.status = ToolSubscriptionStatus::PastDue;
            self.remaining_calls = 0;
            self.remaining_credits = 0;
            return outcome;
        }

        if self.price_per_period > 0 {
            let total_cost = self.price_per_period.saturating_mul(affordable_periods);
            self.reserved_balance = self.reserved_balance.saturating_sub(total_cost);
            outcome.provider_credit = total_cost;
        }

        let previous_period_end = self.current_period_end;
        let advanced_ms = self.period_ms.saturating_mul(affordable_periods);
        self.current_period_end = previous_period_end.saturating_add(advanced_ms);
        self.current_period_start = self.current_period_end.saturating_sub(self.period_ms);
        self.next_renewal_at = self.current_period_end;
        outcome.renewed_periods = affordable_periods.min(u32::MAX as u64) as u32;

        if affordable_periods < periods_due {
            self.status = ToolSubscriptionStatus::PastDue;
            self.remaining_calls = 0;
            self.remaining_credits = 0;
        } else {
            self.remaining_calls = self.included_calls;
            self.remaining_credits = self.included_credits;
            self.status = ToolSubscriptionStatus::Active;
        }

        outcome
    }
}

/// Preferences for tool discovery ranking.
///
/// Controls how tools are ranked when searching by capability.
/// All weights are relative — they're normalized to sum to 1.0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSearchPreferences {
    /// Weight for reliability (success rate). Range: 0-100.
    pub w_reliability: u8,
    /// Weight for price competitiveness (lower = better). Range: 0-100.
    pub w_price: u8,
    /// Weight for quality rating. Range: 0-100.
    pub w_quality: u8,
    /// Weight for popularity (total invocations). Range: 0-100.
    pub w_popularity: u8,
    /// Weight for freshness (boosts newer tools). Range: 0-100.
    pub w_freshness: u8,
    /// Maximum price in micro-ZIN (0 = no limit).
    pub max_price: u64,
    /// Minimum exact verified success rate (0.0 - 1.0, 0 = accept all).
    /// If this is set above 0, tools with no verified outcomes are excluded.
    pub min_success_rate: f64,
    /// Tools with fewer than this many calls get a discovery boost.
    pub discovery_threshold: u32,
    /// Bonus score for tools below the discovery threshold.
    pub discovery_boost: u8,
}

impl Default for ToolSearchPreferences {
    fn default() -> Self {
        ToolSearchPreferences {
            w_reliability: 35,
            w_price: 25,
            w_quality: 20,
            w_popularity: 10,
            w_freshness: 10,
            max_price: 0,
            min_success_rate: 0.0,
            discovery_threshold: 10,
            discovery_boost: 10,
        }
    }
}

impl ToolSearchPreferences {
    /// Preset: cheapest tools first.
    pub fn cheapest() -> Self {
        ToolSearchPreferences {
            w_price: 60,
            w_reliability: 20,
            w_quality: 10,
            w_popularity: 5,
            w_freshness: 5,
            ..Default::default()
        }
    }

    /// Preset: most reliable tools first.
    pub fn most_reliable() -> Self {
        ToolSearchPreferences {
            w_reliability: 50,
            w_quality: 25,
            w_price: 10,
            w_popularity: 10,
            w_freshness: 5,
            min_success_rate: 0.8,
            ..Default::default()
        }
    }

    /// Preset: discover new tools.
    pub fn discover_new() -> Self {
        ToolSearchPreferences {
            w_freshness: 40,
            w_price: 25,
            w_reliability: 15,
            w_quality: 10,
            w_popularity: 10,
            discovery_boost: 20,
            discovery_threshold: 20,
            ..Default::default()
        }
    }

    /// Preset: most popular (battle-tested).
    pub fn most_popular() -> Self {
        ToolSearchPreferences {
            w_popularity: 40,
            w_reliability: 30,
            w_quality: 15,
            w_price: 10,
            w_freshness: 5,
            ..Default::default()
        }
    }
}

/// Data payload for ToolRegister transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRegisterData {
    pub name: String,
    pub description: String,
    pub endpoint: String,
    pub price_per_call: u64,
    /// HTTP settlement semantics for this tool.
    #[serde(default)]
    pub settlement_mode: HttpToolSettlementMode,
    /// SLA for provider result submission in escrowed mode.
    #[serde(default = "default_tool_sla_ms")]
    pub sla_ms: u64,
    /// Challenge window after a result is submitted in escrowed mode.
    #[serde(default = "default_tool_challenge_window_ms")]
    pub challenge_window_ms: u64,
    /// Maximum size of result metadata that providers may submit.
    #[serde(default = "default_tool_max_result_metadata_bytes")]
    pub max_result_metadata_bytes: u32,
    /// Arbitration policy for escrowed result disputes.
    #[serde(default)]
    pub arbitration_policy: ToolArbitrationPolicy,
    /// Capabilities this tool provides.
    pub capabilities: Vec<Capability>,
    /// Whether this tool participates in automatic capability routing.
    #[serde(default = "default_tool_match_enabled")]
    pub match_enabled: bool,
    /// Optional client-provided neural embedding (e.g. MiniLM).
    /// The verified base embedding is always computed on-chain from text.
    #[serde(default)]
    pub neural_embedding: Option<Vec<f32>>,
    /// Version string.
    pub version: String,
}

/// Create a recurring subscription plan for a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSubscriptionPlanCreateData {
    pub tool_id: Hash256,
    pub name: String,
    pub price_per_period: u64,
    #[serde(default = "default_subscription_period_ms")]
    pub period_ms: u64,
    #[serde(default)]
    pub included_calls: u32,
    #[serde(default)]
    pub included_credits: u64,
    #[serde(default)]
    pub overage_policy: SubscriptionOveragePolicy,
}

/// Update a tool subscription plan. Existing subscriptions keep their frozen terms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSubscriptionPlanUpdateData {
    pub plan_id: Hash256,
    pub name: Option<String>,
    pub price_per_period: Option<u64>,
    pub period_ms: Option<u64>,
    pub included_calls: Option<u32>,
    pub included_credits: Option<u64>,
    pub overage_policy: Option<SubscriptionOveragePolicy>,
    pub active: Option<bool>,
}

/// Start a recurring tool subscription for a subscriber.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSubscriptionStartData {
    pub plan_id: Hash256,
    /// Additional reserve funding locked for future renewals.
    #[serde(default)]
    pub reserve_amount: u64,
    #[serde(default = "default_subscription_auto_renew")]
    pub auto_renew: bool,
}

/// Add reserve funding to an existing subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSubscriptionTopUpData {
    pub subscription_id: Hash256,
    pub amount: u64,
}

/// Stop future renewals and refund any unused reserve.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSubscriptionCancelData {
    pub subscription_id: Hash256,
}

/// Re-enable renewals for a cancelled / paused / past-due subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSubscriptionResumeData {
    pub subscription_id: Hash256,
    /// Additional reserve funding locked while resuming.
    ///
    /// When the subscription's paid period has already lapsed, resume starts a
    /// fresh period from the current block time and may require new funding.
    #[serde(default)]
    pub reserve_amount: u64,
}

impl ToolSubscriptionResumeData {
    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// Force an immediate renewal attempt using the existing reserve.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSubscriptionRenewData {
    pub subscription_id: Hash256,
}

impl ToolRegisterData {
    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// Data payload for ToolInvoke transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInvokeData {
    /// Hash identifying the tool to invoke.
    pub tool_id: Hash256,
    /// Serialized input parameters for the tool call.
    pub input_data: Vec<u8>,
    /// Maximum billable units the requester authorizes for a metered session.
    ///
    /// Required only when the tool uses `MeteredUsage`. Ignored for other
    /// settlement modes.
    #[serde(default)]
    pub max_metered_units: Option<u64>,
    /// Maximum gas budget for contract-backed tool execution.
    ///
    /// Ignored for HTTP-backed tools. Builders must still serialize an
    /// explicit canonical value so the ToolInvoke wire format stays single-shape.
    pub gas_limit: u64,
    /// Sequential milestone plan for `MilestoneEscrowed` jobs.
    ///
    /// Amounts must sum to the tool's listed `price_per_call`. Ignored for all
    /// other settlement modes.
    #[serde(default)]
    pub milestones: Vec<ToolMilestoneDef>,
}

pub const DEFAULT_CONTRACT_TOOL_GAS_LIMIT: u64 = 400_000;

pub fn validate_contract_tool_gas_limit(gas_limit: u64) -> std::result::Result<u64, String> {
    if gas_limit == 0 {
        return Err("Contract-backed ToolInvoke gas_limit must be > 0".to_string());
    }
    if gas_limit > crate::primitives::contract::MAX_CONTRACT_GAS {
        return Err(format!(
            "Contract-backed ToolInvoke gas_limit {} exceeds max {}",
            gas_limit,
            crate::primitives::contract::MAX_CONTRACT_GAS
        ));
    }
    Ok(gas_limit)
}

impl ToolInvokeData {
    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// Data payload for ToolUpdate transactions.
/// Only the tool's owner can update it. All fields are optional —
/// only provided fields are changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolUpdateData {
    /// The tool to update (required).
    pub tool_id: Hash256,
    /// New description.
    pub description: Option<String>,
    /// New endpoint URL.
    pub endpoint: Option<String>,
    /// New price per call in micro-ZIN.
    pub price_per_call: Option<u64>,
    /// New HTTP settlement mode.
    #[serde(default)]
    pub settlement_mode: Option<HttpToolSettlementMode>,
    /// New provider SLA in escrowed mode.
    #[serde(default)]
    pub sla_ms: Option<u64>,
    /// New challenge window in escrowed mode.
    #[serde(default)]
    pub challenge_window_ms: Option<u64>,
    /// New maximum result metadata size.
    #[serde(default)]
    pub max_result_metadata_bytes: Option<u32>,
    /// New arbitration policy.
    #[serde(default)]
    pub arbitration_policy: Option<ToolArbitrationPolicy>,
    /// New capabilities list.
    pub capabilities: Option<Vec<Capability>>,
    /// Enable or disable automatic capability routing for this tool.
    #[serde(default)]
    pub match_enabled: Option<bool>,
    /// Optional replacement neural embedding. Use `Some(vec![])` to clear it.
    #[serde(default)]
    pub neural_embedding: Option<Vec<f32>>,
    /// New version string.
    pub version: Option<String>,
    /// Set active/inactive.
    pub active: Option<bool>,
}

impl ToolUpdateData {
    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// On-chain lifecycle for an escrowed HTTP tool invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolJobStatus {
    Open,
    Submitted,
    Disputed,
}

/// Client-supplied milestone plan for a milestone-escrowed tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolMilestoneDef {
    pub label: String,
    pub amount: u64,
}

/// Status of an individual milestone inside a milestone-escrowed tool job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolMilestoneStatus {
    Pending,
    Submitted,
    Disputed,
    Completed,
}

/// On-chain state for one milestone inside a milestone-escrowed tool job.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolMilestone {
    pub label: String,
    pub amount: u64,
    pub status: ToolMilestoneStatus,
    #[serde(default)]
    pub submit_deadline: Option<u64>,
    #[serde(default)]
    pub result_hash: Option<Hash256>,
    #[serde(default)]
    pub result_metadata: Vec<u8>,
    #[serde(default)]
    pub submitted_at: Option<u64>,
    #[serde(default)]
    pub challenge_deadline: Option<u64>,
    #[serde(default)]
    pub dispute_reason: Option<String>,
    #[serde(default)]
    pub disputed_at: Option<u64>,
}

impl From<ToolMilestoneDef> for ToolMilestone {
    fn from(value: ToolMilestoneDef) -> Self {
        Self {
            label: value.label,
            amount: value.amount,
            status: ToolMilestoneStatus::Pending,
            submit_deadline: None,
            result_hash: None,
            result_metadata: vec![],
            submitted_at: None,
            challenge_deadline: None,
            dispute_reason: None,
            disputed_at: None,
        }
    }
}

/// Escrowed HTTP tool job opened by `ToolInvoke`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolJob {
    /// Unique identifier for the job. For now this is the ToolInvoke tx hash.
    pub job_id: Hash256,
    pub tool_id: Hash256,
    pub requester: Address,
    pub provider: Address,
    /// Protocol-selected arbitrator. Required only once a dispute occurs.
    pub arbitrator: Option<Address>,
    /// Price locked in escrow for this invocation.
    pub amount_escrowed: u64,
    /// Locked storage deposit collateralizing this durable job row.
    #[serde(default)]
    pub storage_deposit: u64,
    /// Frozen provider SLA used for the current / next milestone window.
    #[serde(default = "default_tool_sla_ms")]
    pub sla_ms: u64,
    /// Subscription whose current-period allowance covered part or all of this
    /// invoke. Present only for deferred-settlement subscription-backed jobs.
    #[serde(default)]
    pub subscription_id: Option<Hash256>,
    /// Value covered by the subscription at invoke time.
    #[serde(default)]
    pub subscription_covered_amount: u64,
    /// Whether the subscription coverage came from an included-call grant.
    #[serde(default)]
    pub subscription_used_call: bool,
    /// Original invocation payload needed by the off-chain provider.
    pub input_data: Vec<u8>,
    /// Hash of `input_data` for quick integrity checks in clients.
    pub input_hash: Hash256,
    /// Current job status.
    pub status: ToolJobStatus,
    /// Timestamp when the job was opened.
    pub opened_at: u64,
    /// Block height when the job was opened.
    pub opened_at_block: u64,
    /// Frozen requester challenge window for this job.
    pub challenge_window_ms: u64,
    /// Frozen maximum result metadata size for this job.
    pub max_result_metadata_bytes: u32,
    /// Frozen arbitrator fee schedule selected at job-open time.
    #[serde(default)]
    pub arbitrator_fee_bps: u16,
    /// Deadline for provider result submission.
    pub submit_deadline: u64,
    /// Result hash submitted by the provider, if any.
    #[serde(default)]
    pub result_hash: Option<Hash256>,
    /// Opaque off-chain result metadata/pointer supplied by the provider.
    #[serde(default)]
    pub result_metadata: Vec<u8>,
    /// Timestamp when the provider submitted a result.
    #[serde(default)]
    pub submitted_at: Option<u64>,
    /// Deadline after submission when the result auto-settles to the provider.
    #[serde(default)]
    pub challenge_deadline: Option<u64>,
    /// Requester dispute reason, if the job is disputed.
    #[serde(default)]
    pub dispute_reason: Option<String>,
    /// Timestamp of the current dispute, if any.
    #[serde(default)]
    pub disputed_at: Option<u64>,
    /// Deadline for the currently assigned arbitrator to resolve the dispute.
    #[serde(default)]
    pub arbitration_deadline_at: Option<u64>,
    /// Number of timeout-driven arbitrator reassignments already applied.
    #[serde(default)]
    pub arbitration_reassignments: u8,
    /// Prior arbitrators that timed out on this dispute.
    #[serde(default)]
    pub prior_arbitrators: Vec<Address>,
    /// Optional sequential milestone plan. Empty for one-shot escrowed jobs.
    #[serde(default)]
    pub milestones: Vec<ToolMilestone>,
}

impl ToolJob {
    pub fn is_milestone_job(&self) -> bool {
        !self.milestones.is_empty()
    }

    pub fn current_milestone_index(&self) -> Option<usize> {
        self.milestones
            .iter()
            .position(|milestone| milestone.status != ToolMilestoneStatus::Completed)
    }

    pub fn current_milestone(&self) -> Option<&ToolMilestone> {
        self.current_milestone_index()
            .and_then(|idx| self.milestones.get(idx))
    }

    pub fn current_milestone_mut(&mut self) -> Option<(usize, &mut ToolMilestone)> {
        let idx = self.current_milestone_index()?;
        let milestone = self.milestones.get_mut(idx)?;
        Some((idx, milestone))
    }

    pub fn completed_milestone_amount(&self) -> u64 {
        self.milestones
            .iter()
            .filter(|milestone| milestone.status == ToolMilestoneStatus::Completed)
            .map(|milestone| milestone.amount)
            .sum()
    }

    pub fn unpaid_amount_from(&self, start_idx: usize) -> u64 {
        self.milestones
            .iter()
            .skip(start_idx)
            .filter(|milestone| milestone.status != ToolMilestoneStatus::Completed)
            .map(|milestone| milestone.amount)
            .sum()
    }

    pub fn clear_transient_result_state(&mut self) {
        self.result_hash = None;
        self.result_metadata.clear();
        self.submitted_at = None;
        self.challenge_deadline = None;
        self.dispute_reason = None;
        self.disputed_at = None;
        self.arbitration_deadline_at = None;
        self.arbitration_reassignments = 0;
        self.prior_arbitrators.clear();
    }

    pub fn open_current_milestone(&mut self, now_ms: u64) {
        let deadline = now_ms.saturating_add(self.sla_ms);
        {
            let Some((_, milestone)) = self.current_milestone_mut() else {
                return;
            };
            milestone.status = ToolMilestoneStatus::Pending;
            milestone.submit_deadline = Some(deadline);
            milestone.result_hash = None;
            milestone.result_metadata.clear();
            milestone.submitted_at = None;
            milestone.challenge_deadline = None;
            milestone.dispute_reason = None;
            milestone.disputed_at = None;
        }
        self.status = ToolJobStatus::Open;
        self.submit_deadline = deadline;
        self.clear_transient_result_state();
    }
}

/// Provider submission for an escrowed HTTP tool job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResultSubmitData {
    pub job_id: Hash256,
    pub result_hash: Hash256,
    #[serde(default)]
    pub result_metadata: Vec<u8>,
    /// Required for milestone-escrowed jobs; ignored for one-shot jobs.
    #[serde(default)]
    pub milestone_index: Option<u32>,
}

/// Requester acceptance of a submitted result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResultAcceptData {
    pub job_id: Hash256,
    /// Required for milestone-escrowed jobs; ignored for one-shot jobs.
    #[serde(default)]
    pub milestone_index: Option<u32>,
}

/// Requester challenge of a submitted result or provider timeout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResultDisputeData {
    pub job_id: Hash256,
    pub reason: String,
    /// Required for milestone-escrowed jobs; ignored for one-shot jobs.
    #[serde(default)]
    pub milestone_index: Option<u32>,
}

/// Arbitrator resolution of a disputed job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResultResolveData {
    pub job_id: Hash256,
    /// `true` pays the provider, `false` refunds the requester.
    pub provider_wins: bool,
    pub reason: String,
    /// Required for milestone-escrowed jobs; ignored for one-shot jobs.
    #[serde(default)]
    pub milestone_index: Option<u32>,
}

impl ToolResultSubmitData {
    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

impl ToolResultAcceptData {
    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

impl ToolResultDisputeData {
    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

impl ToolResultResolveData {
    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// Deterministic expiry / timeout settlement for escrowed jobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolJobExpireData {
    pub job_id: Hash256,
}

/// On-chain lifecycle for a metered HTTP tool invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolUsageSessionStatus {
    Open,
    Reported,
    Disputed,
}

/// Metered HTTP tool session opened by `ToolInvoke`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolUsageSession {
    /// Unique identifier for the session. For now this is the ToolInvoke tx hash.
    pub session_id: Hash256,
    pub tool_id: Hash256,
    pub requester: Address,
    pub provider: Address,
    /// Protocol-selected arbitrator. Required only once a dispute occurs.
    pub arbitrator: Option<Address>,
    /// Reserved requester funds covering the maximum authorized usage.
    pub amount_reserved: u64,
    /// Locked storage deposit collateralizing this durable session row.
    #[serde(default)]
    pub storage_deposit: u64,
    /// Frozen per-unit price at open time. For metered tools this equals the
    /// tool's `price_per_call`.
    pub price_per_unit: u64,
    /// Maximum billable units authorized by the requester.
    pub max_units: u64,
    /// Original invocation payload needed by the off-chain provider.
    pub input_data: Vec<u8>,
    /// Hash of `input_data` for quick integrity checks in clients.
    pub input_hash: Hash256,
    /// Current session status.
    pub status: ToolUsageSessionStatus,
    /// Timestamp when the session was opened.
    pub opened_at: u64,
    /// Block height when the session was opened.
    pub opened_at_block: u64,
    /// Frozen requester challenge window for this session.
    pub challenge_window_ms: u64,
    /// Frozen maximum result metadata size for this session.
    pub max_result_metadata_bytes: u32,
    /// Frozen arbitrator fee schedule selected at open time.
    #[serde(default)]
    pub arbitrator_fee_bps: u16,
    /// Deadline for provider usage report submission.
    pub submit_deadline: u64,
    /// Provider-reported billable units, if any.
    #[serde(default)]
    pub reported_units: Option<u64>,
    /// Computed billable amount derived from `reported_units`.
    #[serde(default)]
    pub billed_amount: Option<u64>,
    /// Optional provider-reported result hash.
    #[serde(default)]
    pub result_hash: Option<Hash256>,
    /// Opaque off-chain result metadata/pointer supplied by the provider.
    #[serde(default)]
    pub result_metadata: Vec<u8>,
    /// Timestamp when the provider submitted a report.
    #[serde(default)]
    pub submitted_at: Option<u64>,
    /// Deadline after submission when the report auto-settles to the provider.
    #[serde(default)]
    pub challenge_deadline: Option<u64>,
    /// Requester dispute reason, if the session is disputed.
    #[serde(default)]
    pub dispute_reason: Option<String>,
    /// Timestamp of the current dispute, if any.
    #[serde(default)]
    pub disputed_at: Option<u64>,
    /// Deadline for the currently assigned arbitrator to resolve the dispute.
    #[serde(default)]
    pub arbitration_deadline_at: Option<u64>,
    /// Number of timeout-driven arbitrator reassignments already applied.
    #[serde(default)]
    pub arbitration_reassignments: u8,
    /// Prior arbitrators that timed out on this dispute.
    #[serde(default)]
    pub prior_arbitrators: Vec<Address>,
}

/// Provider usage report for a metered HTTP tool session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolUsageReportData {
    pub session_id: Hash256,
    pub units_used: u64,
    pub result_hash: Hash256,
    #[serde(default)]
    pub result_metadata: Vec<u8>,
}

/// Requester acceptance of a reported metered HTTP tool session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolUsageAcceptData {
    pub session_id: Hash256,
}

/// Requester challenge of a reported metered HTTP tool session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolUsageDisputeData {
    pub session_id: Hash256,
    pub reason: String,
}

/// Arbitrator resolution of a disputed metered HTTP tool session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolUsageResolveData {
    pub session_id: Hash256,
    /// `true` pays the provider the reported metered amount, `false` refunds the requester.
    pub provider_wins: bool,
    pub reason: String,
}

/// Deterministic expiry / timeout settlement for metered HTTP sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolUsageExpireData {
    pub session_id: Hash256,
}

/// Access token issued when a ToolInvoke tx (or contract host_tool_invoke)
/// is included in a block.
///
/// This token proves that the invoker paid for tool access. The tool's
/// off-chain API verifies this token before serving results — no payment,
/// no service.
///
/// Verification flow:
/// 1. Agent submits ToolInvoke tx (or contract calls host_tool_invoke)
/// 2. Block producer includes tx in block, token stamped with block_hash
/// 3. Agent retrieves token via GET /v1/access-token/:token_id
/// 4. Agent sends token + invoker proof to tool endpoint in HTTP header
/// 5. Tool verifies via ChainVerifier (confirms on-chain inclusion) → serves result
///
/// For native ToolInvoke, token_id == tx hash. For contract invocations,
/// token_id is a derived per-invocation hash (one contract call can
/// produce multiple tokens). The ChainVerifier cross-checks all fields
/// against on-chain state — no field can be tampered with. The ReplayStore
/// prevents replay at the tool endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    /// The tool being accessed.
    pub tool_id: Hash256,
    /// Address that paid for access.
    pub invoker: Address,
    /// Unique identifier for this access token.
    ///
    /// For native `ToolInvoke` transactions, this equals the transaction hash.
    /// For contract `host_tool_invoke` calls, this is a derived hash
    /// (`hash("token:" + tx_hash + ":" + event_counter)`) because a single
    /// contract call can invoke multiple tools, each needing a unique token.
    ///
    /// Use this as the lookup key for `get_access_token()` and as the receipt
    /// identifier when constructing `TaskFulfillData.receipt_proofs`.
    pub token_id: Hash256,
    /// Block number where the payment was mined.
    pub block_number: u64,
    /// Amount paid in micro-ZIN.
    pub amount_paid: u64,
    /// Timestamp when the token was issued (ms since epoch).
    pub issued_at: u64,
    /// Single-use nonce preventing replay attacks.
    pub nonce: u64,
    /// Hash of the block that included this ToolInvoke transaction.
    /// Set after the block is assembled. Tools verify this against known
    /// finalized blocks — stronger than a single validator signature because
    /// it's backed by BFT finality (2/3+ validator stake).
    #[serde(default)]
    pub block_hash: Hash256,
    /// Task that consumed this token for verified attribution.
    /// Set by TaskFulfill — once set, the token cannot be reused
    /// for attribution on another task.
    #[serde(default)]
    pub consumed_by: Option<Hash256>,
}

impl AccessToken {
    /// Serialize the canonical consensus view of this token.
    ///
    /// `block_hash` is attached after block assembly for off-chain tool
    /// verification, but it cannot participate in the authenticated state
    /// commitment because the block hash itself depends on the committed
    /// state root. Consensus serialization therefore zeroes `block_hash`
    /// while preserving all economically relevant fields.
    pub fn serialize_for_commitment(&self) -> bincode::Result<Vec<u8>> {
        let mut canonical = self.clone();
        canonical.block_hash = Hash256::zero();
        bincode::serialize(&canonical)
    }
}

/// Permanent immutable record of a tool invocation payment.
///
/// This is the **attribution proof** — it survives access token pruning
/// and provides the canonical record for `TaskFulfill` verified
/// attribution. The ephemeral `AccessToken` serves as a short-lived
/// tool-access credential that can be aggressively pruned.
///
/// Written once at token creation time, never modified, never pruned.
/// `TaskFulfill` reads this instead of the ephemeral `AccessToken`
/// to verify tool usage. Consumption (which task used this receipt)
/// is tracked separately in `token_consumptions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenReceipt {
    /// Unique identifier (same as AccessToken.token_id).
    pub token_id: Hash256,
    /// The tool that was invoked.
    pub tool_id: Hash256,
    /// Address that paid for access.
    pub invoker: Address,
    /// Amount paid in micro-ZIN (at invocation time).
    pub amount_paid: u64,
    /// Timestamp when the token was issued (ms since epoch).
    pub issued_at: u64,
    /// Block number where the payment was included.
    /// Used by TaskFulfill to look up the block header's tool_receipt_root
    /// for Merkle proof verification. The cryptographic binding to the block
    /// is via block_number → header.tool_receipt_root → Merkle inclusion.
    pub block_number: u64,
    /// Single-use nonce (for audit trail / dispute resolution).
    pub nonce: u64,
}

/// Canonical write-once receipt-consumption row for verified attribution.
///
/// The row is permanent once written, so its storage deposit remains locked
/// for the lifetime of the consumption proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenConsumptionRecord {
    pub task_id: Hash256,
    #[serde(default)]
    pub storage_deposit: u64,
}

impl AccessTokenReceipt {
    // CONSENSUS-CRITICAL: this domain tag and the field byte order below define
    // the Merkle leaf format for historical tool receipt proofs. Do not change
    // without a deliberate versioned migration/hard fork.
    const CANONICAL_DOMAIN_V1: &'static [u8] = b"ZINCHA_RECEIPT_V1";

    /// Create a receipt from an AccessToken. Called at token creation time.
    pub fn from_token(token: &AccessToken) -> Self {
        Self {
            token_id: token.token_id,
            tool_id: token.tool_id,
            invoker: token.invoker.clone(),
            amount_paid: token.amount_paid,
            issued_at: token.issued_at,
            block_number: token.block_number,
            nonce: token.nonce,
        }
    }

    /// Canonical bytes for Merkle leaf hashing. Deterministic serialization
    /// used to build the per-block receipt tree and verify inclusion proofs.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf =
            Vec::with_capacity(Self::CANONICAL_DOMAIN_V1.len() + 32 + 32 + 20 + 8 + 8 + 8 + 8);
        buf.extend_from_slice(Self::CANONICAL_DOMAIN_V1);
        buf.extend_from_slice(self.token_id.as_bytes());
        buf.extend_from_slice(self.tool_id.as_bytes());
        buf.extend_from_slice(&self.invoker.0);
        buf.extend_from_slice(&self.amount_paid.to_be_bytes());
        buf.extend_from_slice(&self.issued_at.to_be_bytes());
        buf.extend_from_slice(&self.block_number.to_be_bytes());
        buf.extend_from_slice(&self.nonce.to_be_bytes());
        buf
    }

    /// Leaf hash for inclusion in the block's tool_receipt_root Merkle tree.
    pub fn leaf_hash(&self) -> Hash256 {
        crate::crypto::hash_bytes(&self.canonical_bytes())
    }
}

/// A receipt bundled with its Merkle inclusion proof against a block's
/// `tool_receipt_root`. Submitted by the fulfilling agent in TaskFulfill
/// to prove they paid for tool access, even if the ephemeral AccessToken
/// has been pruned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptWithProof {
    /// The receipt payload (issuance facts).
    pub receipt: AccessTokenReceipt,
    /// Merkle sibling hashes along the path to the root, with direction.
    pub proof_siblings: Vec<(Hash256, bool)>,
    /// The expected root hash (must match the block header's tool_receipt_root).
    pub receipt_root: Hash256,
}

impl AccessToken {
    /// Produce canonical bytes for invoker proof signing.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(self.tool_id.as_bytes());
        buf.extend_from_slice(&self.invoker.0);
        buf.extend_from_slice(self.token_id.as_bytes());
        buf.extend_from_slice(&self.block_number.to_be_bytes());
        buf.extend_from_slice(&self.amount_paid.to_be_bytes());
        buf.extend_from_slice(&self.issued_at.to_be_bytes());
        buf.extend_from_slice(&self.nonce.to_be_bytes());
        buf
    }

    /// Hex-encode the full token for transmission in HTTP headers.
    pub fn to_hex(&self) -> String {
        hex::encode(bincode::serialize(self).unwrap_or_default())
    }

    /// Decode a token from hex.
    pub fn from_hex(s: &str) -> Option<Self> {
        let bytes = hex::decode(s).ok()?;
        bincode::deserialize(&bytes).ok()
    }
}

/// A complete tool access request: token + invoker's proof-of-identity.
///
/// The invoker signs the token hash with their private key, proving
/// they are the address that paid. Without this, anyone who observes
/// the token on-chain could use it.
///
/// HTTP headers:
///   X-Zincha-Token: <hex-encoded AccessToken>
///   X-Zincha-Proof: <hex-encoded invoker signature over token hash>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolAccessRequest {
    /// The signed access token from the chain.
    pub token: AccessToken,
    /// Invoker's ed25519 signature over hash(token.signable_bytes()).
    /// Proves the presenter is the address that paid.
    pub invoker_proof: Vec<u8>,
    /// Invoker's public key (needed to verify the proof signature).
    /// The verifier checks that this pubkey hashes to token.invoker.
    pub invoker_pubkey: Vec<u8>,
}

impl ToolAccessRequest {
    /// Create a new access request by signing the token with the invoker's keypair.
    pub fn new(token: AccessToken, invoker_keypair: &crate::crypto::Keypair) -> Self {
        let token_hash = crate::crypto::hash_bytes(&token.signable_bytes());
        let sig = invoker_keypair.sign(token_hash.as_bytes());
        let pubkey_bytes = invoker_keypair.public_key().as_bytes().to_vec();
        ToolAccessRequest {
            token,
            invoker_proof: sig.to_bytes().to_vec(),
            invoker_pubkey: pubkey_bytes,
        }
    }

    /// Hex-encode the full request for HTTP transmission.
    pub fn to_hex(&self) -> String {
        hex::encode(bincode::serialize(self).unwrap_or_default())
    }

    /// Decode from hex.
    pub fn from_hex(s: &str) -> Option<Self> {
        let bytes = hex::decode(s).ok()?;
        bincode::deserialize(&bytes).ok()
    }
}

/// Tool-side verification result.
#[derive(Debug)]
pub enum ToolVerifyError {
    /// Token claims could not be verified against chain state.
    /// Either the token_id doesn't exist on-chain, the block isn't finalized,
    /// or the on-chain parameters don't match the presented token.
    ChainVerificationFailed { token_id: Hash256 },
    /// Invoker proof signature is invalid — presenter is not the payer.
    InvalidInvokerProof,
    /// Token is for a different tool.
    WrongTool { expected: Hash256, got: Hash256 },
    /// Payment amount is below the tool's current price.
    InsufficientPayment { paid: u64, required: u64 },
    /// Token was already consumed for verified attribution via TaskFulfill.
    AlreadyConsumed { task_id: Hash256 },
    /// Token has already been used (replay).
    ReplayDetected { token_id: Hash256 },
    /// Token has expired.
    Expired { issued_at: u64, max_age_ms: u64 },
}

impl std::fmt::Display for ToolVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChainVerificationFailed { token_id } => {
                write!(f, "Token {} not verified on-chain", token_id.to_hex())
            }
            Self::InvalidInvokerProof => {
                write!(f, "Invalid invoker proof — presenter is not the payer")
            }
            Self::WrongTool { expected, got } => write!(
                f,
                "Token is for tool {} but this is {}",
                got.to_hex(),
                expected.to_hex()
            ),
            Self::InsufficientPayment { paid, required } => {
                write!(f, "Paid {} micro-ZIN but tool requires {}", paid, required)
            }
            Self::AlreadyConsumed { task_id } => {
                write!(f, "Token already consumed by task {}", task_id.to_hex())
            }
            Self::ReplayDetected { token_id } => {
                write!(f, "Token {} already used", token_id.to_hex())
            }
            Self::Expired {
                issued_at,
                max_age_ms,
            } => write!(
                f,
                "Token issued at {} exceeded max age {}ms",
                issued_at, max_age_ms
            ),
        }
    }
}

/// Trait for verifying access token claims against chain state.
///
/// This is the critical security boundary. A token's `block_hash` alone
/// does NOT prove the token was created on-chain — anyone can fabricate
/// a token pointing at a real block. The verifier must confirm that the
/// claimed `token_id` exists on-chain with ALL fields matching.
///
/// **All fields must be verified.** If any field (including `nonce` and
/// `issued_at`) is not checked, an attacker can take a real token, mutate
/// the unchecked fields, re-sign the invoker proof, and bypass replay
/// detection or expiry enforcement.
///
/// Implement this with your preferred chain connection:
/// - Full node: query local state (access_tokens DashMap for ephemeral
///   tokens, token_receipts for permanent records)
/// - Light client: verify Merkle proof against state trie (token_receipts
///   are trie-committed under prefix 0x0A)
/// - RPC: query `GET /v1/token-receipt/:token_id` for permanent issuance
///   facts, `GET /v1/token-consumption/:token_id` for attribution status
pub trait ChainVerifier: Send + Sync {
    /// Verify that an access token's claims match on-chain state:
    /// - block_hash is a known finalized block
    /// - token_id exists on-chain (receipt store or access_tokens)
    /// - ALL token fields match the on-chain record (tool_id, invoker,
    ///   amount_paid, block_number, issued_at, nonce)
    ///
    /// Returns false if any claim cannot be verified.
    fn verify_access_token(&self, token: &AccessToken) -> bool;

    /// Check if the token has been consumed for verified attribution
    /// via TaskFulfill. Returns the consuming task ID if consumed,
    /// None if unconsumed or token not found.
    ///
    /// On-chain, consumption is tracked in `token_consumptions` (permanent,
    /// write-once, separate from the ephemeral AccessToken). Implementers
    /// should query `GET /v1/token-consumption/:token_id` or read the
    /// `token_consumptions` DashMap directly.
    ///
    /// This is an additive defense — many tokens are never consumed via
    /// TaskFulfill, so this alone is NOT sufficient for replay prevention.
    fn get_consumed_by(&self, token_id: &Hash256) -> Option<Hash256>;
}

/// Simple chain verifier for testing and embedded use.
/// Register known finalized tokens via `add_token()` and consumptions
/// via `add_consumption()`.
pub struct HashSetChainVerifier {
    known_tokens: std::sync::RwLock<std::collections::HashMap<Hash256, AccessToken>>,
    /// Separate consumption tracking (mirrors on-chain token_consumptions).
    consumptions: std::sync::RwLock<std::collections::HashMap<Hash256, Hash256>>,
}

impl HashSetChainVerifier {
    pub fn new() -> Self {
        Self {
            known_tokens: std::sync::RwLock::new(std::collections::HashMap::new()),
            consumptions: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }
    /// Register a token as a known on-chain ToolInvoke.
    pub fn add_token(&self, token: AccessToken) {
        self.known_tokens
            .write()
            .unwrap()
            .insert(token.token_id, token);
    }
    /// Register a consumption (token_id → task_id).
    pub fn add_consumption(&self, token_id: Hash256, task_id: Hash256) {
        self.consumptions.write().unwrap().insert(token_id, task_id);
    }
}

impl ChainVerifier for HashSetChainVerifier {
    fn verify_access_token(&self, token: &AccessToken) -> bool {
        let known = self.known_tokens.read().unwrap();
        match known.get(&token.token_id) {
            Some(on_chain) => {
                on_chain.block_hash == token.block_hash
                    && on_chain.tool_id == token.tool_id
                    && on_chain.invoker == token.invoker
                    && on_chain.amount_paid == token.amount_paid
                    && on_chain.block_number == token.block_number
                    && on_chain.issued_at == token.issued_at
                    && on_chain.nonce == token.nonce
                    && on_chain.block_hash != Hash256::zero() // must be stamped
            }
            None => false,
        }
    }

    fn get_consumed_by(&self, token_id: &Hash256) -> Option<Hash256> {
        self.consumptions.read().unwrap().get(token_id).copied()
    }
}

/// Pluggable replay prevention store for tool-side verification.
///
/// The `ToolVerifier` calls this on every verified request to track which
/// token ids have already been served. **This is the tool endpoint's
/// replay protection** — it prevents the same paid token from being
/// presented multiple times to receive service.
///
/// Production deployments MUST provide a persistent implementation (e.g.,
/// backed by SQLite, Redis, or a file) so replay protection survives process
/// restarts.
///
/// The on-chain `consumed_by` field is NOT a substitute: it is only set when
/// an agent references the token in `TaskFulfill` for verified attribution,
/// which may never happen for ordinary tool access.
pub trait ReplayStore: Send + Sync {
    /// Atomically check if a token id has been used and mark it as used if not.
    /// Returns `true` if the token id was successfully claimed (first use).
    /// Returns `false` if the token id was already used (replay).
    ///
    /// This MUST be atomic — check-and-mark in one operation. A split
    /// has_been_used() + mark_used() API enables TOCTOU races where two
    /// concurrent requests both observe "unused" before either marks it.
    fn try_use(&self, token_id: Hash256) -> bool;
}

/// In-memory replay store. Suitable for development and testing only.
///
/// **WARNING: Does not survive process restarts.** After restart, all
/// previously-seen token ids are forgotten and tokens can be replayed
/// until they expire. Use a persistent `ReplayStore` implementation
/// in production.
pub struct InMemoryReplayStore {
    used: std::sync::Mutex<std::collections::HashSet<Hash256>>,
}

impl InMemoryReplayStore {
    pub fn new() -> Self {
        Self {
            used: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }
}

impl ReplayStore for InMemoryReplayStore {
    fn try_use(&self, token_id: Hash256) -> bool {
        self.used.lock().unwrap().insert(token_id)
    }
}

/// Tool-side verifier. Drop this into your tool's API middleware.
///
/// Verifies access tokens by confirming the token's claims match on-chain
/// state via the `ChainVerifier` trait, and tracks used token ids via a
/// pluggable `ReplayStore` to prevent replay at the tool endpoint.
///
/// **Production checklist:**
/// - Provide a persistent `ReplayStore` implementation (SQLite, Redis, file).
/// - Provide a `ChainVerifier` implementation. For `verify_access_token()`,
///   query `GET /v1/token-receipt/:token_id` (permanent, survives pruning)
///   or `GET /v1/access-token/:token_id` (ephemeral, pruned after 24h).
///   For `get_consumed_by()`, query `GET /v1/token-consumption/:token_id`.
/// - Set `with_min_price()` to a stable minimum payment floor, NOT your
///   current `price_per_call`. If you track the on-chain price, tokens
///   issued before a price increase will be rejected even though the
///   invoker paid the correct price at invocation time. Use a fixed floor
///   or omit entirely (the on-chain ToolInvoke handler already enforces
///   `price_per_call` at invocation time).
/// - Set `with_max_age_ms()` to bound the replay window (default: 1 hour).
///
/// ```rust,no_run
/// use std::sync::Arc;
///
/// use zincha_primitives::crypto::Hash256;
/// use zincha_primitives::primitives::ToolVerifier;
/// use zincha_primitives::primitives::ToolAccessRequest;
/// use zincha_primitives::primitives::tool::{HashSetChainVerifier, InMemoryReplayStore};
///
/// let chain_verifier = HashSetChainVerifier::new();
/// let replay_store = InMemoryReplayStore::new();
/// let my_tool_id = Hash256::zero();
///
/// let verifier = ToolVerifier::new(
///     my_tool_id,
///     Arc::new(chain_verifier),
///     Arc::new(replay_store),
/// )
///     .with_min_price(100_000)     // 0.1 ZIN absolute floor (not current price)
///     .with_max_age_ms(3_600_000); // 1 hour expiry
///
/// // In your HTTP handler:
/// let header_value = "hex-encoded-tool-access-request";
/// if let Some(request) = ToolAccessRequest::from_hex(header_value) {
///     verifier.verify(&request).unwrap();
///     // serve result
/// }
/// ```
pub struct ToolVerifier {
    /// This tool's ID.
    tool_id: Hash256,
    /// Chain verifier for confirming token claims against on-chain state.
    chain_verifier: std::sync::Arc<dyn ChainVerifier>,
    /// Pluggable replay store for token-use tracking at the tool endpoint.
    replay_store: std::sync::Arc<dyn ReplayStore>,
    /// Maximum token age in milliseconds (0 = no expiry check).
    max_age_ms: u64,
    /// Minimum payment required in micro-ZIN (0 = no payment check).
    min_price: u64,
}

impl ToolVerifier {
    /// Create a new verifier for a specific tool using the caller's replay
    /// prevention store.
    pub fn new(
        tool_id: Hash256,
        chain_verifier: std::sync::Arc<dyn ChainVerifier>,
        replay_store: std::sync::Arc<dyn ReplayStore>,
    ) -> Self {
        ToolVerifier {
            tool_id,
            chain_verifier,
            replay_store,
            max_age_ms: 3_600_000, // default: 1 hour
            min_price: 0,
        }
    }

    /// Explicitly opt into a process-local in-memory replay store.
    ///
    /// This constructor is intended only for tests, local development, and
    /// example code. It is not safe for production because replay protection
    /// is forgotten on restart.
    pub fn new_insecure_in_memory(
        tool_id: Hash256,
        chain_verifier: std::sync::Arc<dyn ChainVerifier>,
    ) -> Self {
        Self::new(
            tool_id,
            chain_verifier,
            std::sync::Arc::new(InMemoryReplayStore::new()),
        )
    }

    /// Set the maximum token age. Tokens older than this are rejected.
    pub fn with_max_age_ms(mut self, ms: u64) -> Self {
        self.max_age_ms = ms;
        self
    }

    /// Set the minimum payment required. Tokens that paid less are rejected.
    ///
    /// This is a **stable floor**, not the current on-chain `price_per_call`.
    /// The on-chain price is enforced at invocation time; this is an additional
    /// tool-side gate. If you set this to your current price and later raise it,
    /// tokens issued at the old (valid) price will be rejected here.
    pub fn with_min_price(mut self, price_micro_zin: u64) -> Self {
        self.min_price = price_micro_zin;
        self
    }

    /// Verify a tool access request. Returns Ok(()) if all checks pass.
    ///
    /// Checks (in order):
    /// 1. Token claims verified against chain state (tx exists, block finalized,
    ///    tool_id/invoker/amount match on-chain record)
    /// 2. Token is for THIS tool
    /// 3. Invoker proof is valid (presenter == payer)
    /// 4. Payment meets minimum floor (if configured — use a stable floor, not current price)
    /// 5. On-chain consumed_by check (additive, catches TaskFulfill consumption)
    /// 6. Token hasn't expired (side-effect-free, checked before replay-store claim)
    /// 7. Tool-side replay prevention (ReplayStore — must be persistent in production)
    pub fn verify(&self, request: &ToolAccessRequest) -> Result<(), ToolVerifyError> {
        let token = &request.token;

        // 1. Chain verification — confirms token was actually created on-chain.
        //    Without this, an attacker could fabricate a token with arbitrary
        //    fields pointing at any finalized block.
        if !self.chain_verifier.verify_access_token(token) {
            return Err(ToolVerifyError::ChainVerificationFailed {
                token_id: token.token_id,
            });
        }

        // 2. Correct tool
        if token.tool_id != self.tool_id {
            return Err(ToolVerifyError::WrongTool {
                expected: self.tool_id,
                got: token.tool_id,
            });
        }

        // 3. Invoker proof — verify the presenter owns the invoker address
        let token_hash = crate::crypto::hash_bytes(&token.signable_bytes());
        if request.invoker_proof.len() != 64 || request.invoker_pubkey.len() != 32 {
            return Err(ToolVerifyError::InvalidInvokerProof);
        }

        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&request.invoker_pubkey);
        let invoker_pk = crate::crypto::PublicKey::from_bytes(&pk_bytes)
            .map_err(|_| ToolVerifyError::InvalidInvokerProof)?;
        if invoker_pk.to_address() != token.invoker {
            return Err(ToolVerifyError::InvalidInvokerProof);
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&request.invoker_proof);
        let sig = crate::crypto::Signature::from_bytes(&sig_bytes)
            .map_err(|_| ToolVerifyError::InvalidInvokerProof)?;
        invoker_pk
            .verify(token_hash.as_bytes(), &sig)
            .map_err(|_| ToolVerifyError::InvalidInvokerProof)?;

        // 4. Payment floor (stable minimum, not current on-chain price)
        if self.min_price > 0 && token.amount_paid < self.min_price {
            return Err(ToolVerifyError::InsufficientPayment {
                paid: token.amount_paid,
                required: self.min_price,
            });
        }

        // 5. On-chain consumed check (additive defense).
        //    Consumption is tracked in token_consumptions (permanent,
        //    write-once). Query via ChainVerifier.get_consumed_by() which
        //    should read token_consumptions, NOT AccessToken.consumed_by.
        if let Some(task_id) = self.chain_verifier.get_consumed_by(&token.token_id) {
            return Err(ToolVerifyError::AlreadyConsumed { task_id });
        }

        // 6. Expiry check (before replay-store claim — a rejected expired
        //    token should not mark the token id as used).
        if self.max_age_ms > 0 {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            if now_ms.saturating_sub(token.issued_at) > self.max_age_ms {
                return Err(ToolVerifyError::Expired {
                    issued_at: token.issued_at,
                    max_age_ms: self.max_age_ms,
                });
            }
        }

        // 7. Replay prevention (tool-side replay store, atomic check+mark).
        //    Last check before granting access — all side-effect-free checks
        //    are done, so a rejected request never consumes a replay key.
        if !self.replay_store.try_use(token.token_id) {
            return Err(ToolVerifyError::ReplayDetected {
                token_id: token.token_id,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_plan() -> ToolSubscriptionPlan {
        ToolSubscriptionPlan {
            plan_id: Hash256::from_bytes([0xaa; 32]),
            tool_id: Hash256::from_bytes([0x33; 32]),
            provider: Address([0x55; 20]),
            name: "Plan".to_string(),
            price_per_period: 2,
            period_ms: 100,
            included_calls: 3,
            included_credits: 7,
            overage_policy: SubscriptionOveragePolicy::Deny,
            active: true,
            created_at: 0,
            created_at_block: 0,
            updated_at: 0,
            storage_deposit: 0,
        }
    }

    fn sample_tool(endpoint: &str, settlement_mode: HttpToolSettlementMode) -> ToolEntry {
        ToolEntry {
            tool_id: Hash256::from_bytes([0x10; 32]),
            owner: Address([0x20; 20]),
            name: "Tool".to_string(),
            description: "Tool description".to_string(),
            endpoint: endpoint.to_string(),
            price_per_call: 1,
            settlement_mode,
            sla_ms: 100,
            challenge_window_ms: 100,
            max_result_metadata_bytes: 1024,
            arbitration_policy: ToolArbitrationPolicy::Protocol,
            capabilities: vec![Capability::new("cap")],
            match_enabled: true,
            description_embedding: vec![0.1; 128],
            neural_embedding: vec![0.1; 128],
            active: true,
            deregistered_at: 0,
            version: "1.0".to_string(),
            registered_at_block: 1,
            reputation: ToolReputation::default(),
            storage_deposit: 0,
        }
    }

    fn sample_subscription() -> ToolSubscription {
        ToolSubscription {
            subscription_id: Hash256::from_bytes([0x11; 32]),
            plan_id: Hash256::from_bytes([0x22; 32]),
            tool_id: Hash256::from_bytes([0x33; 32]),
            subscriber: Address([0x44; 20]),
            provider: Address([0x55; 20]),
            price_per_period: 2,
            period_ms: 100,
            included_calls: 3,
            included_credits: 7,
            overage_policy: SubscriptionOveragePolicy::Deny,
            current_period_start: 0,
            current_period_end: 100,
            next_renewal_at: 100,
            remaining_calls: 0,
            remaining_credits: 0,
            compensating_calls: 0,
            compensating_credits: 0,
            reserved_balance: 0,
            status: ToolSubscriptionStatus::Active,
            auto_renew: true,
            created_at: 0,
            created_at_block: 0,
            storage_deposit: 0,
            cancelled_at: None,
        }
    }

    #[test]
    fn test_access_token_receipt_canonical_bytes_golden() {
        let receipt = AccessTokenReceipt {
            token_id: Hash256::from_bytes([0x11; 32]),
            tool_id: Hash256::from_bytes([0x22; 32]),
            invoker: Address([0x33; 20]),
            amount_paid: 0x0102_0304_0506_0708,
            issued_at: 0x1112_1314_1516_1718,
            block_number: 0x2122_2324_2526_2728,
            nonce: 0x3132_3334_3536_3738,
        };

        let mut expected = Vec::new();
        expected.extend_from_slice(b"ZINCHA_RECEIPT_V1");
        expected.extend_from_slice(&[0x11; 32]);
        expected.extend_from_slice(&[0x22; 32]);
        expected.extend_from_slice(&[0x33; 20]);
        expected.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
        expected.extend_from_slice(&0x1112_1314_1516_1718u64.to_be_bytes());
        expected.extend_from_slice(&0x2122_2324_2526_2728u64.to_be_bytes());
        expected.extend_from_slice(&0x3132_3334_3536_3738u64.to_be_bytes());

        assert_eq!(receipt.canonical_bytes(), expected);
    }

    #[test]
    fn test_access_token_receipt_leaf_hash_golden() {
        let receipt = AccessTokenReceipt {
            token_id: Hash256::from_bytes([0x11; 32]),
            tool_id: Hash256::from_bytes([0x22; 32]),
            invoker: Address([0x33; 20]),
            amount_paid: 0x0102_0304_0506_0708,
            issued_at: 0x1112_1314_1516_1718,
            block_number: 0x2122_2324_2526_2728,
            nonce: 0x3132_3334_3536_3738,
        };

        let expected = crate::crypto::hash_bytes(&receipt.canonical_bytes());
        assert_eq!(receipt.leaf_hash(), expected);
        assert_eq!(
            expected.to_hex(),
            "0971d0324d3716003801f08b93a766ef78fc6fad2a8a7e266702d4fe265c4f1c"
        );
    }

    #[test]
    fn test_access_token_receipt_merkle_root_golden() {
        let receipt_a = AccessTokenReceipt {
            token_id: Hash256::from_bytes([0x11; 32]),
            tool_id: Hash256::from_bytes([0x22; 32]),
            invoker: Address([0x33; 20]),
            amount_paid: 1,
            issued_at: 2,
            block_number: 3,
            nonce: 4,
        };
        let receipt_b = AccessTokenReceipt {
            token_id: Hash256::from_bytes([0x44; 32]),
            tool_id: Hash256::from_bytes([0x55; 32]),
            invoker: Address([0x66; 20]),
            amount_paid: 5,
            issued_at: 6,
            block_number: 7,
            nonce: 8,
        };

        let leaf_hashes = vec![receipt_a.leaf_hash(), receipt_b.leaf_hash()];
        let root = crate::crypto::MerkleTree::from_hashes(leaf_hashes).root();
        assert_eq!(
            root.to_hex(),
            "524f75235dff690b525fc8386e6cf88e3d9785744c6838de90c1f1d67b7bd92a"
        );
    }

    #[test]
    fn test_subscription_advance_periods_catches_up_fully_in_constant_time() {
        let mut subscription = sample_subscription();
        subscription.reserved_balance = 6;

        let outcome = subscription.advance_periods(350, true);

        assert_eq!(outcome.renewed_periods, 3);
        assert_eq!(outcome.provider_credit, 6);
        assert_eq!(subscription.reserved_balance, 0);
        assert_eq!(subscription.current_period_start, 300);
        assert_eq!(subscription.current_period_end, 400);
        assert_eq!(subscription.next_renewal_at, 400);
        assert_eq!(subscription.remaining_calls, 3);
        assert_eq!(subscription.remaining_credits, 7);
        assert_eq!(subscription.status, ToolSubscriptionStatus::Active);
    }

    #[test]
    fn test_subscription_advance_periods_partial_reserve_becomes_past_due() {
        let mut subscription = sample_subscription();
        subscription.reserved_balance = 4;

        let outcome = subscription.advance_periods(350, true);

        assert_eq!(outcome.renewed_periods, 2);
        assert_eq!(outcome.provider_credit, 4);
        assert_eq!(subscription.reserved_balance, 0);
        assert_eq!(subscription.current_period_start, 200);
        assert_eq!(subscription.current_period_end, 300);
        assert_eq!(subscription.next_renewal_at, 300);
        assert_eq!(subscription.remaining_calls, 0);
        assert_eq!(subscription.remaining_credits, 0);
        assert_eq!(subscription.status, ToolSubscriptionStatus::PastDue);
    }

    #[test]
    fn test_subscription_advance_periods_zero_price_handles_large_gaps() {
        let mut subscription = sample_subscription();
        subscription.price_per_period = 0;
        subscription.reserved_balance = 0;

        let outcome = subscription.advance_periods(100_000, true);

        assert_eq!(outcome.renewed_periods, 1000);
        assert_eq!(outcome.provider_credit, 0);
        assert_eq!(subscription.current_period_start, 100_000);
        assert_eq!(subscription.current_period_end, 100_100);
        assert_eq!(subscription.next_renewal_at, 100_100);
        assert_eq!(subscription.remaining_calls, 3);
        assert_eq!(subscription.remaining_credits, 7);
        assert_eq!(subscription.status, ToolSubscriptionStatus::Active);
    }

    #[test]
    fn test_subscription_advance_periods_paused_restarts_from_now_without_back_billing() {
        let mut subscription = sample_subscription();
        subscription.status = ToolSubscriptionStatus::Paused;
        subscription.reserved_balance = 6;

        let outcome = subscription.advance_periods(350, true);

        assert_eq!(outcome.renewed_periods, 1);
        assert_eq!(outcome.provider_credit, 2);
        assert_eq!(subscription.reserved_balance, 4);
        assert_eq!(subscription.current_period_start, 350);
        assert_eq!(subscription.current_period_end, 450);
        assert_eq!(subscription.next_renewal_at, 450);
        assert_eq!(subscription.remaining_calls, 3);
        assert_eq!(subscription.remaining_credits, 7);
        assert_eq!(subscription.status, ToolSubscriptionStatus::Active);
    }

    #[test]
    fn test_subscription_advance_periods_paused_without_reserve_resets_due_anchor() {
        let mut subscription = sample_subscription();
        subscription.status = ToolSubscriptionStatus::Paused;

        let outcome = subscription.advance_periods(350, true);

        assert_eq!(outcome.renewed_periods, 0);
        assert_eq!(outcome.provider_credit, 0);
        assert_eq!(subscription.current_period_start, 350);
        assert_eq!(subscription.current_period_end, 350);
        assert_eq!(subscription.next_renewal_at, 350);
        assert_eq!(subscription.remaining_calls, 0);
        assert_eq!(subscription.remaining_credits, 0);
        assert_eq!(subscription.status, ToolSubscriptionStatus::PastDue);
    }

    #[test]
    fn test_subscription_terminate_for_unrecoverable_service_loss_refunds_reserve_and_compensation()
    {
        let mut subscription = sample_subscription();
        subscription.status = ToolSubscriptionStatus::Paused;
        subscription.auto_renew = true;
        subscription.reserved_balance = 5_000_000;
        subscription.compensating_calls = 2;
        subscription.compensating_credits = 700_000;

        let outcome = subscription.terminate_for_unrecoverable_service_loss(350, 900_000);

        assert_eq!(outcome.reserve_refund, 5_000_000);
        assert_eq!(outcome.compensation_refund, 2_500_000);
        assert_eq!(subscription.reserved_balance, 0);
        assert_eq!(subscription.compensating_calls, 0);
        assert_eq!(subscription.compensating_credits, 0);
        assert_eq!(subscription.status, ToolSubscriptionStatus::Cancelled);
        assert!(!subscription.auto_renew);
        assert_eq!(subscription.cancelled_at, Some(350));
    }

    #[test]
    fn test_tool_supports_subscriptions_by_invoke_route() {
        assert!(sample_tool(
            "https://tools.example.com/prepaid",
            HttpToolSettlementMode::PrepaidAccess
        )
        .supports_subscriptions());
        assert!(sample_tool(
            "https://tools.example.com/escrowed",
            HttpToolSettlementMode::ResultEscrowed
        )
        .supports_subscriptions());
        assert!(sample_tool(
            "contract://zn10123456789abcdef0123456789abcdef01234567/run",
            HttpToolSettlementMode::PrepaidAccess
        )
        .supports_subscriptions());
        assert!(!sample_tool(
            "https://tools.example.com/metered",
            HttpToolSettlementMode::MeteredUsage
        )
        .supports_subscriptions());
        assert!(!sample_tool(
            "https://tools.example.com/milestones",
            HttpToolSettlementMode::MilestoneEscrowed
        )
        .supports_subscriptions());
    }

    #[test]
    fn test_subscription_requires_compatible_tool_until_fully_terminal() {
        let mut subscription = sample_subscription();
        assert!(subscription.requires_subscription_compatible_tool());

        subscription.status = ToolSubscriptionStatus::PastDue;
        assert!(subscription.requires_subscription_compatible_tool());

        subscription.status = ToolSubscriptionStatus::Paused;
        assert!(subscription.requires_subscription_compatible_tool());

        subscription.status = ToolSubscriptionStatus::CancelRequested;
        assert!(subscription.requires_subscription_compatible_tool());

        subscription.status = ToolSubscriptionStatus::Cancelled;
        assert!(!subscription.requires_subscription_compatible_tool());

        subscription.reserved_balance = 1;
        assert!(subscription.requires_subscription_compatible_tool());

        subscription.reserved_balance = 0;
        subscription.compensating_calls = 1;
        assert!(subscription.requires_subscription_compatible_tool());

        subscription.compensating_calls = 0;
        subscription.compensating_credits = 1;
        assert!(subscription.requires_subscription_compatible_tool());
    }

    #[test]
    fn test_subscription_can_accept_reserve_top_up_only_while_non_terminal() {
        let mut subscription = sample_subscription();
        assert!(subscription.can_accept_reserve_top_up());

        subscription.status = ToolSubscriptionStatus::Paused;
        assert!(subscription.can_accept_reserve_top_up());

        subscription.status = ToolSubscriptionStatus::PastDue;
        assert!(subscription.can_accept_reserve_top_up());

        subscription.status = ToolSubscriptionStatus::CancelRequested;
        assert!(!subscription.can_accept_reserve_top_up());

        subscription.status = ToolSubscriptionStatus::Cancelled;
        assert!(!subscription.can_accept_reserve_top_up());
    }

    #[test]
    fn test_start_or_restart_from_plan_preserves_compensation_and_resets_reserve_on_reused_slot() {
        let mut reusable = sample_subscription();
        reusable.status = ToolSubscriptionStatus::Cancelled;
        reusable.compensating_calls = 2;
        reusable.compensating_credits = 11;
        reusable.reserved_balance = 5;
        reusable.storage_deposit = 19;
        reusable.cancelled_at = Some(55);

        let started = ToolSubscription::start_or_restart_from_plan(
            Some(&reusable),
            reusable.subscription_id,
            &sample_plan(),
            reusable.subscriber.clone(),
            500,
            9,
            13,
            false,
            7,
        );

        assert_eq!(started.subscription_id, reusable.subscription_id);
        assert_eq!(started.compensating_calls, 2);
        assert_eq!(started.compensating_credits, 11);
        assert_eq!(started.remaining_calls, 3);
        assert_eq!(started.remaining_credits, 7);
        assert_eq!(started.storage_deposit, 26);
        assert_eq!(started.reserved_balance, 13);
        assert_eq!(started.status, ToolSubscriptionStatus::Active);
        assert!(!started.auto_renew);
        assert_eq!(started.cancelled_at, None);
        assert_eq!(started.current_period_start, 500);
        assert_eq!(started.current_period_end, 600);
        assert_eq!(started.next_renewal_at, 600);
    }

    #[test]
    fn test_validate_contract_tool_gas_limit_rejects_zero() {
        let err = validate_contract_tool_gas_limit(0).expect_err("zero gas limit must fail");
        assert!(err.contains("must be > 0"), "unexpected error: {}", err);
    }

    #[test]
    fn test_validate_contract_tool_gas_limit_accepts_default_limit() {
        let gas_limit = validate_contract_tool_gas_limit(DEFAULT_CONTRACT_TOOL_GAS_LIMIT)
            .expect("default contract tool gas limit should be canonical");
        assert_eq!(gas_limit, DEFAULT_CONTRACT_TOOL_GAS_LIMIT);
    }
}
