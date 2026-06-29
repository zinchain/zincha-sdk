use serde::{Deserialize, Serialize};

use crate::crypto::{Address, Hash256};

/// Status of an agreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum AgreementStatus {
    /// Created by proposer, awaiting counterparty acceptance.
    Proposed,
    /// All parties accepted, work in progress.
    Active,
    /// Work completed, escrow released.
    Completed,
    /// One party raised a dispute, awaiting arbitrator.
    Disputed,
    /// Arbitrator resolved the dispute.
    Resolved,
    /// Agreement expired before completion.
    Expired,
    /// Cancelled by proposer before counterparty accepted.
    Cancelled,
}

/// Status of an individual milestone within an agreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MilestoneStatus {
    /// Milestone work not yet started or submitted.
    Pending,
    /// Milestone deliverable submitted and escrow released.
    Completed,
    /// Milestone is under dispute.
    Disputed,
    /// Dispute on this milestone was resolved by arbitrator.
    Resolved,
}

/// A single milestone within an agreement.
///
/// Milestones allow partial/staged payments. Each milestone has its own
/// escrow portion, deliverable proof, and status. The agreement completes
/// automatically when all milestones are completed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Milestone {
    /// Milestone index (0-based).
    pub index: u32,
    /// Description of the deliverable for this milestone.
    pub description: String,
    /// Escrow portion in micro-ZIN. Sum of all milestone amounts must
    /// equal the agreement's total escrow_amount.
    pub amount: u64,
    /// Current status of this milestone.
    pub status: MilestoneStatus,
    /// Hash of the deliverable (set when completed).
    pub result_hash: Option<Hash256>,
    /// Block when this milestone was completed.
    pub completed_at_block: Option<u64>,
    /// Dispute resolution details for this milestone, if an arbitrator ruled on it.
    #[serde(default)]
    pub resolution: Option<DisputeResolution>,
}

/// Milestone definition at agreement creation time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MilestoneDef {
    /// Description of the deliverable.
    pub description: String,
    /// Escrow amount for this milestone in micro-ZIN.
    pub amount: u64,
}

/// Canonical single-payment agreement form.
///
/// Agreements that do not need staged payouts still persist one explicit
/// milestone whose amount equals the full escrow.
pub fn canonical_single_payment_milestones(escrow_amount: u64) -> Vec<MilestoneDef> {
    vec![MilestoneDef {
        description: "Complete agreement".to_string(),
        amount: escrow_amount,
    }]
}

pub fn materialize_agreement_milestones(
    milestone_defs: &[MilestoneDef],
    escrow_amount: u64,
) -> Result<Vec<Milestone>, String> {
    if milestone_defs.is_empty() {
        return Err(
            "Agreement requires at least one milestone; single-payment agreements must use one milestone whose amount equals escrow"
                .into(),
        );
    }

    let milestone_total = milestone_defs
        .iter()
        .try_fold(0u64, |acc, milestone| acc.checked_add(milestone.amount))
        .ok_or_else(|| "Milestone amounts overflow".to_string())?;
    if milestone_total != escrow_amount {
        return Err(format!(
            "Milestone total {} != escrow {}",
            milestone_total, escrow_amount
        ));
    }
    if milestone_defs.len() > 20 {
        return Err("Max 20 milestones".into());
    }
    for (index, milestone) in milestone_defs.iter().enumerate() {
        if milestone.description.len() > 1_024 {
            return Err(format!("Milestone {} description too long", index));
        }
    }

    Ok(milestone_defs
        .iter()
        .enumerate()
        .map(|(index, milestone)| Milestone {
            index: index as u32,
            description: milestone.description.clone(),
            amount: milestone.amount,
            status: MilestoneStatus::Pending,
            result_hash: None,
            completed_at_block: None,
            resolution: None,
        })
        .collect())
}

/// A deterministic payout share for agreement settlement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementPayoutShare {
    /// Recipient party that receives this share of released escrow.
    pub recipient: Address,
    /// Share of the released escrow in basis points. Sum must equal 10_000.
    pub share_bps: u16,
}

/// Cooperative settlement authority must stay on the payer side of the
/// agreement. The designated approver may not collapse into the same entity
/// as any recipient that remains independent from the proposer.
pub fn settlement_approver_is_independent<F>(
    proposer: &Address,
    settlement_approver: &Address,
    settlement_allocations: &[AgreementPayoutShare],
    mut same_entity: F,
) -> bool
where
    F: FnMut(&Address, &Address) -> bool,
{
    for allocation in settlement_allocations {
        if same_entity(proposer, &allocation.recipient) {
            continue;
        }
        if same_entity(settlement_approver, &allocation.recipient) {
            return false;
        }
    }
    true
}

fn agreement_involves_third_party_with<F>(
    proposer: &Address,
    settlement_recipients: &[Address],
    same_entity: &mut F,
) -> bool
where
    F: FnMut(&Address, &Address) -> bool,
{
    !settlement_recipients.is_empty()
        && settlement_recipients
            .iter()
            .any(|recipient| !same_entity(proposer, recipient))
}

pub fn agreement_involves_third_party<F>(
    proposer: &Address,
    settlement_recipients: &[Address],
    mut same_entity: F,
) -> bool
where
    F: FnMut(&Address, &Address) -> bool,
{
    agreement_involves_third_party_with(proposer, settlement_recipients, &mut same_entity)
}

fn agreement_service_provider_involves_third_party_with<F>(
    proposer: &Address,
    service_provider: &Address,
    same_entity: &mut F,
) -> bool
where
    F: FnMut(&Address, &Address) -> bool,
{
    !same_entity(proposer, service_provider)
}

pub fn agreement_service_provider_involves_third_party<F>(
    proposer: &Address,
    service_provider: &Address,
    mut same_entity: F,
) -> bool
where
    F: FnMut(&Address, &Address) -> bool,
{
    agreement_service_provider_involves_third_party_with(
        proposer,
        service_provider,
        &mut same_entity,
    )
}

fn resolve_agreement_settlement_allocations_with<F>(
    proposer: &Address,
    parties: &[Address],
    service_provider: &Address,
    settlement_allocations: &[AgreementPayoutShare],
    same_entity: &mut F,
) -> Result<Vec<AgreementPayoutShare>, String>
where
    F: FnMut(&Address, &Address) -> bool,
{
    if !settlement_allocations.is_empty() {
        let mut seen = std::collections::HashSet::new();
        let mut total_share_bps = 0u32;
        for allocation in settlement_allocations {
            if allocation.share_bps == 0 {
                return Err("Settlement allocations cannot contain a zero share".into());
            }
            if !parties.contains(&allocation.recipient) {
                return Err("Settlement allocation recipient must be a party".into());
            }
            if !seen.insert(allocation.recipient.clone()) {
                return Err("Settlement allocations cannot contain duplicate recipients".into());
            }
            total_share_bps = total_share_bps.saturating_add(allocation.share_bps as u32);
        }
        if total_share_bps != 10_000 {
            return Err("Settlement allocations must sum to 10_000 bps".into());
        }
        let recipients = settlement_allocations
            .iter()
            .map(|allocation| allocation.recipient.clone())
            .collect::<Vec<_>>();
        if !agreement_involves_third_party_with(proposer, &recipients, same_entity) {
            return Err("Settlement allocations must include a third-party recipient".into());
        }
        if !settlement_allocations
            .iter()
            .any(|allocation| allocation.recipient == *service_provider)
        {
            return Err("Service provider must receive a non-zero settlement allocation".into());
        }
        return Ok(settlement_allocations.to_vec());
    }

    Ok(vec![AgreementPayoutShare {
        recipient: service_provider.clone(),
        share_bps: 10_000,
    }])
}

pub fn resolve_agreement_settlement_allocations<F>(
    proposer: &Address,
    parties: &[Address],
    service_provider: &Address,
    settlement_allocations: &[AgreementPayoutShare],
    mut same_entity: F,
) -> Result<Vec<AgreementPayoutShare>, String>
where
    F: FnMut(&Address, &Address) -> bool,
{
    resolve_agreement_settlement_allocations_with(
        proposer,
        parties,
        service_provider,
        settlement_allocations,
        &mut same_entity,
    )
}

fn resolve_agreement_settlement_approver_with<F>(
    proposer: &Address,
    parties: &[Address],
    settlement_allocations: &[AgreementPayoutShare],
    settlement_approver: Option<&Address>,
    same_entity: &mut F,
) -> Result<Address, String>
where
    F: FnMut(&Address, &Address) -> bool,
{
    let approver = if let Some(approver) = settlement_approver {
        if !parties.contains(approver) {
            return Err("Settlement approver must be a party".into());
        }
        approver.clone()
    } else if parties.len() > 2 {
        return Err("Multi-party agreements require explicit settlement approver".into());
    } else {
        proposer.clone()
    };

    if !settlement_approver_is_independent(
        proposer,
        &approver,
        settlement_allocations,
        |lhs, rhs| same_entity(lhs, rhs),
    ) {
        return Err(
            "Settlement approver cannot be a non-proposer payout recipient or same entity".into(),
        );
    }

    Ok(approver)
}

pub fn resolve_agreement_settlement_approver<F>(
    proposer: &Address,
    parties: &[Address],
    settlement_allocations: &[AgreementPayoutShare],
    settlement_approver: Option<&Address>,
    mut same_entity: F,
) -> Result<Address, String>
where
    F: FnMut(&Address, &Address) -> bool,
{
    resolve_agreement_settlement_approver_with(
        proposer,
        parties,
        settlement_allocations,
        settlement_approver,
        &mut same_entity,
    )
}

/// Canonical per-party reputation result for an arbitrated agreement dispute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum AgreementDisputePartyOutcome {
    Won,
    Lost,
}

/// One explicit party-level dispute reputation effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementDisputeReputationEffect {
    pub party: Address,
    pub outcome: AgreementDisputePartyOutcome,
}

/// Normalize explicit dispute-reputation effects for storage/execution.
pub fn normalize_dispute_reputation_effects<F>(
    parties: &[Address],
    reputation_effects: &[AgreementDisputeReputationEffect],
    mut same_entity: F,
) -> Result<Vec<AgreementDisputeReputationEffect>, String>
where
    F: FnMut(&Address, &Address) -> bool,
{
    let mut seen = std::collections::HashSet::new();
    let mut normalized = Vec::with_capacity(reputation_effects.len());
    let mut saw_winner = false;
    let mut saw_loser = false;

    for effect in reputation_effects {
        if !parties.contains(&effect.party) {
            return Err("Resolution reputation effect party must be a party".into());
        }
        if !seen.insert(effect.party.clone()) {
            return Err("Resolution reputation effects cannot contain duplicate parties".into());
        }
        match effect.outcome {
            AgreementDisputePartyOutcome::Won => saw_winner = true,
            AgreementDisputePartyOutcome::Lost => saw_loser = true,
        }
        normalized.push(effect.clone());
    }

    if !normalized.is_empty() && (!saw_winner || !saw_loser) {
        return Err(
            "Resolution reputation effects must include at least one winner and one loser".into(),
        );
    }

    for index in 0..normalized.len() {
        for other_index in (index + 1)..normalized.len() {
            if same_entity(&normalized[index].party, &normalized[other_index].party) {
                return Err(
                    "Resolution reputation effects cannot target same-entity parties more than once"
                        .into(),
                );
            }
        }
    }

    normalized.sort_by(|lhs, rhs| {
        lhs.party
            .0
            .cmp(&rhs.party.0)
            .then((lhs.outcome as u8).cmp(&(rhs.outcome as u8)))
    });
    Ok(normalized)
}

/// Pick a deterministic opposing counterparty for a reputation event.
pub fn dispute_reputation_counterparty<F>(
    party: &Address,
    outcome: AgreementDisputePartyOutcome,
    reputation_effects: &[AgreementDisputeReputationEffect],
    mut same_entity: F,
) -> Option<Address>
where
    F: FnMut(&Address, &Address) -> bool,
{
    reputation_effects
        .iter()
        .filter(|effect| effect.outcome != outcome && !same_entity(party, &effect.party))
        .map(|effect| effect.party.clone())
        .min_by(|lhs, rhs| lhs.0.cmp(&rhs.0))
}

/// An on-chain agreement between two or more agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agreement {
    /// Unique agreement ID (hash of creation tx).
    pub agreement_id: Hash256,
    /// All parties to the agreement.
    pub parties: Vec<Address>,
    /// The party that proposed the agreement.
    pub proposer: Address,
    /// Serialized terms (JSON or binary).
    pub terms: Vec<u8>,
    /// Total escrow amount in micro-ZIN.
    pub escrow_amount: u64,
    /// Current status.
    pub status: AgreementStatus,
    /// Block at which the agreement was created.
    pub created_at_block: u64,
    /// Expiration timestamp (ms). 0 = no expiry.
    pub expires_at: u64,
    /// Parties that have accepted (for multi-party agreements).
    pub accepted_by: Vec<Address>,
    /// Dispute resolution: address of the designated active registered
    /// arbitrator (if any).
    pub arbitrator: Option<Address>,
    /// Hash of the deliverable/result (set on execution for non-milestone agreements).
    #[serde(default)]
    pub result_hash: Option<Hash256>,
    /// Dispute reason (set when disputed).
    #[serde(default)]
    pub dispute_reason: String,
    /// Which milestone is currently disputed, if any.
    /// `None` means the dispute targets the whole agreement / remaining escrow.
    #[serde(default)]
    pub disputed_milestone_index: Option<u32>,
    /// Timestamp of the active dispute, if any.
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
    /// Whole-agreement dispute resolution details (set by arbitrator).
    /// Milestone dispute outcomes are stored on the resolved milestone instead.
    #[serde(default)]
    pub resolution: Option<DisputeResolution>,
    /// Canonical milestone schedule for cooperative execution and milestone disputes.
    /// Single-payment agreements persist exactly one milestone whose amount equals
    /// the full escrow.
    #[serde(default)]
    pub milestones: Vec<Milestone>,
    /// Amount of escrow already released via completed milestones.
    #[serde(default)]
    pub escrow_released: u64,
    /// Arbitrator fee rate in basis points, locked at creation time.
    /// Deducted from escrow when the arbitrator resolves a dispute.
    #[serde(default)]
    pub arbitrator_fee_bps: u16,
    /// Canonical registered agent accountable for cooperative completion /
    /// expiry reputation and principal-vs-principal dispute semantics.
    /// Cooperative/disputed escrow may still be split across multiple
    /// recipients via settlement allocations, but the service provider must
    /// receive a non-zero cooperative payout share.
    pub service_provider: Address,
    /// Explicit payout allocations applied whenever escrow is cooperatively
    /// released. If omitted, the full escrow defaults to the canonical service
    /// provider.
    #[serde(default)]
    pub settlement_allocations: Vec<AgreementPayoutShare>,
    /// Storage deposit locked for this agreement entry (micro-ZIN).
    /// Refunded to proposer when agreement completes, is cancelled, or expires.
    #[serde(default)]
    pub storage_deposit: u64,
    /// The party explicitly authorized to approve proposer-funded escrow
    /// release. If omitted, settlement defaults to proposer control.
    #[serde(default)]
    pub settlement_approver: Option<Address>,
}

impl Agreement {
    /// Check if all parties have accepted.
    pub fn is_fully_accepted(&self) -> bool {
        self.parties.iter().all(|p| self.accepted_by.contains(p))
    }

    /// Check if the agreement has expired.
    pub fn is_expired(&self, current_time_ms: u64) -> bool {
        self.expires_at > 0 && current_time_ms > self.expires_at
    }

    /// Whether this is a milestone-based agreement.
    pub fn has_milestones(&self) -> bool {
        !self.milestones.is_empty()
    }

    /// Whether all milestones are completed.
    pub fn all_milestones_complete(&self) -> bool {
        !self.milestones.is_empty()
            && self.milestones.iter().all(|m| {
                m.status == MilestoneStatus::Completed || m.status == MilestoneStatus::Resolved
            })
    }

    /// Remaining escrow (not yet released).
    pub fn escrow_remaining(&self) -> u64 {
        self.escrow_amount.saturating_sub(self.escrow_released)
    }

    /// Record a partial escrow release while preventing the persisted counter
    /// from ever drifting above the original escrow amount.
    pub fn record_escrow_release(&mut self, amount: u64) {
        self.escrow_released = self
            .escrow_released
            .saturating_add(amount)
            .min(self.escrow_amount);
    }

    /// Mark all remaining escrow as settled for whole-agreement completion or
    /// resolution flows.
    pub fn release_remaining_escrow(&mut self) {
        self.escrow_released = self.escrow_amount;
    }

    /// Clear all active dispute-tracking fields.
    pub fn clear_dispute_state(&mut self) {
        self.dispute_reason.clear();
        self.disputed_milestone_index = None;
        self.disputed_at = None;
        self.arbitration_deadline_at = None;
        self.arbitration_reassignments = 0;
        self.prior_arbitrators.clear();
    }

    /// Normalize the stored agreement after expiry/refund so it no longer
    /// reports active dispute or locked-deposit metadata.
    pub fn normalize_for_expiry(&mut self) {
        self.status = AgreementStatus::Expired;
        self.storage_deposit = 0;
        self.clear_dispute_state();
    }

    /// The address currently authorized to release escrow on-chain.
    pub fn settlement_approver(&self) -> &Address {
        self.settlement_approver.as_ref().unwrap_or(&self.proposer)
    }

    /// Canonical service-side registered agent for completion, expiry, and
    /// dispute semantics.
    pub fn service_provider(&self) -> &Address {
        &self.service_provider
    }

    /// Effective payout allocations used for cooperative execution and
    /// default single-recipient settlement.
    pub fn effective_settlement_allocations(&self) -> Vec<AgreementPayoutShare> {
        if !self.settlement_allocations.is_empty() {
            return self.settlement_allocations.clone();
        }
        vec![AgreementPayoutShare {
            recipient: self.service_provider.clone(),
            share_bps: 10_000,
        }]
    }

    /// Settlement recipients in stored order.
    pub fn settlement_recipients(&self) -> Vec<Address> {
        self.effective_settlement_allocations()
            .into_iter()
            .map(|share| share.recipient)
            .collect()
    }

    /// Move top-level milestone resolution data into the milestone itself.
    pub fn normalize_resolution_storage(&mut self) {
        let Some(resolution) = self.resolution.clone() else {
            return;
        };
        let Some(milestone_index) = resolution.milestone_index else {
            return;
        };
        if let Some(milestone) = self.milestones.get_mut(milestone_index as usize) {
            if milestone.resolution.is_none() {
                milestone.resolution = Some(resolution);
            }
            self.resolution = None;
        }
    }

    /// Record a milestone-scoped dispute outcome and keep the top-level slot
    /// reserved for whole-agreement resolutions only.
    pub fn record_milestone_resolution(
        &mut self,
        milestone_index: u32,
        resolution: DisputeResolution,
    ) {
        self.normalize_resolution_storage();
        if let Some(milestone) = self.milestones.get_mut(milestone_index as usize) {
            milestone.resolution = Some(resolution);
        }
        self.resolution = None;
    }

    /// Record a whole-agreement dispute outcome.
    pub fn record_whole_agreement_resolution(&mut self, resolution: DisputeResolution) {
        self.normalize_resolution_storage();
        self.resolution = Some(resolution);
    }

    /// Fetch the canonical stored dispute resolution for the requested scope.
    pub fn resolution_for(&self, milestone_index: Option<u32>) -> Option<&DisputeResolution> {
        match milestone_index {
            Some(index) => self
                .milestones
                .get(index as usize)
                .and_then(|milestone| milestone.resolution.as_ref()),
            None => self.resolution.as_ref(),
        }
    }

    /// Split a released escrow amount deterministically across payout shares.
    /// All rounding dust goes to the last recipient so funds are conserved.
    pub fn distribute_amount(
        amount: u64,
        allocations: &[AgreementPayoutShare],
    ) -> Vec<(Address, u64)> {
        if allocations.is_empty() {
            return Vec::new();
        }

        let mut distributed = 0u64;
        let mut payouts = Vec::with_capacity(allocations.len());
        for (index, allocation) in allocations.iter().enumerate() {
            let payout_amount = if index + 1 == allocations.len() {
                amount.saturating_sub(distributed)
            } else {
                (amount as u128 * allocation.share_bps as u128 / 10_000) as u64
            };
            distributed = distributed.saturating_add(payout_amount);
            payouts.push((allocation.recipient.clone(), payout_amount));
        }
        payouts
    }

    /// Look up a recipient amount in a previously computed payout vector.
    pub fn payout_amount_for_recipient(payouts: &[(Address, u64)], recipient: &Address) -> u64 {
        payouts
            .iter()
            .find(|(candidate, _)| candidate == recipient)
            .map(|(_, amount)| *amount)
            .unwrap_or(0)
    }
}

/// Dispute resolution outcome from the arbitrator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeResolution {
    /// Canonical payout allocations for this resolution. New resolutions always
    /// persist this exact N-way shape.
    #[serde(default)]
    pub payouts: Vec<AgreementPayoutShare>,
    /// Canonical per-party dispute reputation effects for this resolution.
    #[serde(default)]
    pub reputation_effects: Vec<AgreementDisputeReputationEffect>,
    /// Arbitrator's reasoning.
    pub reason: String,
    /// Block when resolved.
    pub resolved_at_block: u64,
    /// Which milestone this resolution applied to, if any.
    #[serde(default)]
    pub milestone_index: Option<u32>,
}

impl DisputeResolution {
    pub fn new(
        payouts: Vec<AgreementPayoutShare>,
        mut reputation_effects: Vec<AgreementDisputeReputationEffect>,
        reason: String,
        resolved_at_block: u64,
        milestone_index: Option<u32>,
    ) -> Self {
        reputation_effects.sort_by(|lhs, rhs| {
            lhs.party
                .0
                .cmp(&rhs.party.0)
                .then((lhs.outcome as u8).cmp(&(rhs.outcome as u8)))
        });
        Self {
            payouts,
            reputation_effects,
            reason,
            resolved_at_block,
            milestone_index,
        }
    }
}

/// Data payload for AgreementCreate transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgreementCreateData {
    pub parties: Vec<Address>,
    pub terms: Vec<u8>,
    pub escrow_amount: u64,
    pub expires_at: u64,
    /// Optional active registered arbitrator for this agreement.
    /// If omitted, the protocol may assign one when needed.
    pub arbitrator: Option<Address>,
    /// Canonical milestone schedule. Single-payment agreements must provide one
    /// milestone whose amount equals `escrow_amount`.
    #[serde(default)]
    pub milestones: Vec<MilestoneDef>,
    /// Canonical registered agent accountable for cooperative agreement
    /// reputation.
    pub service_provider: Address,
    /// Explicit cooperative settlement allocations. When present, these drive
    /// N-way payout economics for execute/expiry flows.
    #[serde(default)]
    pub settlement_allocations: Vec<AgreementPayoutShare>,
    /// Explicit party authorized to release proposer-funded escrow.
    /// If None:
    ///   2 parties → defaults to proposer
    ///   3+ parties → required (creation fails without it)
    #[serde(default)]
    pub settlement_approver: Option<Address>,
}

pub fn validate_agreement_create_stateless<F>(
    proposer: &Address,
    data: &AgreementCreateData,
    mut same_entity: F,
) -> Result<(), String>
where
    F: FnMut(&Address, &Address) -> bool,
{
    if data.parties.len() < 2 {
        return Err("Agreement requires at least 2 parties".into());
    }
    if data.parties.len() > 10 {
        return Err(format!("Too many parties: {} > 10", data.parties.len()));
    }
    if !data.parties.contains(proposer) {
        return Err("Proposer must be a party".into());
    }

    let mut seen_parties = std::collections::HashSet::new();
    for party in &data.parties {
        if !seen_parties.insert(party.clone()) {
            return Err(format!("Duplicate party: {}", party));
        }
    }

    if data.escrow_amount == 0 {
        return Err("Escrow amount must be > 0".into());
    }
    if data.terms.len() > 65_536 {
        return Err(format!("Terms too large: {} > 65536", data.terms.len()));
    }

    materialize_agreement_milestones(&data.milestones, data.escrow_amount)?;

    if let Some(arbitrator) = data.arbitrator.as_ref() {
        if data.parties.contains(arbitrator) {
            return Err("Arbitrator cannot be a party".into());
        }
        for party in &data.parties {
            if same_entity(arbitrator, party) {
                return Err("Arbitrator cannot be same entity as a party".into());
            }
        }
    }

    if !data.parties.contains(&data.service_provider) {
        return Err("Service provider must be a party".into());
    }
    if !agreement_service_provider_involves_third_party_with(
        proposer,
        &data.service_provider,
        &mut same_entity,
    ) {
        return Err("Service provider cannot be the proposer or same entity".into());
    }

    let settlement_allocations = resolve_agreement_settlement_allocations_with(
        proposer,
        &data.parties,
        &data.service_provider,
        &data.settlement_allocations,
        &mut same_entity,
    )?;
    let _settlement_approver = resolve_agreement_settlement_approver_with(
        proposer,
        &data.parties,
        &settlement_allocations,
        data.settlement_approver.as_ref(),
        &mut same_entity,
    )?;

    Ok(())
}

/// Data payload for AgreementAccept transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgreementAcceptData {
    pub agreement_id: Hash256,
}

/// Data payload for AgreementExecute transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgreementExecuteData {
    pub agreement_id: Hash256,
    /// Hash of the deliverable/result.
    pub result_hash: Hash256,
    /// Must be submitted by the agreement's settlement approver.
    /// Canonical agreements always execute one explicit milestone (0-based index).
    pub milestone_index: u32,
}

/// Data payload for AgreementDispute transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgreementDisputeData {
    pub agreement_id: Hash256,
    /// Reason for the dispute.
    pub reason: String,
    /// For milestone agreements: which milestone to dispute (None = whole agreement).
    #[serde(default)]
    pub milestone_index: Option<u32>,
}

/// Data payload for AgreementResolve transactions (arbitrator only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgreementResolveData {
    pub agreement_id: Hash256,
    /// Canonical payout allocations for this resolution.
    pub payouts: Vec<AgreementPayoutShare>,
    /// Canonical per-party dispute reputation effects for this resolution.
    #[serde(default)]
    pub reputation_effects: Vec<AgreementDisputeReputationEffect>,
    /// Arbitrator's reasoning.
    pub reason: String,
    /// Which milestone this resolution applies to (None = whole agreement).
    #[serde(default)]
    pub milestone_index: Option<u32>,
}

/// Data payload for AgreementCancel transactions (proposer only, before acceptance).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgreementCancelData {
    pub agreement_id: Hash256,
}

// ═══════════════════════════════════════════════════════════════
// Arbitrator System
// ═══════════════════════════════════════════════════════════════

/// On-chain arbitrator profile. Agents register as arbitrators by staking
/// ZIN and declaring their fee rate and specializations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArbitratorProfile {
    /// The arbitrator's on-chain address.
    pub address: Address,
    /// Human-readable name.
    pub name: String,
    /// Description of arbitration expertise.
    pub description: String,
    /// Amount staked as collateral (micro-ZIN). Slashable for misconduct.
    pub stake: u64,
    /// Fee rate in basis points (1 bps = 0.01%). Applied to escrow at resolution.
    /// Example: 300 bps = 3% of escrow goes to arbitrator.
    pub fee_bps: u16,
    /// Domain specializations (e.g., "ai.data", "finance", "legal").
    pub specializations: Vec<String>,
    /// Whether this arbitrator is currently accepting disputes.
    pub active: bool,
    /// Total disputes resolved.
    pub disputes_resolved: u64,
    /// Total disputes where ruling was not challenged.
    pub rulings_upheld: u64,
    /// Total disputes that timed out without a ruling.
    #[serde(default)]
    pub disputes_missed: u64,
    /// Total fees earned (micro-ZIN).
    pub total_fees_earned: u64,
    /// Registration timestamp (ms).
    pub registered_at: u64,
    /// Last activity timestamp (ms).
    pub last_active: u64,
    /// Storage deposit locked for this arbitrator entry (micro-ZIN).
    /// Refunded when arbitrator deregisters.
    #[serde(default)]
    pub storage_deposit: u64,
}

impl ArbitratorProfile {
    /// Reputation score for arbitrator selection (0-100).
    /// Factors: stake, track record, upheld rate, activity.
    pub fn selection_score(&self) -> f64 {
        let stake_score = (self.stake as f64 / 10_000_000.0).min(30.0); // max 30 at 10 ZIN
        let volume_score = ((self.disputes_resolved as f64 + 1.0).ln() * 10.0).min(25.0);
        let upheld_rate = if self.disputes_resolved > 0 {
            self.rulings_upheld as f64 / self.disputes_resolved as f64
        } else {
            0.5 // neutral for new arbitrators
        };
        let upheld_score = upheld_rate * 30.0;
        let fee_score = (1.0 - (self.fee_bps as f64 / 1000.0).min(1.0)) * 15.0; // lower fee = higher score
        let missed_penalty = ((self.disputes_missed as f64 + 1.0).ln() * 8.0).min(20.0);

        (stake_score + volume_score + upheld_score + fee_score - missed_penalty).max(0.0)
    }
}

/// Data payload for ArbitratorRegister transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArbitratorRegisterData {
    pub name: String,
    pub description: String,
    /// Stake amount in micro-ZIN (minimum enforced by protocol).
    pub stake: u64,
    /// Fee rate in basis points.
    pub fee_bps: u16,
    /// Domain specializations.
    pub specializations: Vec<String>,
}

/// Minimum stake required to register as an arbitrator (5 ZIN).
pub const MIN_ARBITRATOR_STAKE: u64 = 5_000_000;

#[cfg(test)]
mod tests {
    use super::{
        canonical_single_payment_milestones, validate_agreement_create_stateless,
        AgreementCreateData,
    };
    use crate::crypto::Keypair;

    #[test]
    fn validate_agreement_create_stateless_rejects_service_provider_same_as_proposer() {
        let proposer = Keypair::generate().address();
        let counterparty = Keypair::generate().address();
        let data = AgreementCreateData {
            parties: vec![proposer.clone(), counterparty],
            terms: b"T".to_vec(),
            escrow_amount: 1_000_000,
            expires_at: 1,
            arbitrator: None,
            milestones: canonical_single_payment_milestones(1_000_000),
            service_provider: proposer.clone(),
            settlement_allocations: vec![],
            settlement_approver: None,
        };

        let err = validate_agreement_create_stateless(&proposer, &data, |lhs, rhs| lhs == rhs)
            .expect_err("service provider equal to proposer must be rejected");
        assert!(
            err.contains("Service provider cannot be the proposer"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_agreement_create_stateless_rejects_exact_party_arbitrator_before_entity_check() {
        let proposer = Keypair::generate().address();
        let counterparty = Keypair::generate().address();
        let data = AgreementCreateData {
            parties: vec![proposer.clone(), counterparty.clone()],
            terms: b"T".to_vec(),
            escrow_amount: 1_000_000,
            expires_at: 1,
            arbitrator: Some(counterparty),
            milestones: canonical_single_payment_milestones(1_000_000),
            service_provider: proposer.clone(),
            settlement_allocations: vec![],
            settlement_approver: None,
        };

        let err = validate_agreement_create_stateless(&proposer, &data, |lhs, rhs| lhs == rhs)
            .expect_err("party arbitrator must be rejected explicitly");
        assert_eq!(err, "Arbitrator cannot be a party");
    }

    #[test]
    fn validate_agreement_create_stateless_rejects_empty_milestones() {
        let proposer = Keypair::generate().address();
        let counterparty = Keypair::generate().address();
        let data = AgreementCreateData {
            parties: vec![proposer.clone(), counterparty.clone()],
            terms: b"T".to_vec(),
            escrow_amount: 1_000_000,
            expires_at: 1,
            arbitrator: None,
            milestones: vec![],
            service_provider: counterparty,
            settlement_allocations: vec![],
            settlement_approver: None,
        };

        let err = validate_agreement_create_stateless(&proposer, &data, |lhs, rhs| lhs == rhs)
            .expect_err("empty milestones must be rejected");
        assert!(
            err.contains("requires at least one milestone"),
            "unexpected error: {err}"
        );
    }
}
