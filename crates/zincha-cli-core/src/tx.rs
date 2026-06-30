use crate::output::emit;
use crate::secret::{load_keypair, load_secret_key, KeySourceArgs};
use crate::support::{
    now_millis, parse_address, parse_capabilities, parse_hash, parse_hex_bytes, parse_public_key,
    read_hex_or_file, read_json_file, write_private_file,
};
use crate::CliContext;
use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;
use zincha_client::{OrderflowBundleOptions, ProtectedSubmitOptions, ZinchaClient};
use zincha_primitives::crypto::{Address, Hash256};
use zincha_primitives::primitives::agreement::AgreementDisputeReputationEffect;
use zincha_primitives::primitives::{
    AgreementPayoutShare, ContractAbi, ContractSourceProof, HttpToolSettlementMode,
    MatchPreferences, SignedTransaction, StakeTarget, SubTaskDef, SubscriptionOveragePolicy,
    ToolArbitrationPolicy, ToolMilestoneDef, ToolSubscriptionPlanUpdateData, ToolUpdateData,
    ValidatorExecutorService, ValidatorUpdateData,
};
use zincha_primitives::wallet::AgentWallet;

const DEFAULT_CHAIN_ID: &str = "zincha-vega-1";
const DEFAULT_TX_FEE: u64 = 500_000;
const DEFAULT_TTL_BLOCKS: u64 = 128;
const DEFAULT_TOOL_SLA_MS: u64 = 3_600_000;
const DEFAULT_TOOL_CHALLENGE_WINDOW_MS: u64 = 900_000;
const DEFAULT_TOOL_MAX_RESULT_METADATA_BYTES: u32 = 4_096;

macro_rules! wallet_result {
    ($expr:expr) => {
        Ok($expr?)
    };
}

#[derive(Debug, Parser)]
pub struct TxCommand {
    #[command(subcommand)]
    pub command: TxCommands,
}

#[derive(Args, Clone, Debug, Default)]
pub struct TxBuildArgs {
    #[command(flatten)]
    pub key_source: KeySourceArgs,
    #[arg(long)]
    pub nonce: Option<u64>,
    #[arg(long)]
    pub chain_id: Option<String>,
    #[arg(long)]
    pub timestamp_ms: Option<u64>,
    #[arg(long)]
    pub reference_block_height: Option<u64>,
    #[arg(long)]
    pub reference_block_hash: Option<String>,
    #[arg(long)]
    pub ttl_blocks: Option<u64>,
    #[arg(long)]
    pub offline: bool,
    #[arg(long)]
    pub submit: bool,
    #[arg(long)]
    pub wait: bool,
    #[arg(long, default_value_t = 45)]
    pub wait_timeout_secs: u64,
    #[arg(long, default_value_t = 500)]
    pub wait_interval_ms: u64,
    #[arg(long)]
    pub signed_tx_out: Option<PathBuf>,
    #[arg(long)]
    pub force: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum StakeTargetArg {
    Agent,
    Validator,
    RequesterAutoMatch,
}

impl From<StakeTargetArg> for StakeTarget {
    fn from(value: StakeTargetArg) -> Self {
        match value {
            StakeTargetArg::Agent => StakeTarget::Agent,
            StakeTargetArg::Validator => StakeTarget::Validator,
            StakeTargetArg::RequesterAutoMatch => StakeTarget::RequesterAutoMatch,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum TxCommands {
    SubmitSigned {
        #[arg(long, conflicts_with = "signed_tx_file")]
        signed_tx_hex: Option<String>,
        #[arg(long, conflicts_with = "signed_tx_hex")]
        signed_tx_file: Option<PathBuf>,
    },
    SubmitBatch {
        #[arg(long = "signed-tx-hex")]
        signed_tx_hexes: Vec<String>,
        #[arg(long = "signed-tx-file")]
        signed_tx_files: Vec<PathBuf>,
    },
    SubmitProtected {
        #[arg(long, conflicts_with = "signed_tx_file")]
        signed_tx_hex: Option<String>,
        #[arg(long, conflicts_with = "signed_tx_hex")]
        signed_tx_file: Option<PathBuf>,
        #[arg(long)]
        max_priority_fee_per_gas: Option<u64>,
    },
    SubmitBundle {
        #[arg(long = "signed-tx-hex")]
        signed_tx_hexes: Vec<String>,
        #[arg(long = "signed-tx-file")]
        signed_tx_files: Vec<PathBuf>,
        #[arg(long, default_value_t = true)]
        atomic: bool,
        #[arg(long)]
        expiration_height: Option<u64>,
        #[arg(long)]
        max_total_fee: Option<u64>,
        #[arg(long)]
        max_priority_fee_per_gas: Option<u64>,
    },
    Wait {
        tx_hash: String,
        #[arg(long, default_value_t = 45)]
        timeout_secs: u64,
        #[arg(long, default_value_t = 500)]
        poll_interval_ms: u64,
    },
    Transfer {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long, alias = "recipient")]
        to: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
        #[arg(long)]
        max_priority_fee_per_gas: Option<u64>,
    },
    EntityLink {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        entity: String,
        #[arg(long)]
        authorizer_secret_key: String,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    RegisterAgent {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "")]
        description: String,
        #[arg(long = "capability")]
        capabilities: Vec<String>,
        #[arg(long)]
        model_hash: Option<String>,
        #[arg(long)]
        min_fee: Option<u64>,
        #[arg(long)]
        fee_schedule_file: Option<PathBuf>,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    UpdateAgent {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        model_hash: Option<String>,
        #[arg(long = "capability")]
        capabilities: Vec<String>,
        #[arg(long)]
        metadata_hex: Option<String>,
        #[arg(long)]
        active: Option<bool>,
        #[arg(long)]
        min_fee: Option<u64>,
        #[arg(long)]
        fee_schedule_file: Option<PathBuf>,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    DeregisterAgent {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    BondRequesterAutoMatch {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    SubmitTask {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        description: String,
        #[arg(long = "capability")]
        capabilities: Vec<String>,
        #[arg(long)]
        max_fee: u64,
        #[arg(long, default_value_t = 5)]
        priority: u8,
        #[arg(long)]
        deadline_ms: Option<u64>,
        #[arg(long)]
        parameters_hex: Option<String>,
        #[arg(long)]
        match_prefs_file: Option<PathBuf>,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    FulfillTask {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        task_id: String,
        #[arg(long)]
        result_hash: Option<String>,
        #[arg(long)]
        result_data_hex: Option<String>,
        #[arg(long = "tool-id")]
        tools_used: Vec<String>,
        #[arg(long = "input-ref")]
        input_refs: Vec<String>,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    AcceptTask {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        task_id: String,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    DisputeTask {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        task_id: String,
        #[arg(long)]
        reason: String,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    ResolveTask {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        task_id: String,
        #[arg(long)]
        agent_wins: bool,
        #[arg(long)]
        reason: String,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    FinalizeTask {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        task_id: String,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    CancelTask {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        task_id: String,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    DecomposeTask {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        task_id: String,
        #[arg(long)]
        subtasks_file: PathBuf,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    UpdateReputation {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        task_id: String,
        #[arg(long)]
        quality: f64,
        #[arg(long)]
        requester_accepted: bool,
        #[arg(long)]
        feedback: Option<String>,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    RegisterValidator {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        stake: u64,
        #[arg(long)]
        vrf_public_key: Option<String>,
        #[arg(long)]
        executor_services_file: Option<PathBuf>,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    UpdateValidator {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        vrf_public_key: Option<String>,
        #[arg(long)]
        executor_services_file: Option<PathBuf>,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    Stake {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long, value_enum)]
        target: StakeTargetArg,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    Unstake {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long, value_enum)]
        target: StakeTargetArg,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    ExitValidator {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    RegisterTool {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "")]
        description: String,
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        price: u64,
        #[arg(long = "capability")]
        capabilities: Vec<String>,
        #[arg(long, default_value = "prepaid_access")]
        settlement_mode: String,
        #[arg(long, default_value_t = DEFAULT_TOOL_SLA_MS)]
        sla_ms: u64,
        #[arg(long, default_value_t = DEFAULT_TOOL_CHALLENGE_WINDOW_MS)]
        challenge_window_ms: u64,
        #[arg(long, default_value_t = DEFAULT_TOOL_MAX_RESULT_METADATA_BYTES)]
        max_result_metadata_bytes: u32,
        #[arg(long, default_value = "protocol")]
        arbitration_policy: String,
        #[arg(long, default_value = "1.0.0")]
        version: String,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    InvokeTool {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        tool_id: String,
        #[arg(long)]
        input_hex: Option<String>,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    InvokeMeteredTool {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        tool_id: String,
        #[arg(long)]
        input_hex: Option<String>,
        #[arg(long)]
        max_units: u64,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    InvokeMilestoneTool {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        tool_id: String,
        #[arg(long)]
        input_hex: Option<String>,
        #[arg(long)]
        milestones_file: PathBuf,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    SubmitToolResult {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        job_id: String,
        #[arg(long)]
        result_hash: Option<String>,
        #[arg(long)]
        result_metadata_hex: Option<String>,
        #[arg(long)]
        milestone_index: Option<u32>,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    AcceptToolResult {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        job_id: String,
        #[arg(long)]
        milestone_index: Option<u32>,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    DisputeToolResult {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        job_id: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        milestone_index: Option<u32>,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    ResolveToolResult {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        job_id: String,
        #[arg(long)]
        provider_wins: bool,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        milestone_index: Option<u32>,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    ReportToolUsage {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        units_used: u64,
        #[arg(long)]
        result_hash: Option<String>,
        #[arg(long)]
        result_metadata_hex: Option<String>,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    AcceptToolUsage {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        session_id: String,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    DisputeToolUsage {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        reason: String,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    ResolveToolUsage {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        provider_wins: bool,
        #[arg(long)]
        reason: String,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    CreateToolSubscriptionPlan {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        tool_id: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        price_per_period: u64,
        #[arg(long)]
        period_ms: u64,
        #[arg(long, default_value_t = 0)]
        included_calls: u32,
        #[arg(long, default_value_t = 0)]
        included_credits: u64,
        #[arg(long, default_value = "deny")]
        overage_policy: String,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    UpdateToolSubscriptionPlan {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        plan_id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        price_per_period: Option<u64>,
        #[arg(long)]
        period_ms: Option<u64>,
        #[arg(long)]
        included_calls: Option<u32>,
        #[arg(long)]
        included_credits: Option<u64>,
        #[arg(long)]
        overage_policy: Option<String>,
        #[arg(long)]
        active: Option<bool>,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    StartToolSubscription {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        plan_id: String,
        #[arg(long, default_value_t = 0)]
        reserve_amount: u64,
        #[arg(long, default_value_t = true)]
        auto_renew: bool,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    TopUpToolSubscription {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        subscription_id: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    CancelToolSubscription {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        subscription_id: String,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    ResumeToolSubscription {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        subscription_id: String,
        #[arg(long, default_value_t = 0)]
        reserve_amount: u64,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    RenewToolSubscription {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        subscription_id: String,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    UpdateTool {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        tool_id: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        price_per_call: Option<u64>,
        #[arg(long)]
        settlement_mode: Option<String>,
        #[arg(long)]
        active: Option<bool>,
        #[arg(long = "capability")]
        capabilities: Vec<String>,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    DeregisterTool {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        tool_id: String,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    CreateAgreement {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long = "party")]
        parties: Vec<String>,
        #[arg(long)]
        terms_hex: Option<String>,
        #[arg(long)]
        escrow_amount: u64,
        #[arg(long, default_value_t = 0)]
        expires_at: u64,
        #[arg(long)]
        arbitrator: Option<String>,
        #[arg(long)]
        milestones_file: Option<PathBuf>,
        #[arg(long)]
        service_provider: String,
        #[arg(long)]
        settlement_allocations_file: Option<PathBuf>,
        #[arg(long)]
        settlement_approver: Option<String>,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    AcceptAgreement {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        agreement_id: String,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    ExecuteAgreement {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        agreement_id: String,
        #[arg(long)]
        result_hash: String,
        #[arg(long)]
        milestone_index: Option<u32>,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    DisputeAgreement {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        agreement_id: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        milestone_index: Option<u32>,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    ResolveAgreement {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        agreement_id: String,
        #[arg(long)]
        payouts_file: PathBuf,
        #[arg(long)]
        reputation_effects_file: Option<PathBuf>,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        milestone_index: Option<u32>,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    CancelAgreement {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        agreement_id: String,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    RegisterArbitrator {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "")]
        description: String,
        #[arg(long)]
        stake: u64,
        #[arg(long)]
        fee_bps: u16,
        #[arg(long = "specialization")]
        specializations: Vec<String>,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    DeregisterArbitrator {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    DeployContract {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        bytecode_hex: Option<String>,
        #[arg(long)]
        bytecode_file: Option<PathBuf>,
        #[arg(long, default_value_t = 0)]
        initial_balance: u64,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    CallContract {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        contract_address: String,
        #[arg(long)]
        function: String,
        #[arg(long)]
        args_hex: Option<String>,
        #[arg(long, default_value_t = 0)]
        call_value: u64,
        #[arg(long, default_value_t = 1_000_000)]
        gas_limit: u64,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    CallContractRoute {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        deployer: String,
        #[arg(long)]
        route_name: String,
        #[arg(long)]
        function: String,
        #[arg(long)]
        args_hex: Option<String>,
        #[arg(long, default_value_t = 0)]
        call_value: u64,
        #[arg(long, default_value_t = 1_000_000)]
        gas_limit: u64,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    UpdateContractRoute {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        route_name: String,
        #[arg(long)]
        target_contract_address: String,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    VerifyContractSource {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        contract_address: String,
        #[arg(long)]
        proof_file: PathBuf,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    PublishContractAbi {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        contract_address: String,
        #[arg(long)]
        abi_file: PathBuf,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    DeactivateContract {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        contract_address: String,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    CreateToken {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        name: String,
        #[arg(long)]
        symbol: String,
        #[arg(long)]
        decimals: u8,
        #[arg(long)]
        initial_supply: u64,
        #[arg(long)]
        max_supply: Option<u64>,
        #[arg(long)]
        mint_authority: Option<String>,
        #[arg(long, default_value_t = true)]
        burnable: bool,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    TransferToken {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        token_id: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    ApproveToken {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        token_id: String,
        #[arg(long)]
        spender: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    MintToken {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        token_id: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    UpdateTokenMintAuthority {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        token_id: String,
        #[arg(long)]
        mint_authority: Option<String>,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    BurnToken {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        token_id: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    DestroyToken {
        #[command(flatten)]
        build: TxBuildArgs,
        #[arg(long)]
        token_id: String,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
}

pub async fn run_tx(command: TxCommand, client: ZinchaClient, context: &CliContext) -> Result<()> {
    match command.command {
        TxCommands::SubmitSigned {
            signed_tx_hex,
            signed_tx_file,
        } => {
            let signed_tx_hex = read_hex_or_file(&signed_tx_hex, &signed_tx_file)?;
            emit(
                "tx-submit-signed",
                client.submit_signed_transaction_hex(&signed_tx_hex).await?,
                context.json,
            )
        }
        TxCommands::SubmitBatch {
            signed_tx_hexes,
            signed_tx_files,
        } => {
            let signed_txs_hex = collect_signed_hexes(signed_tx_hexes, signed_tx_files)?;
            emit(
                "tx-submit-batch",
                client.submit_batch(signed_txs_hex).await?,
                context.json,
            )
        }
        TxCommands::SubmitProtected {
            signed_tx_hex,
            signed_tx_file,
            max_priority_fee_per_gas,
        } => {
            let token = require_bearer(context)?;
            let signed_tx_hex = read_hex_or_file(&signed_tx_hex, &signed_tx_file)?;
            emit(
                "tx-submit-protected",
                client
                    .submit_protected(
                        signed_tx_hex,
                        ProtectedSubmitOptions {
                            bearer_token: Some(token),
                            max_priority_fee_per_gas,
                        },
                    )
                    .await?,
                context.json,
            )
        }
        TxCommands::SubmitBundle {
            signed_tx_hexes,
            signed_tx_files,
            atomic,
            expiration_height,
            max_total_fee,
            max_priority_fee_per_gas,
        } => {
            let token = require_bearer(context)?;
            let signed_txs_hex = collect_signed_hexes(signed_tx_hexes, signed_tx_files)?;
            emit(
                "tx-submit-bundle",
                client
                    .submit_orderflow_bundle(
                        signed_txs_hex,
                        OrderflowBundleOptions {
                            bearer_token: Some(token),
                            atomic,
                            expiration_height,
                            max_total_fee,
                            max_priority_fee_per_gas,
                        },
                    )
                    .await?,
                context.json,
            )
        }
        TxCommands::Wait {
            tx_hash,
            timeout_secs,
            poll_interval_ms,
        } => {
            let payload = client
                .wait_for_transaction(
                    &tx_hash,
                    Duration::from_secs(timeout_secs),
                    Duration::from_millis(poll_interval_ms),
                )
                .await?;
            emit("tx-wait", payload, context.json)
        }
        other => {
            let (label, signed, build) = build_signed_transaction(other, &client).await?;
            finish_transaction(label, signed, &build, client, context).await
        }
    }
}

async fn build_signed_transaction(
    command: TxCommands,
    client: &ZinchaClient,
) -> Result<(&'static str, SignedTransaction, TxBuildArgs)> {
    match command {
        TxCommands::Transfer {
            build,
            to,
            amount,
            fee,
            max_priority_fee_per_gas,
        } => {
            let mut wallet = resolve_wallet(&build, client).await?;
            let recipient = parse_address(&to)?;
            let signed = match max_priority_fee_per_gas {
                Some(priority) => {
                    wallet.build_transfer_with_priority_fee(recipient, amount, fee, priority)?
                }
                None => wallet.build_transfer(recipient, amount, fee)?,
            };
            Ok(("tx-transfer", signed, build))
        }
        TxCommands::EntityLink {
            build,
            entity,
            authorizer_secret_key,
            fee,
        } => {
            let mut wallet = resolve_wallet(&build, client).await?;
            let authorizer = load_secret_key(&authorizer_secret_key)?;
            Ok((
                "tx-entity-link",
                wallet.build_entity_link(parse_address(&entity)?, &authorizer, fee)?,
                build,
            ))
        }
        TxCommands::RegisterAgent {
            build,
            name,
            description,
            capabilities,
            model_hash,
            min_fee,
            fee_schedule_file,
            fee,
        } => {
            let mut wallet = resolve_wallet(&build, client).await?;
            let fee_schedule = fee_schedule_file
                .map(|path| read_json_file(&path))
                .transpose()?
                .unwrap_or_default();
            let model_hash = match model_hash {
                Some(hash) => parse_hash(&hash)?,
                None => Hash256::zero(),
            };
            Ok((
                "tx-register-agent",
                wallet.build_register_agent_full(
                    &name,
                    &description,
                    parse_capabilities(capabilities)?,
                    model_hash,
                    min_fee.unwrap_or(0),
                    fee_schedule,
                    fee,
                )?,
                build,
            ))
        }
        TxCommands::UpdateAgent {
            build,
            name,
            description,
            model_hash,
            capabilities,
            metadata_hex,
            active,
            min_fee,
            fee_schedule_file,
            fee,
        } => {
            let mut wallet = resolve_wallet(&build, client).await?;
            let model_hash = model_hash.map(|hash| parse_hash(&hash)).transpose()?;
            let caps = (!capabilities.is_empty())
                .then(|| parse_capabilities(capabilities))
                .transpose()?;
            let metadata = metadata_hex
                .as_deref()
                .map(|hex| parse_hex_bytes(Some(hex)))
                .transpose()?;
            let fee_schedule = fee_schedule_file
                .map(|path| read_json_file(&path))
                .transpose()?;
            Ok((
                "tx-update-agent",
                wallet.build_update_agent_full(
                    name,
                    description,
                    None,
                    model_hash,
                    caps,
                    metadata,
                    active,
                    min_fee,
                    fee_schedule,
                    fee,
                )?,
                build,
            ))
        }
        TxCommands::DeregisterAgent { build, fee } => {
            let mut wallet = resolve_wallet(&build, client).await?;
            Ok((
                "tx-deregister-agent",
                wallet.build_deregister_agent(fee)?,
                build,
            ))
        }
        TxCommands::BondRequesterAutoMatch { build, amount, fee } => {
            let mut wallet = resolve_wallet(&build, client).await?;
            Ok((
                "tx-bond-requester-auto-match",
                wallet.build_requester_auto_match_bond(amount, fee)?,
                build,
            ))
        }
        TxCommands::SubmitTask {
            build,
            description,
            capabilities,
            max_fee,
            priority,
            deadline_ms,
            parameters_hex,
            match_prefs_file,
            fee,
        } => {
            let mut wallet = resolve_wallet(&build, client).await?;
            let deadline = deadline_ms.unwrap_or(now_millis()? + 600_000);
            let parameters = parse_hex_bytes(parameters_hex.as_deref())?;
            let prefs: Option<MatchPreferences> = match_prefs_file
                .map(|path| read_json_file(&path))
                .transpose()?;
            let signed = match prefs {
                Some(prefs) => wallet.build_submit_task_with_prefs(
                    &description,
                    parse_capabilities(capabilities)?,
                    max_fee,
                    priority,
                    deadline,
                    parameters,
                    fee,
                    prefs,
                )?,
                None => wallet.build_submit_task(
                    &description,
                    parse_capabilities(capabilities)?,
                    max_fee,
                    priority,
                    deadline,
                    parameters,
                    fee,
                )?,
            };
            Ok(("tx-submit-task", signed, build))
        }
        TxCommands::FulfillTask {
            build,
            task_id,
            result_hash,
            result_data_hex,
            tools_used,
            input_refs,
            fee,
        } => {
            let mut wallet = resolve_wallet(&build, client).await?;
            Ok((
                "tx-fulfill-task",
                wallet.build_fulfill_task(
                    parse_hash(&task_id)?,
                    parse_optional_hash(result_hash)?,
                    parse_hex_bytes(result_data_hex.as_deref())?,
                    parse_hashes(tools_used)?,
                    parse_hashes(input_refs)?,
                    fee,
                )?,
                build,
            ))
        }
        TxCommands::AcceptTask {
            build,
            task_id,
            fee,
        } => {
            simple(build, client, "tx-accept-task", |wallet| {
                wallet_result!(wallet.build_accept_task(parse_hash(&task_id)?, fee))
            })
            .await
        }
        TxCommands::DisputeTask {
            build,
            task_id,
            reason,
            fee,
        } => {
            simple(build, client, "tx-dispute-task", |wallet| {
                wallet_result!(wallet.build_dispute_task(parse_hash(&task_id)?, &reason, fee))
            })
            .await
        }
        TxCommands::ResolveTask {
            build,
            task_id,
            agent_wins,
            reason,
            fee,
        } => {
            simple(build, client, "tx-resolve-task", |wallet| {
                wallet_result!(wallet.build_resolve_task(
                    parse_hash(&task_id)?,
                    agent_wins,
                    &reason,
                    fee
                ))
            })
            .await
        }
        TxCommands::FinalizeTask {
            build,
            task_id,
            fee,
        } => {
            simple(build, client, "tx-finalize-task", |wallet| {
                wallet_result!(wallet.build_finalize_task(parse_hash(&task_id)?, fee))
            })
            .await
        }
        TxCommands::CancelTask {
            build,
            task_id,
            fee,
        } => {
            simple(build, client, "tx-cancel-task", |wallet| {
                wallet_result!(wallet.build_cancel_task(parse_hash(&task_id)?, fee))
            })
            .await
        }
        TxCommands::DecomposeTask {
            build,
            task_id,
            subtasks_file,
            fee,
        } => {
            let mut wallet = resolve_wallet(&build, client).await?;
            let subtasks: Vec<SubTaskDef> = read_json_file(&subtasks_file)?;
            Ok((
                "tx-decompose-task",
                wallet.build_decompose_task(parse_hash(&task_id)?, subtasks, fee)?,
                build,
            ))
        }
        TxCommands::UpdateReputation {
            build,
            task_id,
            quality,
            requester_accepted,
            feedback,
            fee,
        } => {
            let mut wallet = resolve_wallet(&build, client).await?;
            let signed = match feedback {
                Some(feedback) => wallet.build_update_reputation_with_feedback(
                    parse_hash(&task_id)?,
                    quality,
                    requester_accepted,
                    &feedback,
                    fee,
                )?,
                None => wallet.build_update_reputation(
                    parse_hash(&task_id)?,
                    quality,
                    requester_accepted,
                    fee,
                )?,
            };
            Ok(("tx-update-reputation", signed, build))
        }
        TxCommands::RegisterValidator {
            build,
            stake,
            vrf_public_key,
            executor_services_file,
            fee,
        } => {
            let mut wallet = resolve_wallet(&build, client).await?;
            let update = validator_update(vrf_public_key, executor_services_file)?;
            Ok((
                "tx-register-validator",
                wallet.build_register_validator_with_update(stake, update, fee)?,
                build,
            ))
        }
        TxCommands::UpdateValidator {
            build,
            vrf_public_key,
            executor_services_file,
            fee,
        } => {
            let mut wallet = resolve_wallet(&build, client).await?;
            Ok((
                "tx-update-validator",
                wallet.build_update_validator(
                    validator_update(vrf_public_key, executor_services_file)?,
                    fee,
                )?,
                build,
            ))
        }
        TxCommands::Stake {
            build,
            target,
            amount,
            fee,
        } => {
            simple(build, client, "tx-stake", |wallet| {
                wallet_result!(wallet.build_stake(amount, target.into(), fee))
            })
            .await
        }
        TxCommands::Unstake {
            build,
            target,
            amount,
            fee,
        } => {
            simple(build, client, "tx-unstake", |wallet| {
                wallet_result!(wallet.build_unstake(amount, target.into(), fee))
            })
            .await
        }
        TxCommands::ExitValidator { build, fee } => {
            simple(build, client, "tx-exit-validator", |wallet| {
                wallet_result!(wallet.build_exit_validator(fee))
            })
            .await
        }
        TxCommands::RegisterTool {
            build,
            name,
            description,
            endpoint,
            price,
            capabilities,
            settlement_mode,
            sla_ms,
            challenge_window_ms,
            max_result_metadata_bytes,
            arbitration_policy,
            version,
            fee,
        } => {
            let mut wallet = resolve_wallet(&build, client).await?;
            Ok((
                "tx-register-tool",
                wallet.build_register_tool_with_settlement(
                    &name,
                    &description,
                    &endpoint,
                    price,
                    parse_settlement_mode(&settlement_mode)?,
                    sla_ms,
                    challenge_window_ms,
                    max_result_metadata_bytes,
                    parse_arbitration_policy(&arbitration_policy)?,
                    parse_capabilities(capabilities)?,
                    &version,
                    fee,
                )?,
                build,
            ))
        }
        TxCommands::InvokeTool {
            build,
            tool_id,
            input_hex,
            fee,
        } => {
            simple(build, client, "tx-invoke-tool", |wallet| {
                wallet_result!(wallet.build_invoke_tool(
                    parse_hash(&tool_id)?,
                    parse_hex_bytes(input_hex.as_deref())?,
                    fee,
                ))
            })
            .await
        }
        TxCommands::InvokeMeteredTool {
            build,
            tool_id,
            input_hex,
            max_units,
            fee,
        } => {
            simple(build, client, "tx-invoke-metered-tool", |wallet| {
                wallet_result!(wallet.build_invoke_metered_tool(
                    parse_hash(&tool_id)?,
                    parse_hex_bytes(input_hex.as_deref())?,
                    max_units,
                    fee,
                ))
            })
            .await
        }
        TxCommands::InvokeMilestoneTool {
            build,
            tool_id,
            input_hex,
            milestones_file,
            fee,
        } => {
            let milestones: Vec<ToolMilestoneDef> = read_json_file(&milestones_file)?;
            simple(build, client, "tx-invoke-milestone-tool", |wallet| {
                wallet_result!(wallet.build_invoke_milestone_tool(
                    parse_hash(&tool_id)?,
                    parse_hex_bytes(input_hex.as_deref())?,
                    milestones,
                    fee,
                ))
            })
            .await
        }
        TxCommands::SubmitToolResult {
            build,
            job_id,
            result_hash,
            result_metadata_hex,
            milestone_index,
            fee,
        } => {
            let result_hash = parse_optional_hash(result_hash)?;
            let metadata = parse_hex_bytes(result_metadata_hex.as_deref())?;
            match milestone_index {
                Some(index) => {
                    simple(build, client, "tx-submit-tool-result", |wallet| {
                        wallet_result!(wallet.build_submit_tool_milestone_result(
                            parse_hash(&job_id)?,
                            index,
                            result_hash,
                            metadata,
                            fee,
                        ))
                    })
                    .await
                }
                None => {
                    simple(build, client, "tx-submit-tool-result", |wallet| {
                        wallet_result!(wallet.build_submit_tool_result(
                            parse_hash(&job_id)?,
                            result_hash,
                            metadata,
                            fee,
                        ))
                    })
                    .await
                }
            }
        }
        TxCommands::AcceptToolResult {
            build,
            job_id,
            milestone_index,
            fee,
        } => match milestone_index {
            Some(index) => {
                simple(build, client, "tx-accept-tool-result", |wallet| {
                    wallet_result!(wallet.build_accept_tool_milestone_result(
                        parse_hash(&job_id)?,
                        index,
                        fee
                    ))
                })
                .await
            }
            None => {
                simple(build, client, "tx-accept-tool-result", |wallet| {
                    wallet_result!(wallet.build_accept_tool_result(parse_hash(&job_id)?, fee))
                })
                .await
            }
        },
        TxCommands::DisputeToolResult {
            build,
            job_id,
            reason,
            milestone_index,
            fee,
        } => match milestone_index {
            Some(index) => {
                simple(build, client, "tx-dispute-tool-result", |wallet| {
                    wallet_result!(wallet.build_dispute_tool_milestone_result(
                        parse_hash(&job_id)?,
                        index,
                        &reason,
                        fee,
                    ))
                })
                .await
            }
            None => {
                simple(build, client, "tx-dispute-tool-result", |wallet| {
                    wallet_result!(wallet.build_dispute_tool_result(
                        parse_hash(&job_id)?,
                        &reason,
                        fee
                    ))
                })
                .await
            }
        },
        TxCommands::ResolveToolResult {
            build,
            job_id,
            provider_wins,
            reason,
            milestone_index,
            fee,
        } => match milestone_index {
            Some(index) => {
                simple(build, client, "tx-resolve-tool-result", |wallet| {
                    wallet_result!(wallet.build_resolve_tool_milestone_result(
                        parse_hash(&job_id)?,
                        index,
                        provider_wins,
                        &reason,
                        fee,
                    ))
                })
                .await
            }
            None => {
                simple(build, client, "tx-resolve-tool-result", |wallet| {
                    wallet_result!(wallet.build_resolve_tool_result(
                        parse_hash(&job_id)?,
                        provider_wins,
                        &reason,
                        fee,
                    ))
                })
                .await
            }
        },
        TxCommands::ReportToolUsage {
            build,
            session_id,
            units_used,
            result_hash,
            result_metadata_hex,
            fee,
        } => {
            simple(build, client, "tx-report-tool-usage", |wallet| {
                wallet_result!(wallet.build_report_tool_usage(
                    parse_hash(&session_id)?,
                    units_used,
                    parse_optional_hash(result_hash)?,
                    parse_hex_bytes(result_metadata_hex.as_deref())?,
                    fee,
                ))
            })
            .await
        }
        TxCommands::AcceptToolUsage {
            build,
            session_id,
            fee,
        } => {
            simple(build, client, "tx-accept-tool-usage", |wallet| {
                wallet_result!(wallet.build_accept_tool_usage(parse_hash(&session_id)?, fee))
            })
            .await
        }
        TxCommands::DisputeToolUsage {
            build,
            session_id,
            reason,
            fee,
        } => {
            simple(build, client, "tx-dispute-tool-usage", |wallet| {
                wallet_result!(wallet.build_dispute_tool_usage(
                    parse_hash(&session_id)?,
                    &reason,
                    fee
                ))
            })
            .await
        }
        TxCommands::ResolveToolUsage {
            build,
            session_id,
            provider_wins,
            reason,
            fee,
        } => {
            simple(build, client, "tx-resolve-tool-usage", |wallet| {
                wallet_result!(wallet.build_resolve_tool_usage(
                    parse_hash(&session_id)?,
                    provider_wins,
                    &reason,
                    fee,
                ))
            })
            .await
        }
        TxCommands::CreateToolSubscriptionPlan {
            build,
            tool_id,
            name,
            price_per_period,
            period_ms,
            included_calls,
            included_credits,
            overage_policy,
            fee,
        } => {
            simple(
                build,
                client,
                "tx-create-tool-subscription-plan",
                |wallet| {
                    wallet_result!(wallet.build_create_tool_subscription_plan(
                        parse_hash(&tool_id)?,
                        &name,
                        price_per_period,
                        period_ms,
                        included_calls,
                        included_credits,
                        parse_overage_policy(&overage_policy)?,
                        fee,
                    ))
                },
            )
            .await
        }
        TxCommands::UpdateToolSubscriptionPlan {
            build,
            plan_id,
            name,
            price_per_period,
            period_ms,
            included_calls,
            included_credits,
            overage_policy,
            active,
            fee,
        } => {
            let update = ToolSubscriptionPlanUpdateData {
                plan_id: parse_hash(&plan_id)?,
                name,
                price_per_period,
                period_ms,
                included_calls,
                included_credits,
                overage_policy: overage_policy
                    .as_deref()
                    .map(parse_overage_policy)
                    .transpose()?,
                active,
            };
            simple(
                build,
                client,
                "tx-update-tool-subscription-plan",
                |wallet| wallet_result!(wallet.build_update_tool_subscription_plan(update, fee)),
            )
            .await
        }
        TxCommands::StartToolSubscription {
            build,
            plan_id,
            reserve_amount,
            auto_renew,
            fee,
        } => {
            simple(build, client, "tx-start-tool-subscription", |wallet| {
                wallet_result!(wallet.build_start_tool_subscription(
                    parse_hash(&plan_id)?,
                    reserve_amount,
                    auto_renew,
                    fee,
                ))
            })
            .await
        }
        TxCommands::TopUpToolSubscription {
            build,
            subscription_id,
            amount,
            fee,
        } => {
            simple(build, client, "tx-top-up-tool-subscription", |wallet| {
                wallet_result!(wallet.build_top_up_tool_subscription(
                    parse_hash(&subscription_id)?,
                    amount,
                    fee
                ))
            })
            .await
        }
        TxCommands::CancelToolSubscription {
            build,
            subscription_id,
            fee,
        } => {
            simple(build, client, "tx-cancel-tool-subscription", |wallet| {
                wallet_result!(
                    wallet.build_cancel_tool_subscription(parse_hash(&subscription_id)?, fee)
                )
            })
            .await
        }
        TxCommands::ResumeToolSubscription {
            build,
            subscription_id,
            reserve_amount,
            fee,
        } => {
            simple(build, client, "tx-resume-tool-subscription", |wallet| {
                wallet_result!(wallet.build_resume_tool_subscription_with_reserve(
                    parse_hash(&subscription_id)?,
                    reserve_amount,
                    fee,
                ))
            })
            .await
        }
        TxCommands::RenewToolSubscription {
            build,
            subscription_id,
            fee,
        } => {
            simple(build, client, "tx-renew-tool-subscription", |wallet| {
                wallet_result!(
                    wallet.build_renew_tool_subscription(parse_hash(&subscription_id)?, fee)
                )
            })
            .await
        }
        TxCommands::UpdateTool {
            build,
            tool_id,
            description,
            endpoint,
            price_per_call,
            settlement_mode,
            active,
            capabilities,
            fee,
        } => {
            let tool_id = parse_hash(&tool_id)?;
            let update = ToolUpdateData {
                tool_id,
                description,
                endpoint,
                price_per_call,
                settlement_mode: settlement_mode
                    .as_deref()
                    .map(parse_settlement_mode)
                    .transpose()?,
                sla_ms: None,
                challenge_window_ms: None,
                max_result_metadata_bytes: None,
                arbitration_policy: None,
                capabilities: (!capabilities.is_empty())
                    .then(|| parse_capabilities(capabilities))
                    .transpose()?,
                match_enabled: None,
                neural_embedding: None,
                version: None,
                active,
            };
            simple(build, client, "tx-update-tool", |wallet| {
                wallet_result!(wallet.build_update_tool(tool_id, update, fee))
            })
            .await
        }
        TxCommands::DeregisterTool {
            build,
            tool_id,
            fee,
        } => {
            simple(build, client, "tx-deregister-tool", |wallet| {
                wallet_result!(wallet.build_deregister_tool(parse_hash(&tool_id)?, fee))
            })
            .await
        }
        TxCommands::CreateAgreement {
            build,
            parties,
            terms_hex,
            escrow_amount,
            expires_at,
            arbitrator,
            milestones_file,
            service_provider,
            settlement_allocations_file,
            settlement_approver,
            fee,
        } => {
            let mut wallet = resolve_wallet(&build, client).await?;
            let milestones = milestones_file
                .map(|path| read_json_file(&path))
                .transpose()?
                .unwrap_or_default();
            let allocations = settlement_allocations_file
                .map(|path| read_json_file(&path))
                .transpose()?
                .unwrap_or_default();
            Ok((
                "tx-create-agreement",
                wallet.build_create_agreement(
                    parse_addresses(parties)?,
                    parse_hex_bytes(terms_hex.as_deref())?,
                    escrow_amount,
                    expires_at,
                    arbitrator.as_deref().map(parse_address).transpose()?,
                    milestones,
                    parse_address(&service_provider)?,
                    allocations,
                    settlement_approver
                        .as_deref()
                        .map(parse_address)
                        .transpose()?,
                    fee,
                )?,
                build,
            ))
        }
        TxCommands::AcceptAgreement {
            build,
            agreement_id,
            fee,
        } => {
            simple(build, client, "tx-accept-agreement", |wallet| {
                wallet_result!(wallet.build_accept_agreement(parse_hash(&agreement_id)?, fee))
            })
            .await
        }
        TxCommands::ExecuteAgreement {
            build,
            agreement_id,
            result_hash,
            milestone_index,
            fee,
        } => match milestone_index {
            Some(index) => {
                simple(build, client, "tx-execute-agreement", |wallet| {
                    wallet_result!(wallet.build_execute_milestone(
                        parse_hash(&agreement_id)?,
                        parse_hash(&result_hash)?,
                        index,
                        fee,
                    ))
                })
                .await
            }
            None => {
                simple(build, client, "tx-execute-agreement", |wallet| {
                    wallet_result!(wallet.build_execute_agreement(
                        parse_hash(&agreement_id)?,
                        parse_hash(&result_hash)?,
                        fee,
                    ))
                })
                .await
            }
        },
        TxCommands::DisputeAgreement {
            build,
            agreement_id,
            reason,
            milestone_index,
            fee,
        } => {
            simple(build, client, "tx-dispute-agreement", |wallet| {
                wallet_result!(wallet.build_dispute_agreement_with_milestone(
                    parse_hash(&agreement_id)?,
                    &reason,
                    milestone_index,
                    fee,
                ))
            })
            .await
        }
        TxCommands::ResolveAgreement {
            build,
            agreement_id,
            payouts_file,
            reputation_effects_file,
            reason,
            milestone_index,
            fee,
        } => {
            let payouts: Vec<AgreementPayoutShare> = read_json_file(&payouts_file)?;
            let effects: Vec<AgreementDisputeReputationEffect> = reputation_effects_file
                .map(|path| read_json_file(&path))
                .transpose()?
                .unwrap_or_default();
            simple(build, client, "tx-resolve-agreement", |wallet| {
                wallet_result!(wallet.build_resolve_agreement(
                    parse_hash(&agreement_id)?,
                    payouts,
                    effects,
                    &reason,
                    milestone_index,
                    fee,
                ))
            })
            .await
        }
        TxCommands::CancelAgreement {
            build,
            agreement_id,
            fee,
        } => {
            simple(build, client, "tx-cancel-agreement", |wallet| {
                wallet_result!(wallet.build_cancel_agreement(parse_hash(&agreement_id)?, fee))
            })
            .await
        }
        TxCommands::RegisterArbitrator {
            build,
            name,
            description,
            stake,
            fee_bps,
            specializations,
            fee,
        } => {
            simple(build, client, "tx-register-arbitrator", |wallet| {
                wallet_result!(wallet.build_register_arbitrator(
                    &name,
                    &description,
                    stake,
                    fee_bps,
                    specializations,
                    fee,
                ))
            })
            .await
        }
        TxCommands::DeregisterArbitrator { build, fee } => {
            simple(build, client, "tx-deregister-arbitrator", |wallet| {
                wallet_result!(wallet.build_deregister_arbitrator(fee))
            })
            .await
        }
        TxCommands::DeployContract {
            build,
            bytecode_hex,
            bytecode_file,
            initial_balance,
            fee,
        } => {
            let bytecode = hex::decode(read_hex_or_file(&bytecode_hex, &bytecode_file)?)
                .context("decode bytecode hex")?;
            simple(build, client, "tx-deploy-contract", |wallet| {
                wallet_result!(wallet.build_deploy_contract(bytecode, initial_balance, fee))
            })
            .await
        }
        TxCommands::CallContract {
            build,
            contract_address,
            function,
            args_hex,
            call_value,
            gas_limit,
            fee,
        } => {
            simple(build, client, "tx-call-contract", |wallet| {
                wallet_result!(wallet.build_call_contract(
                    parse_address(&contract_address)?,
                    &function,
                    parse_hex_bytes(args_hex.as_deref())?,
                    call_value,
                    gas_limit,
                    fee,
                ))
            })
            .await
        }
        TxCommands::CallContractRoute {
            build,
            deployer,
            route_name,
            function,
            args_hex,
            call_value,
            gas_limit,
            fee,
        } => {
            simple(build, client, "tx-call-contract-route", |wallet| {
                wallet_result!(wallet.build_call_contract_route(
                    parse_address(&deployer)?,
                    &route_name,
                    &function,
                    parse_hex_bytes(args_hex.as_deref())?,
                    call_value,
                    gas_limit,
                    fee,
                ))
            })
            .await
        }
        TxCommands::UpdateContractRoute {
            build,
            route_name,
            target_contract_address,
            fee,
        } => {
            simple(build, client, "tx-update-contract-route", |wallet| {
                wallet_result!(wallet.build_update_contract_route(
                    &route_name,
                    parse_address(&target_contract_address)?,
                    fee,
                ))
            })
            .await
        }
        TxCommands::VerifyContractSource {
            build,
            contract_address,
            proof_file,
            fee,
        } => {
            let proof: ContractSourceProof = read_json_file(&proof_file)?;
            simple(build, client, "tx-verify-contract-source", |wallet| {
                wallet_result!(wallet.build_verify_contract_source(
                    parse_address(&contract_address)?,
                    proof,
                    fee
                ))
            })
            .await
        }
        TxCommands::PublishContractAbi {
            build,
            contract_address,
            abi_file,
            fee,
        } => {
            let abi: ContractAbi = read_json_file(&abi_file)?;
            simple(build, client, "tx-publish-contract-abi", |wallet| {
                wallet_result!(wallet.build_publish_contract_abi(
                    parse_address(&contract_address)?,
                    abi,
                    fee
                ))
            })
            .await
        }
        TxCommands::DeactivateContract {
            build,
            contract_address,
            fee,
        } => {
            simple(build, client, "tx-deactivate-contract", |wallet| {
                wallet_result!(
                    wallet.build_deactivate_contract(parse_address(&contract_address)?, fee)
                )
            })
            .await
        }
        TxCommands::CreateToken {
            build,
            name,
            symbol,
            decimals,
            initial_supply,
            max_supply,
            mint_authority,
            burnable,
            fee,
        } => {
            simple(build, client, "tx-create-token", |wallet| {
                wallet_result!(wallet.build_create_token(
                    &name,
                    &symbol,
                    decimals,
                    initial_supply,
                    max_supply,
                    mint_authority.as_deref().map(parse_address).transpose()?,
                    burnable,
                    Vec::new(),
                    fee,
                ))
            })
            .await
        }
        TxCommands::TransferToken {
            build,
            token_id,
            to,
            amount,
            fee,
        } => {
            simple(build, client, "tx-transfer-token", |wallet| {
                wallet_result!(wallet.build_transfer_token(
                    parse_hash(&token_id)?,
                    parse_address(&to)?,
                    amount,
                    fee,
                ))
            })
            .await
        }
        TxCommands::ApproveToken {
            build,
            token_id,
            spender,
            amount,
            fee,
        } => {
            simple(build, client, "tx-approve-token", |wallet| {
                wallet_result!(wallet.build_approve_token(
                    parse_hash(&token_id)?,
                    parse_address(&spender)?,
                    amount,
                    fee,
                ))
            })
            .await
        }
        TxCommands::MintToken {
            build,
            token_id,
            to,
            amount,
            fee,
        } => {
            simple(build, client, "tx-mint-token", |wallet| {
                wallet_result!(wallet.build_mint_token(
                    parse_hash(&token_id)?,
                    parse_address(&to)?,
                    amount,
                    fee
                ))
            })
            .await
        }
        TxCommands::UpdateTokenMintAuthority {
            build,
            token_id,
            mint_authority,
            fee,
        } => {
            simple(build, client, "tx-update-token-mint-authority", |wallet| {
                wallet_result!(wallet.build_update_token_mint_authority(
                    parse_hash(&token_id)?,
                    mint_authority.as_deref().map(parse_address).transpose()?,
                    fee,
                ))
            })
            .await
        }
        TxCommands::BurnToken {
            build,
            token_id,
            amount,
            fee,
        } => {
            simple(build, client, "tx-burn-token", |wallet| {
                wallet_result!(wallet.build_burn_token(parse_hash(&token_id)?, amount, fee))
            })
            .await
        }
        TxCommands::DestroyToken {
            build,
            token_id,
            fee,
        } => {
            simple(build, client, "tx-destroy-token", |wallet| {
                wallet_result!(wallet.build_destroy_token(parse_hash(&token_id)?, fee))
            })
            .await
        }
        TxCommands::SubmitSigned { .. }
        | TxCommands::SubmitBatch { .. }
        | TxCommands::SubmitProtected { .. }
        | TxCommands::SubmitBundle { .. }
        | TxCommands::Wait { .. } => unreachable!(),
    }
}

async fn simple<F>(
    build: TxBuildArgs,
    client: &ZinchaClient,
    label: &'static str,
    f: F,
) -> Result<(&'static str, SignedTransaction, TxBuildArgs)>
where
    F: FnOnce(&mut AgentWallet) -> Result<SignedTransaction>,
{
    let mut wallet = resolve_wallet(&build, client).await?;
    Ok((label, f(&mut wallet)?, build))
}

async fn resolve_wallet(build: &TxBuildArgs, client: &ZinchaClient) -> Result<AgentWallet> {
    let keypair = load_keypair(&build.key_source)?;
    let address = keypair.address();
    if build.offline && (build.chain_id.is_none() || build.nonce.is_none()) {
        bail!("--offline requires explicit --chain-id and --nonce");
    }

    let chain_info =
        if build.offline || (!build.submit && build.nonce.is_some() && build.chain_id.is_some()) {
            None
        } else {
            client.chain_info().await.ok()
        };

    let chain_id = build
        .chain_id
        .clone()
        .or_else(|| extract_string(chain_info.as_ref(), &["chain_id", "chainId"]))
        .unwrap_or_else(|| DEFAULT_CHAIN_ID.to_string());
    let nonce = match build.nonce {
        Some(nonce) => nonce,
        None if build.offline => bail!("--offline requires explicit --nonce"),
        None => extract_nonce(&client.nonce(&address.to_string()).await?)?,
    };

    let mut wallet = AgentWallet::new(keypair, &chain_id, client.base_url().as_str());
    wallet.set_nonce(nonce);
    if let Some(timestamp) = build.timestamp_ms {
        wallet.set_timestamp_ms(timestamp);
    }
    apply_validity_window(&mut wallet, build, chain_info.as_ref())?;
    Ok(wallet)
}

fn apply_validity_window(
    wallet: &mut AgentWallet,
    build: &TxBuildArgs,
    chain_info: Option<&Value>,
) -> Result<()> {
    match (
        build.reference_block_height,
        build.reference_block_hash.as_ref(),
        build.ttl_blocks,
    ) {
        (Some(height), Some(hash), Some(ttl)) => {
            wallet.set_transaction_validity_window(height, parse_hash(hash)?, ttl);
        }
        (Some(height), Some(hash), None) => {
            wallet.set_transaction_validity_window(height, parse_hash(hash)?, DEFAULT_TTL_BLOCKS);
        }
        (None, None, None) => {
            if let Some(info) = chain_info {
                if let (Some(height), Some(hash)) = (
                    extract_u64(Some(info), &["reference_block_height", "block_height", "height", "latest_block_height"]),
                    extract_string(Some(info), &["reference_block_hash", "block_hash", "latest_block_hash"]),
                ) {
                    wallet.set_transaction_validity_window(height, parse_hash(&hash)?, build.ttl_blocks.unwrap_or(DEFAULT_TTL_BLOCKS));
                }
            }
        }
        _ => bail!("reference_block_height and reference_block_hash must be provided together; ttl_blocks is optional"),
    }
    Ok(())
}

async fn finish_transaction(
    label: &'static str,
    signed: SignedTransaction,
    build: &TxBuildArgs,
    client: ZinchaClient,
    context: &CliContext,
) -> Result<()> {
    let signed_tx_hex = hex::encode(bincode::serialize(&signed)?);
    if let Some(path) = build.signed_tx_out.as_ref() {
        write_private_file(path, &signed_tx_hex, build.force)?;
    }
    let mut payload = json!({
        "hash": signed.hash.to_hex(),
        "sender": signed.transaction.sender.to_string(),
        "tx_type": format!("{:?}", signed.transaction.tx_type),
        "nonce": signed.transaction.nonce,
        "chain_id": signed.transaction.chain_id,
        "signed_tx_hex": signed_tx_hex,
        "signed_tx_file": build.signed_tx_out.as_ref().map(|path| path.display().to_string()),
        "submitted": false,
        "submission": Value::Null,
        "wait": Value::Null,
    });
    if build.wait && !build.submit {
        bail!("--wait requires --submit for newly built transactions");
    }
    if build.submit {
        let submission = client
            .submit_signed_transaction_hex(payload["signed_tx_hex"].as_str().expect("signed hex"))
            .await?;
        payload["submitted"] = Value::Bool(true);
        payload["submission"] = submission;
        if build.wait {
            payload["wait"] = client
                .wait_for_transaction(
                    &signed.hash.to_hex(),
                    Duration::from_secs(build.wait_timeout_secs),
                    Duration::from_millis(build.wait_interval_ms),
                )
                .await?;
        }
    }
    emit(label, payload, context.json)
}

fn collect_signed_hexes(values: Vec<String>, files: Vec<PathBuf>) -> Result<Vec<String>> {
    let mut output = values;
    for file in files {
        output.push(
            std::fs::read_to_string(&file)
                .with_context(|| format!("read {}", file.display()))?
                .trim()
                .to_string(),
        );
    }
    if output.is_empty() {
        bail!("at least one --signed-tx-hex or --signed-tx-file is required");
    }
    Ok(output)
}

fn validator_update(
    vrf_public_key: Option<String>,
    executor_services_file: Option<PathBuf>,
) -> Result<ValidatorUpdateData> {
    Ok(ValidatorUpdateData {
        executor_services: executor_services_file
            .map(|path| read_json_file::<Vec<ValidatorExecutorService>>(&path))
            .transpose()?
            .unwrap_or_default(),
        vrf_public_key: vrf_public_key
            .as_deref()
            .map(parse_public_key)
            .transpose()?,
    })
}

fn parse_optional_hash(raw: Option<String>) -> Result<Hash256> {
    raw.as_deref()
        .map(parse_hash)
        .transpose()
        .map(|value| value.unwrap_or_else(Hash256::zero))
}

fn parse_hashes(values: Vec<String>) -> Result<Vec<Hash256>> {
    values.into_iter().map(|value| parse_hash(&value)).collect()
}

fn parse_addresses(values: Vec<String>) -> Result<Vec<Address>> {
    values
        .into_iter()
        .map(|value| parse_address(&value))
        .collect()
}

fn parse_settlement_mode(raw: &str) -> Result<HttpToolSettlementMode> {
    match raw {
        "prepaid_access" | "prepaid" => Ok(HttpToolSettlementMode::PrepaidAccess),
        "result_escrowed" | "result-escrowed" => Ok(HttpToolSettlementMode::ResultEscrowed),
        "metered_usage" | "metered" => Ok(HttpToolSettlementMode::MeteredUsage),
        "milestone_escrowed" | "milestone-escrowed" => {
            Ok(HttpToolSettlementMode::MilestoneEscrowed)
        }
        other => bail!("unsupported settlement mode {other}"),
    }
}

fn parse_arbitration_policy(raw: &str) -> Result<ToolArbitrationPolicy> {
    match raw {
        "protocol" => Ok(ToolArbitrationPolicy::Protocol),
        other => bail!("unsupported arbitration policy {other}"),
    }
}

fn parse_overage_policy(raw: &str) -> Result<SubscriptionOveragePolicy> {
    match raw {
        "deny" => Ok(SubscriptionOveragePolicy::Deny),
        "pay_as_you_go" | "pay-as-you-go" => Ok(SubscriptionOveragePolicy::PayAsYouGo),
        other => bail!("unsupported overage policy {other}"),
    }
}

fn require_bearer(context: &CliContext) -> Result<String> {
    context.bearer_token.clone().ok_or_else(|| {
        anyhow::anyhow!("provider orderflow commands require --bearer-token or --bearer-token-env")
    })
}

fn extract_nonce(value: &Value) -> Result<u64> {
    extract_u64(Some(value), &["next_nonce", "nonce", "account_nonce"])
        .or_else(|| {
            value
                .pointer("/account/nonce")
                .and_then(Value::as_u64)
                .map(|nonce| nonce + 1)
        })
        .ok_or_else(|| anyhow::anyhow!("nonce response did not include next_nonce or nonce"))
}

fn extract_u64(value: Option<&Value>, keys: &[&str]) -> Option<u64> {
    let value = value?;
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_u64))
}

fn extract_string(value: Option<&Value>, keys: &[&str]) -> Option<String> {
    let value = value?;
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(ToString::to_string)
}
