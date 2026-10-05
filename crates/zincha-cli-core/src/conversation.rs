use crate::output::emit;
use crate::secret::{load_keypair, secret_to_keypair, KeySourceArgs};
use crate::support::{check_owner_only, now_millis, parse_address, parse_hash, parse_public_key};
use crate::tx::{self, TxBuildArgs, DEFAULT_TX_FEE};
use crate::CliContext;
use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use futures::StreamExt;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zincha_client::conversation::{
    challenge_signature, conversation_profile_from_metadata, create_delegation, decrypt_e2e,
    delegation_signing_bytes, encrypt_e2e, now_ms, sign_message, validate_conversation_id,
    validate_conversation_profile, ConversationClient, ConversationDelegationInfo,
    ConversationKeyDelegationV1, ConversationProfileV2, ConversationTransportPolicy,
    CreateDelegationOptions, E2eRecipient, FileOutbox, MessagePayload, MessageRecord, PrivacyMode,
    ResolveConversationRequest, SessionRequest, SubjectKind, SubjectRef,
};
use zincha_client::ZinchaClient;
use zincha_primitives::crypto::Signature;
use zincha_primitives::primitives::rpc_delegation::rpc_read_delegation_id;

const STATE_VERSION: u16 = 1;
const MAX_STATE_BYTES: u64 = 128 * 1024;
const MAX_PAYLOAD_BYTES: u64 = 64 * 1024;
const DEFAULT_SESSION_DELEGATION_SECS: u64 = 24 * 60 * 60;
const MAX_DECRYPTION_KEY_IDS: usize = 32;

#[derive(Debug, Parser)]
pub struct ConversationCommand {
    #[command(subcommand)]
    pub command: ConversationCommands,
}

#[derive(Debug, Subcommand)]
pub enum ConversationCommands {
    /// Read the provider's on-chain profile and verify the live service profile.
    Profile(ProfileTargetArgs),
    /// Read the authenticated service's chain-read delegation requirements.
    DelegationInfo(ProfileTargetArgs),
    /// Build or submit the provider's scoped on-chain chain-read grant.
    Authorize {
        #[command(flatten)]
        target: ProfileTargetArgs,
        #[command(flatten)]
        build: TxBuildArgs,
        /// Grant lifetime in milliseconds. Defaults to the service's advertised value.
        #[arg(long)]
        lifetime_ms: Option<u64>,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    /// Build or submit revocation of the provider's scoped chain-read grant.
    Deauthorize {
        #[command(flatten)]
        target: ProfileTargetArgs,
        #[command(flatten)]
        build: TxBuildArgs,
        /// Explicit grant ID, useful when revoking a previous service key.
        #[arg(long)]
        delegation_id: Option<String>,
        #[arg(long, default_value_t = DEFAULT_TX_FEE)]
        fee: u64,
    },
    /// Create operational keys, authenticate, resolve a conversation, and save private state.
    Open(OpenArgs),
    /// Renew the account-signed operational delegation and bearer session.
    Renew(RenewArgs),
    /// Show a redacted local state summary.
    Status {
        #[arg(long)]
        state: PathBuf,
    },
    /// Fetch the resolved conversation record.
    Get(StateTargetArgs),
    /// Sign, durably enqueue, and submit a message.
    Send(SendArgs),
    /// Fetch a bounded page of messages.
    Messages(MessagesArgs),
    /// Follow the resumable SSE message stream.
    Watch(WatchArgs),
    /// Acknowledge the highest locally processed sequence.
    Acknowledge(AcknowledgeArgs),
    /// Retry due entries in the durable outbox.
    OutboxFlush(OutboxFlushArgs),
    /// Decrypt one E2E message with the private state key.
    Decrypt(DecryptArgs),
    /// Revoke the current service-side operational delegation and session.
    RevokeSession(StateTargetArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum TransportPolicyArg {
    Auto,
    HttpsOnly,
    ZinchaTlsOnly,
}

impl From<TransportPolicyArg> for ConversationTransportPolicy {
    fn from(value: TransportPolicyArg) -> Self {
        match value {
            TransportPolicyArg::Auto => Self::Auto,
            TransportPolicyArg::HttpsOnly => Self::HttpsOnly,
            TransportPolicyArg::ZinchaTlsOnly => Self::ZinchaTlsOnly,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum SubjectKindArg {
    Task,
    Agreement,
    ToolJob,
    ToolSession,
}

impl From<SubjectKindArg> for SubjectKind {
    fn from(value: SubjectKindArg) -> Self {
        match value {
            SubjectKindArg::Task => Self::Task,
            SubjectKindArg::Agreement => Self::Agreement,
            SubjectKindArg::ToolJob => Self::ToolJob,
            SubjectKindArg::ToolSession => Self::ToolSession,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum PrivacyModeArg {
    PlatformReadable,
    EndToEnd,
}

impl From<PrivacyModeArg> for PrivacyMode {
    fn from(value: PrivacyModeArg) -> Self {
        match value {
            PrivacyModeArg::PlatformReadable => Self::PlatformReadable,
            PrivacyModeArg::EndToEnd => Self::EndToEnd,
        }
    }
}

#[derive(Debug, Args)]
pub struct ProfileTargetArgs {
    /// Provider agent whose authenticated on-chain metadata advertises the service.
    #[arg(long)]
    pub provider: String,
    #[arg(long, value_enum, default_value_t = TransportPolicyArg::Auto)]
    pub transport: TransportPolicyArg,
}

#[derive(Debug, Args)]
pub struct StateTargetArgs {
    #[arg(long)]
    pub state: PathBuf,
    #[arg(long, value_enum, default_value_t = TransportPolicyArg::Auto)]
    pub transport: TransportPolicyArg,
}

#[derive(Debug, Args)]
pub struct OpenArgs {
    #[command(flatten)]
    pub target: ProfileTargetArgs,
    #[command(flatten)]
    pub account: KeySourceArgs,
    #[arg(long, value_enum)]
    pub subject_kind: SubjectKindArg,
    #[arg(long)]
    pub subject_id: String,
    #[arg(long, value_enum, default_value_t = PrivacyModeArg::PlatformReadable)]
    pub privacy_mode: PrivacyModeArg,
    #[arg(long, default_value_t = DEFAULT_SESSION_DELEGATION_SECS)]
    pub delegation_lifetime_secs: u64,
    #[arg(long)]
    pub state: PathBuf,
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct RenewArgs {
    #[command(flatten)]
    pub target: StateTargetArgs,
    #[command(flatten)]
    pub account: KeySourceArgs,
    #[arg(long, default_value_t = DEFAULT_SESSION_DELEGATION_SECS)]
    pub delegation_lifetime_secs: u64,
}

#[derive(Debug, Args)]
pub struct SendArgs {
    #[command(flatten)]
    pub target: StateTargetArgs,
    /// A single plaintext message part.
    #[arg(
        long,
        conflicts_with = "payload_file",
        required_unless_present = "payload_file"
    )]
    pub text: Option<String>,
    /// Private JSON file containing a complete MessagePayload object.
    #[arg(long, conflicts_with = "text", required_unless_present = "text")]
    pub payload_file: Option<PathBuf>,
    #[arg(long)]
    pub reply_to: Option<String>,
    /// E2E epoch. Required for ciphertext or when --e2e-recipients-file is used.
    #[arg(long)]
    pub key_epoch: Option<u64>,
    /// JSON array of {"key_id":"...","public_key":"<64 hex>"} recipients.
    #[arg(long)]
    pub e2e_recipients_file: Option<PathBuf>,
    /// Durable outbox path. Defaults beside the state file.
    #[arg(long)]
    pub outbox: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct MessagesArgs {
    #[command(flatten)]
    pub target: StateTargetArgs,
    #[arg(long)]
    pub after: Option<i64>,
    #[arg(long, default_value_t = 100)]
    pub limit: u32,
    /// Save the highest returned sequence as the next SSE resume cursor.
    #[arg(long)]
    pub advance_cursor: bool,
}

#[derive(Debug, Args)]
pub struct WatchArgs {
    #[command(flatten)]
    pub target: StateTargetArgs,
    #[arg(long)]
    pub after: Option<i64>,
    /// Exit after this many messages; zero follows indefinitely.
    #[arg(long, default_value_t = 0)]
    pub limit: usize,
}

#[derive(Debug, Args)]
pub struct AcknowledgeArgs {
    #[command(flatten)]
    pub target: StateTargetArgs,
    #[arg(long)]
    pub through_sequence: i64,
}

#[derive(Debug, Args)]
pub struct OutboxFlushArgs {
    #[command(flatten)]
    pub target: StateTargetArgs,
    #[arg(long)]
    pub outbox: Option<PathBuf>,
    #[arg(long, default_value_t = 100)]
    pub limit: usize,
}

#[derive(Debug, Args)]
pub struct DecryptArgs {
    #[arg(long)]
    pub state: PathBuf,
    /// Private JSON file containing a MessageRecord returned by the service.
    #[arg(long)]
    pub message_file: PathBuf,
    /// Explicit recipient key ID. Defaults to the bounded IDs retained in state.
    #[arg(long)]
    pub recipient_key_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConversationStateV1 {
    version: u16,
    provider_address: String,
    profile: ConversationProfileV2,
    subject: SubjectRef,
    privacy_mode: PrivacyMode,
    operational_secret_key: String,
    encryption_secret_key: String,
    delegation: ConversationKeyDelegationV1,
    decryption_key_ids: Vec<String>,
    access_token: Option<String>,
    session_expires_at_ms: Option<i64>,
    conversation_id: Option<String>,
    last_observed_sequence: i64,
    last_acknowledged_sequence: i64,
}

pub async fn run_conversation(
    command: ConversationCommand,
    node: ZinchaClient,
    context: &CliContext,
) -> Result<()> {
    match command.command {
        ConversationCommands::Profile(target) => {
            let (profile, _) = verified_provider_client(&node, &target).await?;
            emit(
                "conversation-profile",
                json!({
                    "provider_address": canonical_address(&target.provider)?,
                    "profile": profile,
                    "verified": true,
                }),
                context.json,
            )
        }
        ConversationCommands::DelegationInfo(target) => {
            let (profile, client) = verified_provider_client(&node, &target).await?;
            let info = client.delegation_info().await?;
            validate_delegation_info(&profile, &info)?;
            emit(
                "conversation-delegation-info",
                serde_json::to_value(info)?,
                context.json,
            )
        }
        ConversationCommands::Authorize {
            target,
            build,
            lifetime_ms,
            fee,
        } => authorize(target, build, lifetime_ms, fee, node, context).await,
        ConversationCommands::Deauthorize {
            target,
            build,
            delegation_id,
            fee,
        } => deauthorize(target, build, delegation_id, fee, node, context).await,
        ConversationCommands::Open(args) => open(args, &node, context).await,
        ConversationCommands::Renew(args) => renew(args, &node, context).await,
        ConversationCommands::Status { state } => status(&state, context),
        ConversationCommands::Get(target) => get(target, &node, context).await,
        ConversationCommands::Send(args) => send(args, &node, context).await,
        ConversationCommands::Messages(args) => messages(args, &node, context).await,
        ConversationCommands::Watch(args) => watch(args, &node, context).await,
        ConversationCommands::Acknowledge(args) => acknowledge(args, &node, context).await,
        ConversationCommands::OutboxFlush(args) => outbox_flush(args, &node, context).await,
        ConversationCommands::Decrypt(args) => decrypt(args, context),
        ConversationCommands::RevokeSession(target) => revoke_session(target, &node, context).await,
    }
}

async fn authorize(
    target: ProfileTargetArgs,
    build: TxBuildArgs,
    lifetime_ms: Option<u64>,
    fee: u64,
    node: ZinchaClient,
    context: &CliContext,
) -> Result<()> {
    let provider = parse_address(&target.provider)?;
    let (profile, client) = verified_provider_client(&node, &target).await?;
    let info = client.delegation_info().await?;
    validate_delegation_info(&profile, &info)?;
    let lifetime = lifetime_ms.unwrap_or(info.default_grant_lifetime_ms);
    if lifetime < 3_600_000 || lifetime > info.maximum_grant_lifetime_ms {
        bail!("conversation grant lifetime is outside service bounds");
    }
    let delegate = parse_public_key(&info.active_key.public_key)?;
    let expires_at_ms = now_millis()?
        .checked_add(lifetime)
        .context("conversation grant expiry overflows")?;
    let mut wallet = tx::resolve_wallet(&build, &node).await?;
    if wallet.address() != provider {
        bail!("conversation provider address does not match transaction signer");
    }
    let signed = wallet.build_rpc_read_delegation_grant(
        delegate,
        info.service_id,
        info.required_scope_mask,
        expires_at_ms,
        fee,
    )?;
    tx::finish_transaction("conversation-authorize", signed, &build, node, context).await
}

async fn deauthorize(
    target: ProfileTargetArgs,
    build: TxBuildArgs,
    delegation_id: Option<String>,
    fee: u64,
    node: ZinchaClient,
    context: &CliContext,
) -> Result<()> {
    let provider = parse_address(&target.provider)?;
    let mut wallet = tx::resolve_wallet(&build, &node).await?;
    if wallet.address() != provider {
        bail!("conversation provider address does not match transaction signer");
    }
    let id = match delegation_id {
        Some(value) => parse_hash(&value)?,
        None => {
            let (profile, client) = verified_provider_client(&node, &target).await?;
            let info = client.delegation_info().await?;
            validate_delegation_info(&profile, &info)?;
            let delegate = parse_public_key(&info.active_key.public_key)?;
            rpc_read_delegation_id(&provider, delegate.as_bytes(), &info.service_id)
        }
    };
    let signed = wallet.build_rpc_read_delegation_revoke(id, fee)?;
    tx::finish_transaction("conversation-deauthorize", signed, &build, node, context).await
}

async fn open(args: OpenArgs, node: &ZinchaClient, context: &CliContext) -> Result<()> {
    if args.delegation_lifetime_secs == 0 {
        bail!("delegation lifetime must be greater than zero");
    }
    if args.state.exists() {
        check_private_existing(&args.state)?;
        if !args.force {
            bail!(
                "refusing to overwrite existing file {}",
                args.state.display()
            );
        }
    }
    let provider_address = canonical_address(&args.target.provider)?;
    let (profile, client) = verified_provider_client(node, &args.target).await?;
    let privacy_mode: PrivacyMode = args.privacy_mode.into();
    if !profile.privacy_modes.contains(&privacy_mode) {
        bail!("conversation service does not advertise the selected privacy mode");
    }
    let info = client.delegation_info().await?;
    validate_delegation_info(&profile, &info)?;
    let account = load_keypair(&args.account)?;
    let operational = zincha_primitives::crypto::Keypair::generate();
    let encryption_secret = StaticSecret::random_from_rng(OsRng);
    let encryption_public = X25519PublicKey::from(&encryption_secret);
    let subject = SubjectRef {
        network: info.network,
        chain_id: info.chain_id,
        kind: args.subject_kind.into(),
        id: args.subject_id,
    };
    let start = now_ms();
    let expires_at_ms = delegation_expiry(start, args.delegation_lifetime_secs)?;
    let delegation = create_delegation(
        &account,
        &operational,
        *encryption_public.as_bytes(),
        CreateDelegationOptions {
            subject: subject.clone(),
            home_service_id: profile.service_id.clone(),
            not_before_ms: start,
            expires_at_ms,
            capabilities: vec!["read".to_string(), "write".to_string()],
        },
    )?;
    let challenge = client
        .issue_challenge(&zincha_client::conversation::ChallengeRequest {
            participant_address: account.address().to_string(),
            subject: subject.clone(),
        })
        .await?;
    let session = client
        .create_session(&SessionRequest {
            challenge_id: challenge.challenge_id,
            delegation: delegation.clone(),
            challenge_signature: challenge_signature(&operational, &challenge),
        })
        .await?;
    let authenticated = client.with_access_token(session.access_token.clone());
    let conversation = authenticated
        .resolve(&ResolveConversationRequest {
            subject: subject.clone(),
            provider_address: provider_address.clone(),
            privacy_mode,
        })
        .await?;
    let key_id = delegation.delegation_id.to_string();
    let state = ConversationStateV1 {
        version: STATE_VERSION,
        provider_address,
        profile,
        subject,
        privacy_mode,
        operational_secret_key: hex::encode(operational.secret_bytes()),
        encryption_secret_key: hex::encode(encryption_secret.to_bytes()),
        delegation,
        decryption_key_ids: vec![key_id],
        access_token: Some(session.access_token),
        session_expires_at_ms: Some(session.expires_at_ms),
        conversation_id: Some(conversation.id.clone()),
        last_observed_sequence: 0,
        last_acknowledged_sequence: 0,
    };
    write_state(&args.state, &state, args.force)?;
    emit(
        "conversation-open",
        json!({
            "state_file": args.state.display().to_string(),
            "provider_address": state.provider_address,
            "participant_address": state.delegation.participant_address,
            "delegation_id": state.delegation.delegation_id,
            "delegation_expires_at_ms": state.delegation.expires_at_ms,
            "session_expires_at_ms": state.session_expires_at_ms,
            "conversation": conversation,
        }),
        context.json,
    )
}

async fn renew(args: RenewArgs, node: &ZinchaClient, context: &CliContext) -> Result<()> {
    if args.delegation_lifetime_secs == 0 {
        bail!("delegation lifetime must be greater than zero");
    }
    let mut state = read_state(&args.target.state)?;
    let account = load_keypair(&args.account)?;
    if account.address().to_string() != state.delegation.participant_address {
        bail!("conversation state participant does not match account signer");
    }
    let current_profile = provider_profile(node, &state.provider_address).await?;
    let client =
        ConversationClient::from_profile(&current_profile, args.target.transport.into()).await?;
    let info = client.delegation_info().await?;
    validate_delegation_info(&current_profile, &info)?;
    if state.subject.network != info.network || state.subject.chain_id != info.chain_id {
        bail!("conversation service chain identity changed");
    }
    let operational = operational_key(&state)?;
    let encryption_secret = encryption_secret(&state)?;
    let encryption_public = X25519PublicKey::from(&encryption_secret);
    let start = now_ms();
    let delegation = create_delegation(
        &account,
        &operational,
        *encryption_public.as_bytes(),
        CreateDelegationOptions {
            subject: state.subject.clone(),
            home_service_id: current_profile.service_id.clone(),
            not_before_ms: start,
            expires_at_ms: delegation_expiry(start, args.delegation_lifetime_secs)?,
            capabilities: vec!["read".to_string(), "write".to_string()],
        },
    )?;
    let challenge = client
        .issue_challenge(&zincha_client::conversation::ChallengeRequest {
            participant_address: account.address().to_string(),
            subject: state.subject.clone(),
        })
        .await?;
    let session = client
        .create_session(&SessionRequest {
            challenge_id: challenge.challenge_id,
            delegation: delegation.clone(),
            challenge_signature: challenge_signature(&operational, &challenge),
        })
        .await?;
    let authenticated = client.with_access_token(session.access_token.clone());
    if let Some(id) = state.conversation_id.as_deref() {
        authenticated.conversation(id).await?;
    }
    state.profile = current_profile;
    state.delegation = delegation;
    state.access_token = Some(session.access_token);
    state.session_expires_at_ms = Some(session.expires_at_ms);
    retain_decryption_key_id(
        &mut state.decryption_key_ids,
        state.delegation.delegation_id.to_string(),
    );
    write_state(&args.target.state, &state, true)?;
    emit(
        "conversation-renew",
        json!({
            "state_file": args.target.state.display().to_string(),
            "delegation_id": state.delegation.delegation_id,
            "delegation_expires_at_ms": state.delegation.expires_at_ms,
            "session_expires_at_ms": state.session_expires_at_ms,
            "conversation_id": state.conversation_id,
        }),
        context.json,
    )
}

fn status(path: &Path, context: &CliContext) -> Result<()> {
    let state = read_state(path)?;
    emit(
        "conversation-status",
        json!({
            "state_file": path.display().to_string(),
            "provider_address": state.provider_address,
            "service_id": state.profile.service_id,
            "subject": state.subject,
            "privacy_mode": state.privacy_mode,
            "participant_address": state.delegation.participant_address,
            "delegation_id": state.delegation.delegation_id,
            "delegation_expires_at_ms": state.delegation.expires_at_ms,
            "session_expires_at_ms": state.session_expires_at_ms,
            "session_available": state.access_token.is_some(),
            "conversation_id": state.conversation_id,
            "last_observed_sequence": state.last_observed_sequence,
            "last_acknowledged_sequence": state.last_acknowledged_sequence,
            "outbox": default_outbox_path(path).display().to_string(),
        }),
        context.json,
    )
}

async fn get(target: StateTargetArgs, node: &ZinchaClient, context: &CliContext) -> Result<()> {
    let state = read_state(&target.state)?;
    let id = conversation_id(&state)?;
    let client = authenticated_client(node, &state, target.transport).await?;
    emit(
        "conversation-get",
        serde_json::to_value(client.conversation(id).await?)?,
        context.json,
    )
}

async fn send(args: SendArgs, node: &ZinchaClient, context: &CliContext) -> Result<()> {
    let mut state = read_state(&args.target.state)?;
    let id = conversation_id(&state)?.to_string();
    let client = authenticated_client(node, &state, args.target.transport).await?;
    let mut payload = match (args.text, args.payload_file.as_deref()) {
        (Some(text), None) => MessagePayload::Plaintext {
            parts: vec![zincha_client::conversation::MessagePart::Text { text }],
        },
        (None, Some(path)) => read_private_json_limited(path, MAX_PAYLOAD_BYTES)?,
        _ => bail!("provide exactly one of --text or --payload-file"),
    };
    if let Some(path) = args.e2e_recipients_file.as_deref() {
        let epoch = args
            .key_epoch
            .ok_or_else(|| anyhow!("--key-epoch is required for E2E encryption"))?;
        let recipients: Vec<E2eRecipient> = read_json_limited(path, MAX_PAYLOAD_BYTES)?;
        payload = encrypt_e2e(&id, epoch, &payload, &recipients)?;
    }
    match (&state.privacy_mode, &payload) {
        (PrivacyMode::EndToEnd, MessagePayload::Plaintext { .. }) => {
            bail!("end_to_end conversations require encrypted payloads")
        }
        (PrivacyMode::PlatformReadable, MessagePayload::Ciphertext { .. }) => {
            bail!("platform_readable conversations require plaintext payloads")
        }
        _ => {}
    }
    if serde_json::to_vec(&payload)?.len() as u64 > MAX_PAYLOAD_BYTES {
        bail!("conversation payload exceeds the bounded payload size");
    }
    let reply_to = args
        .reply_to
        .as_deref()
        .map(Uuid::parse_str)
        .transpose()
        .context("parse reply message ID")?;
    let request = sign_message(
        &operational_key(&state)?,
        state.delegation.delegation_id,
        &id,
        &state.delegation.participant_address,
        payload,
        reply_to,
        args.key_epoch,
    )?;
    let outbox_path = args
        .outbox
        .unwrap_or_else(|| default_outbox_path(&args.target.state));
    check_private_existing(&outbox_path)?;
    let outbox = FileOutbox::new(&outbox_path);
    outbox.enqueue(&id, request.clone())?;
    match client.submit(&id, &request).await {
        Ok(record) => {
            outbox.mark_sent(request.message_id)?;
            state.last_observed_sequence = state.last_observed_sequence.max(record.sequence);
            write_state(&args.target.state, &state, true)?;
            emit(
                "conversation-send",
                json!({
                    "message": record,
                    "outbox": outbox_path.display().to_string(),
                    "queued": false,
                }),
                context.json,
            )
        }
        Err(error) => {
            let rendered = format!("{error:#}");
            outbox.mark_failed(request.message_id, &rendered, now_ms())?;
            Err(error).context(format!(
                "message remains queued in {}",
                outbox_path.display()
            ))
        }
    }
}

async fn messages(args: MessagesArgs, node: &ZinchaClient, context: &CliContext) -> Result<()> {
    let mut state = read_state(&args.target.state)?;
    let id = conversation_id(&state)?.to_string();
    let after = args.after.unwrap_or(state.last_observed_sequence);
    let client = authenticated_client(node, &state, args.target.transport).await?;
    let page = client.messages(&id, after, args.limit).await?;
    if args.advance_cursor {
        if let Some(highest) = page.items.iter().map(|message| message.sequence).max() {
            state.last_observed_sequence = state.last_observed_sequence.max(highest);
            write_state(&args.target.state, &state, true)?;
        }
    }
    emit(
        "conversation-messages",
        serde_json::to_value(page)?,
        context.json,
    )
}

async fn watch(args: WatchArgs, node: &ZinchaClient, context: &CliContext) -> Result<()> {
    let mut state = read_state(&args.target.state)?;
    let id = conversation_id(&state)?.to_string();
    let after = args.after.unwrap_or(state.last_observed_sequence);
    if after < 0 {
        bail!("message cursor cannot be negative");
    }
    let client = authenticated_client(node, &state, args.target.transport).await?;
    let mut stream = client.events(id, after);
    let mut delivered = 0usize;
    while let Some(message) = stream.next().await {
        let message = message?;
        emit_stream_message(&message, context.json)?;
        state.last_observed_sequence = state.last_observed_sequence.max(message.sequence);
        write_state(&args.target.state, &state, true)?;
        delivered += 1;
        if args.limit != 0 && delivered >= args.limit {
            break;
        }
    }
    Ok(())
}

async fn acknowledge(
    args: AcknowledgeArgs,
    node: &ZinchaClient,
    context: &CliContext,
) -> Result<()> {
    let mut state = read_state(&args.target.state)?;
    if args.through_sequence < state.last_acknowledged_sequence
        || args.through_sequence > state.last_observed_sequence
    {
        bail!("acknowledgement must advance within the locally observed sequence range");
    }
    let id = conversation_id(&state)?.to_string();
    let client = authenticated_client(node, &state, args.target.transport).await?;
    client.acknowledge(&id, args.through_sequence).await?;
    state.last_acknowledged_sequence = args.through_sequence;
    write_state(&args.target.state, &state, true)?;
    emit(
        "conversation-acknowledge",
        json!({
            "conversation_id": id,
            "through_sequence": args.through_sequence,
        }),
        context.json,
    )
}

async fn outbox_flush(
    args: OutboxFlushArgs,
    node: &ZinchaClient,
    context: &CliContext,
) -> Result<()> {
    if args.limit == 0 || args.limit > 500 {
        bail!("outbox flush limit must be between 1 and 500");
    }
    let state = read_state(&args.target.state)?;
    let client = authenticated_client(node, &state, args.target.transport).await?;
    let path = args
        .outbox
        .unwrap_or_else(|| default_outbox_path(&args.target.state));
    check_private_existing(&path)?;
    let sent = FileOutbox::new(&path).flush(&client, args.limit).await?;
    emit(
        "conversation-outbox-flush",
        json!({
            "outbox": path.display().to_string(),
            "sent": sent,
        }),
        context.json,
    )
}

fn decrypt(args: DecryptArgs, context: &CliContext) -> Result<()> {
    let state = read_state(&args.state)?;
    let message: MessageRecord = read_private_json_limited(&args.message_file, MAX_PAYLOAD_BYTES)?;
    let conversation = conversation_id(&state)?;
    if message.conversation_id != conversation {
        bail!("message conversation does not match state");
    }
    let epoch = message
        .key_epoch
        .ok_or_else(|| anyhow!("message has no E2E key epoch"))?;
    let ids = match args.recipient_key_id {
        Some(id) => vec![id],
        None => state.decryption_key_ids.clone(),
    };
    let secret = encryption_secret(&state)?.to_bytes();
    let mut failures = Vec::new();
    for id in ids {
        match decrypt_e2e(conversation, epoch, &message.payload, &id, secret) {
            Ok(payload) => {
                return emit(
                    "conversation-decrypt",
                    json!({
                        "conversation_id": conversation,
                        "message_id": message.message_id,
                        "sender": message.sender,
                        "key_epoch": epoch,
                        "recipient_key_id": id,
                        "payload": payload,
                    }),
                    context.json,
                )
            }
            Err(error) => failures.push(format!("{id}: {error:#}")),
        }
    }
    bail!(
        "message could not be decrypted with retained key IDs: {}",
        failures.join("; ")
    )
}

async fn revoke_session(
    target: StateTargetArgs,
    node: &ZinchaClient,
    context: &CliContext,
) -> Result<()> {
    let mut state = read_state(&target.state)?;
    let client = authenticated_client(node, &state, target.transport).await?;
    let delegation_id = state.delegation.delegation_id;
    client.revoke_delegation(delegation_id).await?;
    state.access_token = None;
    state.session_expires_at_ms = None;
    write_state(&target.state, &state, true)?;
    emit(
        "conversation-revoke-session",
        json!({
            "delegation_id": delegation_id,
            "state_file": target.state.display().to_string(),
            "revoked": true,
        }),
        context.json,
    )
}

async fn verified_provider_client(
    node: &ZinchaClient,
    target: &ProfileTargetArgs,
) -> Result<(ConversationProfileV2, ConversationClient)> {
    let provider = canonical_address(&target.provider)?;
    let profile = provider_profile(node, &provider).await?;
    let client = ConversationClient::from_profile(&profile, target.transport.into()).await?;
    Ok((profile, client))
}

async fn authenticated_client(
    node: &ZinchaClient,
    state: &ConversationStateV1,
    policy: TransportPolicyArg,
) -> Result<ConversationClient> {
    let token = state
        .access_token
        .as_deref()
        .ok_or_else(|| anyhow!("conversation session is unavailable; run conversation renew"))?;
    if state
        .session_expires_at_ms
        .is_some_and(|expires| expires <= now_ms())
    {
        bail!("conversation session expired; run conversation renew");
    }
    let profile = provider_profile(node, &state.provider_address).await?;
    if profile.service_id != state.delegation.home_service_id {
        bail!("on-chain conversation service ID no longer matches the session delegation");
    }
    Ok(ConversationClient::from_profile(&profile, policy.into())
        .await?
        .with_access_token(token.to_string()))
}

async fn provider_profile(
    node: &ZinchaClient,
    provider_address: &str,
) -> Result<ConversationProfileV2> {
    let agent: Value = node
        .get(&format!("/v1/agents/{provider_address}"))
        .await
        .context("fetch provider agent profile")?;
    let metadata = agent
        .get("metadata")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("provider agent response has no metadata byte array"))?;
    if metadata.len() > 4_096 {
        bail!("provider conversation profile exceeds the agent metadata limit");
    }
    let bytes = metadata
        .iter()
        .map(|value| {
            value
                .as_u64()
                .filter(|value| *value <= u8::MAX as u64)
                .map(|value| value as u8)
                .ok_or_else(|| anyhow!("provider metadata contains a non-byte value"))
        })
        .collect::<Result<Vec<_>>>()?;
    conversation_profile_from_metadata(&bytes).context("decode provider conversation profile")
}

fn validate_delegation_info(
    profile: &ConversationProfileV2,
    info: &ConversationDelegationInfo,
) -> Result<()> {
    if info.protocol_version != 1 || info.service_id != profile.service_id {
        bail!("conversation delegation information does not match the authenticated profile");
    }
    if info.required_scope_mask == 0
        || info.default_grant_lifetime_ms < 3_600_000
        || info.default_grant_lifetime_ms > info.maximum_grant_lifetime_ms
    {
        bail!("conversation delegation information is invalid");
    }
    let active = parse_public_key(&info.active_key.public_key)?;
    if active.to_address().to_string() != info.active_key.address {
        bail!("conversation active chain-read key address is invalid");
    }
    if let Some(next) = info.next_key.as_ref() {
        let key = parse_public_key(&next.public_key)?;
        if key.to_address().to_string() != next.address || key.as_bytes() == active.as_bytes() {
            bail!("conversation next chain-read key is invalid");
        }
    }
    Ok(())
}

fn canonical_address(value: &str) -> Result<String> {
    Ok(parse_address(value)?.to_string())
}

fn delegation_expiry(start: i64, lifetime_secs: u64) -> Result<i64> {
    let duration = lifetime_secs
        .checked_mul(1_000)
        .and_then(|value| i64::try_from(value).ok())
        .context("delegation lifetime overflows")?;
    start
        .checked_add(duration)
        .context("delegation expiry overflows")
}

fn operational_key(state: &ConversationStateV1) -> Result<zincha_primitives::crypto::Keypair> {
    secret_to_keypair(&state.operational_secret_key)
        .context("decode operational signing key from private state")
}

fn encryption_secret(state: &ConversationStateV1) -> Result<StaticSecret> {
    let bytes: [u8; 32] = hex::decode(&state.encryption_secret_key)
        .context("decode E2E secret key")?
        .try_into()
        .map_err(|_| anyhow!("E2E secret key must be 32 bytes"))?;
    Ok(StaticSecret::from(bytes))
}

fn conversation_id(state: &ConversationStateV1) -> Result<&str> {
    state
        .conversation_id
        .as_deref()
        .ok_or_else(|| anyhow!("conversation state has no resolved conversation ID"))
}

fn retain_decryption_key_id(ids: &mut Vec<String>, value: String) {
    ids.retain(|id| id != &value);
    ids.push(value);
    if ids.len() > MAX_DECRYPTION_KEY_IDS {
        ids.drain(..ids.len() - MAX_DECRYPTION_KEY_IDS);
    }
}

fn default_outbox_path(state: &Path) -> PathBuf {
    let name = state
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("conversation-state.json");
    state.with_file_name(format!("{name}.outbox.json"))
}

fn emit_stream_message(message: &MessageRecord, json_output: bool) -> Result<()> {
    let value = if json_output {
        json!({
            "version": 1,
            "ok": true,
            "command": "conversation-watch",
            "data": message,
        })
    } else {
        serde_json::to_value(message)?
    };
    let mut stdout = std::io::stdout().lock();
    if json_output {
        serde_json::to_writer(&mut stdout, &value)?;
    } else {
        serde_json::to_writer_pretty(&mut stdout, &value)?;
    }
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

fn read_state(path: &Path) -> Result<ConversationStateV1> {
    let state: ConversationStateV1 = read_private_json_limited(path, MAX_STATE_BYTES)?;
    validate_state(&state)?;
    Ok(state)
}

fn validate_state(state: &ConversationStateV1) -> Result<()> {
    if state.version != STATE_VERSION {
        bail!("unsupported conversation state version");
    }
    canonical_address(&state.provider_address)?;
    if state.profile.service_id != state.delegation.home_service_id
        || state.subject != state.delegation.subject
    {
        bail!("conversation state profile or subject does not match its delegation");
    }
    validate_conversation_profile(&state.profile)?;
    if !state.profile.privacy_modes.contains(&state.privacy_mode) {
        bail!("conversation state privacy mode is absent from its profile");
    }
    if let Some(id) = state.conversation_id.as_deref() {
        validate_conversation_id(id)?;
    }
    let participant = parse_public_key(&state.delegation.participant_public_key)?;
    if participant.to_address().to_string() != state.delegation.participant_address {
        bail!("conversation state participant key does not match its address");
    }
    let signature: [u8; 64] = hex::decode(&state.delegation.signature)
        .context("decode conversation delegation signature")?
        .try_into()
        .map_err(|_| anyhow!("conversation delegation signature must be 64 bytes"))?;
    participant
        .verify(
            &delegation_signing_bytes(&state.delegation),
            &Signature::from_bytes(&signature)?,
        )
        .context("verify conversation state delegation")?;
    let operational = operational_key(state)?;
    if hex::encode(operational.public_key().as_bytes()) != state.delegation.operational_signing_key
    {
        bail!("conversation state operational key does not match its delegation");
    }
    let encryption_public = X25519PublicKey::from(&encryption_secret(state)?);
    if hex::encode(encryption_public.as_bytes()) != state.delegation.encryption_key {
        bail!("conversation state encryption key does not match its delegation");
    }
    if state.decryption_key_ids.is_empty()
        || state.decryption_key_ids.len() > MAX_DECRYPTION_KEY_IDS
        || state
            .decryption_key_ids
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != state.decryption_key_ids.len()
        || !state
            .decryption_key_ids
            .contains(&state.delegation.delegation_id.to_string())
    {
        bail!("conversation state decryption key IDs are invalid");
    }
    if state
        .access_token
        .as_ref()
        .is_some_and(|token| token.is_empty() || token.len() > 8_192)
        || state.access_token.is_some() != state.session_expires_at_ms.is_some()
    {
        bail!("conversation state access token is invalid");
    }
    if state.last_observed_sequence < 0
        || state.last_acknowledged_sequence < 0
        || state.last_acknowledged_sequence > state.last_observed_sequence
    {
        bail!("conversation state sequence cursors are invalid");
    }
    Ok(())
}

fn write_state(path: &Path, state: &ConversationStateV1, force: bool) -> Result<()> {
    validate_state(state)?;
    if path.exists() {
        check_private_existing(path)?;
        if !force {
            bail!("refusing to overwrite existing file {}", path.display());
        }
    }
    let bytes = serde_json::to_vec_pretty(state).context("encode conversation state")?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        bail!("conversation state exceeds the bounded file size");
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("create state directory {}", parent.display()))?;
    }
    let mut suffix = [0u8; 16];
    OsRng.fill_bytes(&mut suffix);
    let temp = path.with_extension(format!("tmp-{}", hex::encode(suffix)));
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp)
            .with_context(|| format!("create temporary state {}", temp.display()))?;
        file.write_all(&bytes)
            .context("write temporary conversation state")?;
        file.sync_all()
            .context("sync temporary conversation state")?;
        drop(file);
        fs::rename(&temp, path)
            .with_context(|| format!("replace conversation state {}", path.display()))?;
        #[cfg(unix)]
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .context("sync conversation state directory")?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn read_private_json_limited<T: for<'de> Deserialize<'de>>(path: &Path, limit: u64) -> Result<T> {
    check_private_existing(path)?;
    read_json_limited(path, limit)
}

fn read_json_limited<T: for<'de> Deserialize<'de>>(path: &Path, limit: u64) -> Result<T> {
    let metadata = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if !metadata.is_file() || metadata.len() > limit {
        bail!("{} is not a bounded regular file", path.display());
    }
    let file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    if bytes.len() as u64 > limit {
        bail!("{} exceeds the bounded file size", path.display());
    }
    serde_json::from_slice(&bytes).with_context(|| format!("parse JSON {}", path.display()))
}

fn check_private_existing(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect private file {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{} must be a regular private file", path.display());
    }
    check_owner_only(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_decryption_ids_are_unique_and_bounded() {
        let mut ids = Vec::new();
        for index in 0..40 {
            retain_decryption_key_id(&mut ids, format!("key-{index}"));
        }
        assert_eq!(ids.len(), MAX_DECRYPTION_KEY_IDS);
        assert_eq!(ids.first().unwrap(), "key-8");
        retain_decryption_key_id(&mut ids, "key-20".to_string());
        assert_eq!(ids.len(), MAX_DECRYPTION_KEY_IDS);
        assert_eq!(ids.last().unwrap(), "key-20");
    }

    #[test]
    fn outbox_path_is_scoped_to_the_state_file() {
        assert_eq!(
            default_outbox_path(Path::new("/tmp/requester.json")),
            PathBuf::from("/tmp/requester.json.outbox.json")
        );
    }
}
