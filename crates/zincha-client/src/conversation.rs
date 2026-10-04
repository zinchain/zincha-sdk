//! Participant-authorized off-chain conversation protocol and client.

use std::{
    collections::BTreeSet,
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use futures::{Stream, StreamExt};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use reqwest::{Client, Method, Url};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zincha_primitives::crypto::Keypair;

const DELEGATION_DOMAIN: &str = "zincha-conversation-delegation-v1";
const CHALLENGE_DOMAIN: &str = "zincha-conversation-challenge-v1";
const MESSAGE_DOMAIN: &str = "zincha-conversation-message-v1";
const E2E_CONTENT_DOMAIN: &str = "zincha-conversation-e2e-content-v1";
const E2E_WRAP_DOMAIN: &str = "zincha-conversation-e2e-wrap-v1";
const DEFAULT_OUTBOX_MAX_ENTRIES: usize = 1_000;
const DEFAULT_OUTBOX_MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CONVERSATION_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const MAX_PROFILE_RESPONSE_BYTES: usize = 8 * 1024;
const MAX_SSE_EVENT_BYTES: usize = 256 * 1024;
const MAX_OUTBOX_ERROR_CHARS: usize = 1_024;
const MAX_IDLE_CONNECTIONS_PER_HOST: usize = 256;
const MAX_HTTPS_INTERFACE_URL_LENGTH: usize = 2_048;
const MAX_PROTOCOL_VERSIONS: usize = 64;

#[derive(Debug)]
pub struct ConversationAuthorizationRequiredError;

impl fmt::Display for ConversationAuthorizationRequiredError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("conversation authorization must be renewed")
    }
}

impl std::error::Error for ConversationAuthorizationRequiredError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    Task,
    Agreement,
    ToolJob,
    ToolSession,
}

impl SubjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Task => "task",
            Self::Agreement => "agreement",
            Self::ToolJob => "tool_job",
            Self::ToolSession => "tool_session",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectRef {
    pub network: String,
    pub chain_id: String,
    pub kind: SubjectKind,
    pub id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyMode {
    PlatformReadable,
    EndToEnd,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsCertificatePin {
    pub sha256: String,
    pub not_before_ms: i64,
    pub not_after_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConversationInterface {
    Https {
        url: String,
    },
    ZinchaTlsV1 {
        host: String,
        port: u16,
        certificate_pins: Vec<TlsCertificatePin>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationProfileV2 {
    pub version: u16,
    pub service_id: String,
    pub interfaces: Vec<ConversationInterface>,
    pub privacy_modes: Vec<PrivacyMode>,
    pub protocol_versions: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationTransportPolicy {
    Auto,
    HttpsOnly,
    ZinchaTlsOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationKeyDelegationV1 {
    pub version: u16,
    pub delegation_id: Uuid,
    pub participant_address: String,
    pub participant_public_key: String,
    pub subject: SubjectRef,
    pub home_service_id: String,
    pub operational_signing_key: String,
    pub encryption_key: String,
    pub capabilities: Vec<String>,
    pub not_before_ms: i64,
    pub expires_at_ms: i64,
    pub nonce: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeRequest {
    pub participant_address: String,
    pub subject: SubjectRef,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub challenge_id: Uuid,
    pub challenge: String,
    pub expires_at_ms: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRequest {
    pub challenge_id: Uuid,
    pub delegation: ConversationKeyDelegationV1,
    pub challenge_signature: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResponse {
    pub access_token: String,
    pub expires_at_ms: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveConversationRequest {
    pub subject: SubjectRef,
    pub provider_address: String,
    pub privacy_mode: PrivacyMode,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversation {
    pub id: String,
    pub tenant_id: String,
    pub subject: SubjectRef,
    pub home_service_id: String,
    pub privacy_mode: PrivacyMode,
    pub snapshot: Value,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum MessagePart {
    Text {
        text: String,
    },
    Data {
        value: Value,
    },
    ArtifactReference {
        artifact_id: Uuid,
        digest: String,
        media_type: String,
        size: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "encoding", rename_all = "snake_case", deny_unknown_fields)]
pub enum MessagePayload {
    Plaintext { parts: Vec<MessagePart> },
    Ciphertext { ciphertext: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitMessageRequest {
    pub message_id: Uuid,
    pub client_timestamp_ms: i64,
    pub reply_to: Option<Uuid>,
    pub key_epoch: Option<u64>,
    pub payload: MessagePayload,
    pub signing_key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageRecord {
    pub conversation_id: String,
    pub sequence: i64,
    pub message_id: Uuid,
    pub sender: String,
    pub client_timestamp_ms: i64,
    pub accepted_at_ms: i64,
    pub reply_to: Option<Uuid>,
    pub key_epoch: Option<u64>,
    pub payload: MessagePayload,
    pub payload_digest: String,
    pub signing_key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<i64>,
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub fn delegation_signing_bytes(delegation: &ConversationKeyDelegationV1) -> Vec<u8> {
    let capabilities = delegation
        .capabilities
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{DELEGATION_DOMAIN}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        delegation.version,
        delegation.delegation_id,
        delegation.participant_address,
        delegation.participant_public_key,
        delegation.subject.network,
        delegation.subject.chain_id,
        delegation.subject.kind.as_str(),
        delegation.subject.id,
        delegation.home_service_id,
        delegation.operational_signing_key,
        delegation.encryption_key,
        capabilities,
        delegation.not_before_ms,
        delegation.expires_at_ms,
        delegation.nonce,
    )
    .into_bytes()
}

#[derive(Debug, Clone)]
pub struct CreateDelegationOptions {
    pub subject: SubjectRef,
    pub home_service_id: String,
    pub not_before_ms: i64,
    pub expires_at_ms: i64,
    pub capabilities: Vec<String>,
}

pub fn create_delegation(
    account: &Keypair,
    operational: &Keypair,
    encryption_public_key: [u8; 32],
    options: CreateDelegationOptions,
) -> Result<ConversationKeyDelegationV1> {
    validate_subject_ref(&options.subject)?;
    validate_service_id(&options.home_service_id)?;
    validate_x25519_public_key(encryption_public_key)?;
    if options.not_before_ms >= options.expires_at_ms
        || options.expires_at_ms.saturating_sub(options.not_before_ms) > 31 * 24 * 60 * 60 * 1_000
    {
        bail!("delegation validity must be positive and no longer than 31 days");
    }
    let unique_capabilities = options.capabilities.iter().collect::<BTreeSet<_>>();
    if unique_capabilities.is_empty()
        || unique_capabilities.len() != options.capabilities.len()
        || unique_capabilities
            .iter()
            .any(|capability| !matches!(capability.as_str(), "read" | "write"))
    {
        bail!("delegation capabilities must be unique read/write values");
    }
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let mut delegation = ConversationKeyDelegationV1 {
        version: 1,
        delegation_id: Uuid::new_v4(),
        participant_address: account.address().to_string(),
        participant_public_key: hex::encode(account.public_key().as_bytes()),
        subject: options.subject,
        home_service_id: options.home_service_id,
        operational_signing_key: hex::encode(operational.public_key().as_bytes()),
        encryption_key: hex::encode(encryption_public_key),
        capabilities: options.capabilities,
        not_before_ms: options.not_before_ms,
        expires_at_ms: options.expires_at_ms,
        nonce: hex::encode(nonce),
        signature: String::new(),
    };
    delegation.signature = hex::encode(
        account
            .sign(&delegation_signing_bytes(&delegation))
            .to_bytes(),
    );
    Ok(delegation)
}

pub fn challenge_signing_bytes(challenge_id: Uuid, challenge: &str) -> Vec<u8> {
    format!("{CHALLENGE_DOMAIN}\n{challenge_id}\n{challenge}").into_bytes()
}

pub fn challenge_signature(operational: &Keypair, challenge: &ChallengeResponse) -> String {
    hex::encode(
        operational
            .sign(&challenge_signing_bytes(
                challenge.challenge_id,
                &challenge.challenge,
            ))
            .to_bytes(),
    )
}

pub fn payload_digest(payload: &MessagePayload) -> Result<String> {
    Ok(hex::encode(Sha256::digest(
        serde_jcs::to_vec(payload).context("canonicalize message payload")?,
    )))
}

pub fn message_signing_bytes(
    conversation_id: &str,
    sender: &str,
    request: &SubmitMessageRequest,
    digest: &str,
) -> Vec<u8> {
    format!(
        "{MESSAGE_DOMAIN}\n{conversation_id}\n{}\n{sender}\n{}\n{}\n{}\n{digest}\n{}",
        request.message_id,
        request.client_timestamp_ms,
        request
            .reply_to
            .map(|id| id.to_string())
            .unwrap_or_default(),
        request
            .key_epoch
            .map(|value| value.to_string())
            .unwrap_or_default(),
        request.signing_key_id,
    )
    .into_bytes()
}

pub fn sign_message(
    operational: &Keypair,
    delegation_id: Uuid,
    conversation_id: &str,
    sender: &str,
    payload: MessagePayload,
    reply_to: Option<Uuid>,
    key_epoch: Option<u64>,
) -> Result<SubmitMessageRequest> {
    validate_conversation_id(conversation_id)?;
    validate_address(sender)?;
    if key_epoch.is_some_and(|epoch| i64::try_from(epoch).is_err()) {
        bail!("message key epoch exceeds the protocol range");
    }
    validate_message_payload(&payload, key_epoch)?;
    let mut request = SubmitMessageRequest {
        message_id: Uuid::new_v4(),
        client_timestamp_ms: now_ms(),
        reply_to,
        key_epoch,
        payload,
        signing_key_id: delegation_id.to_string(),
        signature: String::new(),
    };
    let digest = payload_digest(&request.payload)?;
    request.signature = hex::encode(
        operational
            .sign(&message_signing_bytes(
                conversation_id,
                sender,
                &request,
                &digest,
            ))
            .to_bytes(),
    );
    Ok(request)
}

#[derive(Debug)]
struct PinnedCertificateVerifier {
    pins: Vec<([u8; 32], i64, i64)>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let digest: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        let pin = self
            .pins
            .iter()
            .find(|(expected, _, _)| digest.ct_eq(expected).into())
            .ok_or_else(|| {
                rustls::Error::General("zincha-tls-v1 certificate pin mismatch".into())
            })?;
        let current = now_ms();
        const CLOCK_SKEW_MS: i64 = 5 * 60 * 1_000;
        if current.saturating_add(CLOCK_SKEW_MS) < pin.1
            || current.saturating_sub(CLOCK_SKEW_MS) > pin.2
        {
            return Err(rustls::Error::General(
                "zincha-tls-v1 certificate pin is outside its advertised validity".into(),
            ));
        }
        let (_, certificate) =
            x509_parser::parse_x509_certificate(end_entity.as_ref()).map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;
        let not_before_ms = certificate
            .validity()
            .not_before
            .timestamp()
            .checked_mul(1_000)
            .ok_or_else(|| rustls::Error::General("certificate validity overflows".into()))?;
        let not_after_ms = certificate
            .validity()
            .not_after
            .timestamp()
            .checked_mul(1_000)
            .ok_or_else(|| rustls::Error::General("certificate validity overflows".into()))?;
        if (not_before_ms, not_after_ms) != (pin.1, pin.2) {
            return Err(rustls::Error::General(
                "zincha-tls-v1 certificate validity does not match the on-chain pin".into(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn pinned_http_client(pins: &[TlsCertificatePin]) -> Result<Client> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let parsed = pins
        .iter()
        .map(|pin| {
            let bytes: [u8; 32] = hex::decode(&pin.sha256)
                .context("decode zincha-tls-v1 pin")?
                .try_into()
                .map_err(|_| anyhow!("zincha-tls-v1 pin must be 32 bytes"))?;
            Ok((bytes, pin.not_before_ms, pin.not_after_ms))
        })
        .collect::<Result<Vec<_>>>()?;
    let verifier = Arc::new(PinnedCertificateVerifier {
        pins: parsed,
        algorithms: provider.signature_verification_algorithms,
    });
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("configure zincha-tls-v1 TLS 1.3")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    tls.enable_early_data = false;
    Client::builder()
        .use_preconfigured_tls(tls)
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(30))
        .pool_max_idle_per_host(MAX_IDLE_CONNECTIONS_PER_HOST)
        .build()
        .context("build zincha-tls-v1 HTTP client")
}

#[derive(Clone)]
pub struct ConversationClient {
    http: Client,
    base_url: Url,
    access_token: Option<String>,
}

impl ConversationClient {
    pub fn new(base_url: impl AsRef<str>) -> Result<Self> {
        let mut base_url =
            Url::parse(base_url.as_ref()).context("parse conversation service URL")?;
        validate_conversation_url(&base_url)?;
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        base_url.set_query(None);
        base_url.set_fragment(None);
        Ok(Self {
            http: Client::builder()
                .connect_timeout(std::time::Duration::from_secs(5))
                .timeout(std::time::Duration::from_secs(30))
                .pool_max_idle_per_host(MAX_IDLE_CONNECTIONS_PER_HOST)
                .build()?,
            base_url,
            access_token: None,
        })
    }

    /// Builds a client from authenticated on-chain metadata and verifies the
    /// live profile before any credential or workflow identifier can be sent.
    pub async fn from_profile(
        profile: &ConversationProfileV2,
        policy: ConversationTransportPolicy,
    ) -> Result<Self> {
        validate_conversation_profile(profile)?;
        let mut supported = false;
        let mut unreachable = Vec::new();
        for interface in &profile.interfaces {
            let (base_url, http) = match interface {
                ConversationInterface::Https { url }
                    if policy != ConversationTransportPolicy::ZinchaTlsOnly =>
                {
                    supported = true;
                    (
                        Url::parse(url).context("parse HTTPS conversation interface")?,
                        Client::builder()
                            .connect_timeout(std::time::Duration::from_secs(5))
                            .timeout(std::time::Duration::from_secs(30))
                            .pool_max_idle_per_host(MAX_IDLE_CONNECTIONS_PER_HOST)
                            .build()?,
                    )
                }
                ConversationInterface::ZinchaTlsV1 {
                    host,
                    port,
                    certificate_pins,
                } if policy != ConversationTransportPolicy::HttpsOnly => {
                    supported = true;
                    (
                        direct_tls_url(host, *port)?,
                        pinned_http_client(certificate_pins)?,
                    )
                }
                _ => continue,
            };

            let mut client = Self::with_http(base_url, http)?;
            let live = match client.profile().await {
                Ok(profile) => profile,
                Err(error)
                    if policy == ConversationTransportPolicy::Auto
                        && is_reachability_error(&error) =>
                {
                    unreachable.push(client.base_url.to_string());
                    continue;
                }
                Err(error) => {
                    return Err(error).context("verify live conversation service profile")
                }
            };
            verify_conversation_service_profile(profile, &live)?;
            client.access_token = None;
            return Ok(client);
        }
        if !supported {
            bail!(
                "conversation profile has no interface supported by the selected transport policy"
            );
        }
        bail!(
            "all supported conversation interfaces were unreachable: {}",
            unreachable.join(", ")
        )
    }

    fn with_http(mut base_url: Url, http: Client) -> Result<Self> {
        validate_conversation_url(&base_url)?;
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        base_url.set_query(None);
        base_url.set_fragment(None);
        Ok(Self {
            http,
            base_url,
            access_token: None,
        })
    }

    pub fn with_access_token(mut self, token: impl Into<String>) -> Self {
        self.access_token = Some(token.into());
        self
    }
    pub fn access_token(&self) -> Option<&str> {
        self.access_token.as_deref()
    }
    pub fn events_url(&self, conversation_id: &str, after: i64) -> Result<Url> {
        validate_conversation_id(conversation_id)?;
        if after < 0 {
            bail!("message cursor cannot be negative");
        }
        self.base_url
            .join(&format!(
                "v1/conversations/{conversation_id}/events?after={after}&limit=100"
            ))
            .context("build event URL")
    }

    /// Follows the durable message stream, reconnecting with the last delivered sequence.
    /// A server-requested resync is satisfied through bounded paged reads before reconnecting.
    /// Authentication or authorization expiry is returned to the caller instead of retried.
    pub fn events(
        &self,
        conversation_id: impl Into<String>,
        after: i64,
    ) -> Pin<Box<dyn Stream<Item = Result<MessageRecord>> + Send>> {
        let client = self.clone();
        let conversation_id = conversation_id.into();
        Box::pin(async_stream::try_stream! {
            let mut cursor = after;
            let mut delay_ms = 250u64;
            loop {
                let url = client.events_url(&conversation_id, cursor)?;
                let mut request = client.http.get(url).header(reqwest::header::ACCEPT, "text/event-stream");
                if let Some(token) = client.access_token.as_deref() {
                    request = request.bearer_auth(token);
                }
                let response = match request.send().await {
                    Ok(response) => response,
                    Err(_) => {
                        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                        delay_ms = (delay_ms.saturating_mul(2)).min(30_000);
                        continue;
                    }
                };
                if matches!(response.status(), reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN) {
                    Err::<(), _>(anyhow!(ConversationAuthorizationRequiredError))?;
                }
                let status = response.status();
                if !status.is_success()
                    && (status == reqwest::StatusCode::REQUEST_TIMEOUT
                        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
                        || status.is_server_error())
                {
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                    delay_ms = (delay_ms.saturating_mul(2)).min(30_000);
                    continue;
                }
                if !status.is_success() {
                    Err::<(), _>(anyhow!("conversation SSE HTTP {status}"))?;
                }
                let mut chunks = response.bytes_stream();
                let mut buffer = Vec::new();
                let mut resync = false;
                'connection: while let Some(chunk) = chunks.next().await {
                    let chunk = match chunk {
                        Ok(chunk) => chunk,
                        Err(_) => break,
                    };
                    if buffer.len().saturating_add(chunk.len()) > MAX_SSE_EVENT_BYTES {
                        Err::<(), _>(anyhow!("conversation SSE event exceeds 256 KiB"))?;
                    }
                    buffer.extend_from_slice(&chunk);
                    while let Some((boundary, separator_len)) = sse_boundary(&buffer) {
                        let block = buffer.drain(..boundary).collect::<Vec<_>>();
                        buffer.drain(..separator_len);
                        let event = parse_sse_block(&block)?;
                        match event.kind.as_deref() {
                            Some("message") => {
                                if let Some(data) = event.data {
                                    let message: MessageRecord = serde_json::from_str(&data)
                                        .context("decode conversation SSE message")?;
                                    if message.sequence > cursor {
                                        cursor = message.sequence;
                                        yield message;
                                    }
                                }
                            }
                            Some("resync_required") => {
                                resync = true;
                                break 'connection;
                            }
                            Some("authorization_required") => {
                                Err::<(), _>(anyhow!(ConversationAuthorizationRequiredError))?;
                            }
                            _ => {}
                        }
                    }
                }
                if resync {
                    loop {
                        let previous_cursor = cursor;
                        let page = client.messages(&conversation_id, cursor, 100).await?;
                        for message in page.items {
                            if message.sequence > cursor {
                                cursor = message.sequence;
                                yield message;
                            }
                        }
                        let Some(next_cursor) = page.next_cursor else {
                            break;
                        };
                        if cursor <= previous_cursor || next_cursor != cursor {
                            Err::<(), _>(anyhow!(
                                "conversation message pagination did not advance coherently"
                            ))?;
                        }
                    }
                    delay_ms = 250;
                    continue;
                }
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                delay_ms = (delay_ms.saturating_mul(2)).min(30_000);
            }
        })
    }

    pub async fn issue_challenge(&self, request: &ChallengeRequest) -> Result<ChallengeResponse> {
        validate_address(&request.participant_address)?;
        validate_subject_ref(&request.subject)?;
        self.json(Method::POST, "/v1/auth/challenges", Some(request))
            .await
    }
    pub async fn profile(&self) -> Result<ConversationProfileV2> {
        self.json_with_limit::<(), _>(Method::GET, "/v1/profile", None, MAX_PROFILE_RESPONSE_BYTES)
            .await
    }
    pub async fn create_session(&self, request: &SessionRequest) -> Result<SessionResponse> {
        self.json(Method::POST, "/v1/auth/sessions", Some(request))
            .await
    }
    pub async fn resolve(&self, request: &ResolveConversationRequest) -> Result<Conversation> {
        validate_subject_ref(&request.subject)?;
        validate_address(&request.provider_address)?;
        self.json(Method::POST, "/v1/conversations/resolve", Some(request))
            .await
    }
    pub async fn conversation(&self, id: &str) -> Result<Conversation> {
        validate_conversation_id(id)?;
        self.json::<(), _>(Method::GET, &format!("/v1/conversations/{id}"), None)
            .await
    }
    pub async fn submit(&self, id: &str, request: &SubmitMessageRequest) -> Result<MessageRecord> {
        validate_conversation_id(id)?;
        self.json(
            Method::POST,
            &format!("/v1/conversations/{id}/messages"),
            Some(request),
        )
        .await
    }
    pub async fn messages(&self, id: &str, after: i64, limit: u32) -> Result<Page<MessageRecord>> {
        validate_conversation_id(id)?;
        if after < 0 || limit == 0 || limit > 500 {
            bail!("message page cursor or limit is invalid");
        }
        self.json::<(), _>(
            Method::GET,
            &format!("/v1/conversations/{id}/messages?after={after}&limit={limit}"),
            None,
        )
        .await
    }
    pub async fn acknowledge(&self, id: &str, through_sequence: i64) -> Result<()> {
        validate_conversation_id(id)?;
        if through_sequence < 0 {
            bail!("acknowledgement sequence cannot be negative");
        }
        self.empty(
            Method::POST,
            &format!("/v1/conversations/{id}/acknowledgements"),
            Some(&serde_json::json!({"through_sequence": through_sequence})),
        )
        .await
    }
    pub async fn revoke_delegation(&self, delegation_id: Uuid) -> Result<()> {
        self.empty::<()>(
            Method::DELETE,
            &format!("/v1/auth/delegations/{delegation_id}"),
            None,
        )
        .await
    }

    async fn json<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T> {
        self.json_with_limit(method, path, body, MAX_CONVERSATION_RESPONSE_BYTES)
            .await
    }

    async fn json_with_limit<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        response_limit: usize,
    ) -> Result<T> {
        let url = self
            .base_url
            .join(path.trim_start_matches('/'))
            .context("build conversation URL")?;
        let mut request = self
            .http
            .request(method, url)
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(token) = self.access_token.as_deref() {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.context("send conversation request")?;
        let status = response.status();
        if response
            .content_length()
            .is_some_and(|length| length > response_limit as u64)
        {
            bail!("conversation response exceeds bounded limit");
        }
        let mut encoded = Vec::with_capacity(
            response
                .content_length()
                .unwrap_or_default()
                .min(response_limit as u64) as usize,
        );
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("read conversation response")?;
            if encoded.len().saturating_add(chunk.len()) > response_limit {
                bail!("conversation response exceeds bounded limit");
            }
            encoded.extend_from_slice(&chunk);
        }
        let value: ApiResponse<T> =
            serde_json::from_slice(&encoded).context("decode conversation response")?;
        if !status.is_success() || value.success != Some(true) {
            bail!(
                "conversation HTTP {}: {}",
                status,
                value.error.unwrap_or_else(|| "request failed".to_string())
            );
        }
        value
            .data
            .ok_or_else(|| anyhow!("conversation response has no data"))
    }

    async fn empty<B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<()> {
        let url = self
            .base_url
            .join(path.trim_start_matches('/'))
            .context("build conversation URL")?;
        let mut request = self.http.request(method, url);
        if let Some(token) = self.access_token.as_deref() {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        request
            .send()
            .await
            .context("send conversation request")?
            .error_for_status()
            .context("conversation request failed")?;
        Ok(())
    }
}

fn is_reachability_error(error: &anyhow::Error) -> bool {
    let mut request_error = None;
    let mut reachable_io_failure = false;
    for cause in error.chain() {
        if let Some(cause) = cause.downcast_ref::<std::io::Error>() {
            reachable_io_failure |= matches!(
                cause.kind(),
                std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::AddrNotAvailable
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::NetworkUnreachable
                    | std::io::ErrorKind::HostUnreachable
            );
        }
        if let Some(cause) = cause.downcast_ref::<reqwest::Error>() {
            request_error = Some(cause);
        }
    }
    request_error.is_some_and(|error| error.is_timeout() || reachable_io_failure)
}

#[derive(Default)]
struct ParsedSseEvent {
    kind: Option<String>,
    data: Option<String>,
}

fn sse_boundary(buffer: &[u8]) -> Option<(usize, usize)> {
    let lf = buffer
        .windows(2)
        .position(|value| value == b"\n\n")
        .map(|index| (index, 2));
    let crlf = buffer
        .windows(4)
        .position(|value| value == b"\r\n\r\n")
        .map(|index| (index, 4));
    match (lf, crlf) {
        (Some(left), Some(right)) => Some(if left.0 <= right.0 { left } else { right }),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn parse_sse_block(block: &[u8]) -> Result<ParsedSseEvent> {
    let block = std::str::from_utf8(block).context("decode conversation SSE event")?;
    let mut event = ParsedSseEvent::default();
    for line in block.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.strip_prefix(' ').unwrap_or(value);
        match name {
            "event" => event.kind = Some(value.to_string()),
            "data" => {
                if let Some(data) = event.data.as_mut() {
                    data.push('\n');
                    data.push_str(value);
                } else {
                    event.data = Some(value.to_string());
                }
            }
            _ => {}
        }
    }
    Ok(event)
}

#[derive(Debug, Deserialize)]
struct ApiResponse<T> {
    success: Option<bool>,
    data: Option<T>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eRecipient {
    pub key_id: String,
    pub public_key: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct E2eWrappedKey {
    key_id: String,
    nonce: String,
    ciphertext: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct E2eEnvelopeV1 {
    version: u16,
    epoch: u64,
    ephemeral_public_key: String,
    content_nonce: String,
    ciphertext: String,
    recipients: Vec<E2eWrappedKey>,
}

pub fn encrypt_e2e(
    conversation_id: &str,
    epoch: u64,
    plaintext: &MessagePayload,
    recipients: &[E2eRecipient],
) -> Result<MessagePayload> {
    validate_conversation_id(conversation_id)?;
    if i64::try_from(epoch).is_err() {
        bail!("E2E epoch exceeds the protocol range");
    }
    validate_plaintext_payload(plaintext)?;
    if recipients.is_empty() || recipients.len() > 256 {
        bail!("E2E encryption requires plaintext and recipients");
    }
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral);
    let mut content_key = [0u8; 32];
    OsRng.fill_bytes(&mut content_key);
    let mut content_nonce = [0u8; 24];
    OsRng.fill_bytes(&mut content_nonce);
    let content_aad = format!("{E2E_CONTENT_DOMAIN}\n{conversation_id}\n{epoch}");
    let encoded = serde_jcs::to_vec(plaintext).context("canonicalize E2E plaintext")?;
    let ciphertext = XChaCha20Poly1305::new((&content_key).into())
        .encrypt(
            XNonce::from_slice(&content_nonce),
            Payload {
                msg: &encoded,
                aad: content_aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow!("encrypt E2E content"))?;
    let mut wrapped = Vec::with_capacity(recipients.len());
    let mut seen = BTreeSet::new();
    for recipient in recipients {
        if recipient.key_id.is_empty()
            || recipient.key_id.len() > 256
            || recipient.key_id.chars().any(char::is_control)
        {
            bail!("E2E recipient key ID is invalid");
        }
        if !seen.insert(recipient.key_id.clone()) {
            bail!("duplicate E2E recipient key ID");
        }
        let bytes: [u8; 32] = hex::decode(&recipient.public_key)
            .context("decode recipient key")?
            .try_into()
            .map_err(|_| anyhow!("recipient key must be 32 bytes"))?;
        let shared = ephemeral.diffie_hellman(&X25519PublicKey::from(bytes));
        if !shared.was_contributory() {
            bail!("E2E recipient public key is non-contributory");
        }
        let wrap_aad = format!(
            "{E2E_WRAP_DOMAIN}\n{conversation_id}\n{epoch}\n{}",
            recipient.key_id
        );
        let mut wrap_key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(conversation_id.as_bytes()), shared.as_bytes())
            .expand(wrap_aad.as_bytes(), &mut wrap_key)
            .map_err(|_| anyhow!("derive E2E wrap key"))?;
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let encrypted_key = XChaCha20Poly1305::new((&wrap_key).into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &content_key,
                    aad: wrap_aad.as_bytes(),
                },
            )
            .map_err(|_| anyhow!("wrap E2E content key"))?;
        wrapped.push(E2eWrappedKey {
            key_id: recipient.key_id.clone(),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(encrypted_key),
        });
    }
    let envelope = E2eEnvelopeV1 {
        version: 1,
        epoch,
        ephemeral_public_key: hex::encode(ephemeral_public.as_bytes()),
        content_nonce: URL_SAFE_NO_PAD.encode(content_nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        recipients: wrapped,
    };
    Ok(MessagePayload::Ciphertext {
        ciphertext: URL_SAFE_NO_PAD
            .encode(serde_jcs::to_vec(&envelope).context("encode E2E envelope")?),
    })
}

pub fn decrypt_e2e(
    conversation_id: &str,
    expected_epoch: u64,
    payload: &MessagePayload,
    recipient_key_id: &str,
    recipient_secret: [u8; 32],
) -> Result<MessagePayload> {
    validate_conversation_id(conversation_id)?;
    if i64::try_from(expected_epoch).is_err()
        || recipient_key_id.is_empty()
        || recipient_key_id.len() > 256
        || recipient_key_id.chars().any(char::is_control)
    {
        bail!("E2E epoch or recipient key ID is invalid");
    }
    let MessagePayload::Ciphertext { ciphertext } = payload else {
        bail!("E2E payload is not ciphertext");
    };
    let envelope: E2eEnvelopeV1 = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(ciphertext)
            .context("decode E2E envelope")?,
    )
    .context("parse E2E envelope")?;
    if envelope.version != 1 || envelope.epoch != expected_epoch {
        bail!("E2E envelope version or epoch mismatch");
    }
    if envelope.recipients.is_empty() || envelope.recipients.len() > 256 {
        bail!("E2E envelope recipient count is invalid");
    }
    let mut recipient_ids = BTreeSet::new();
    if envelope.recipients.iter().any(|recipient| {
        recipient.key_id.is_empty()
            || recipient.key_id.len() > 256
            || recipient.key_id.chars().any(char::is_control)
            || !recipient_ids.insert(&recipient.key_id)
    }) {
        bail!("E2E envelope recipient IDs are invalid");
    }
    let ephemeral: [u8; 32] = hex::decode(&envelope.ephemeral_public_key)
        .context("decode ephemeral key")?
        .try_into()
        .map_err(|_| anyhow!("ephemeral key must be 32 bytes"))?;
    let recipient = envelope
        .recipients
        .iter()
        .find(|item| item.key_id == recipient_key_id)
        .ok_or_else(|| anyhow!("recipient is not included in E2E envelope"))?;
    let secret = StaticSecret::from(recipient_secret);
    let shared = secret.diffie_hellman(&X25519PublicKey::from(ephemeral));
    if !shared.was_contributory() {
        bail!("E2E ephemeral public key is non-contributory");
    }
    let wrap_aad =
        format!("{E2E_WRAP_DOMAIN}\n{conversation_id}\n{expected_epoch}\n{recipient_key_id}");
    let mut wrap_key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(conversation_id.as_bytes()), shared.as_bytes())
        .expand(wrap_aad.as_bytes(), &mut wrap_key)
        .map_err(|_| anyhow!("derive E2E wrap key"))?;
    let nonce = URL_SAFE_NO_PAD
        .decode(&recipient.nonce)
        .context("decode wrap nonce")?;
    let encrypted_key = URL_SAFE_NO_PAD
        .decode(&recipient.ciphertext)
        .context("decode wrapped key")?;
    if nonce.len() != 24 {
        bail!("invalid wrap nonce");
    }
    let content_key = XChaCha20Poly1305::new((&wrap_key).into())
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &encrypted_key,
                aad: wrap_aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow!("unwrap E2E content key"))?;
    if content_key.len() != 32 {
        bail!("invalid E2E content key");
    }
    let content_aad = format!("{E2E_CONTENT_DOMAIN}\n{conversation_id}\n{expected_epoch}");
    let content_nonce = URL_SAFE_NO_PAD
        .decode(&envelope.content_nonce)
        .context("decode content nonce")?;
    if content_nonce.len() != 24 {
        bail!("invalid content nonce");
    }
    let encrypted = URL_SAFE_NO_PAD
        .decode(&envelope.ciphertext)
        .context("decode E2E ciphertext")?;
    let plaintext = XChaCha20Poly1305::new_from_slice(&content_key)
        .map_err(|_| anyhow!("invalid E2E content key"))?
        .decrypt(
            XNonce::from_slice(&content_nonce),
            Payload {
                msg: &encrypted,
                aad: content_aad.as_bytes(),
            },
        )
        .map_err(|_| anyhow!("decrypt E2E content"))?;
    let plaintext: MessagePayload =
        serde_json::from_slice(&plaintext).context("decode E2E plaintext")?;
    validate_plaintext_payload(&plaintext)?;
    Ok(plaintext)
}

fn validate_message_payload(payload: &MessagePayload, key_epoch: Option<u64>) -> Result<()> {
    match payload {
        MessagePayload::Plaintext { .. } => {
            if key_epoch.is_some() {
                bail!("plaintext messages cannot include a key epoch");
            }
            validate_plaintext_payload(payload)
        }
        MessagePayload::Ciphertext { ciphertext } => {
            if key_epoch.is_none()
                || ciphertext.is_empty()
                || ciphertext.len() % 4 == 1
                || !ciphertext
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                bail!("ciphertext messages require URL-safe ciphertext and a key epoch");
            }
            Ok(())
        }
    }
}

fn validate_plaintext_payload(payload: &MessagePayload) -> Result<()> {
    let MessagePayload::Plaintext { parts } = payload else {
        bail!("E2E plaintext has an invalid payload encoding");
    };
    if parts.is_empty() || parts.len() > 256 {
        bail!("plaintext messages require 1-256 parts");
    }
    for part in parts {
        if let MessagePart::ArtifactReference {
            digest, media_type, ..
        } = part
        {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || media_type.is_empty()
                || media_type.len() > 255
                || media_type.chars().any(char::is_control)
            {
                bail!(
                    "artifact references require a lowercase SHA-256 digest and bounded media type"
                );
            }
        }
    }
    Ok(())
}

fn validate_x25519_public_key(public_key: [u8; 32]) -> Result<()> {
    let probe = StaticSecret::from([0x42; 32]);
    if !probe
        .diffie_hellman(&X25519PublicKey::from(public_key))
        .was_contributory()
    {
        bail!("encryption public key is non-contributory");
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedMessage {
    pub conversation_id: String,
    pub request: SubmitMessageRequest,
    pub attempts: u32,
    pub next_attempt_ms: i64,
    pub last_error: Option<String>,
}

pub struct FileOutbox {
    path: PathBuf,
    max_entries: usize,
    max_bytes: u64,
    lock: Mutex<()>,
}

impl FileOutbox {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            max_entries: DEFAULT_OUTBOX_MAX_ENTRIES,
            max_bytes: DEFAULT_OUTBOX_MAX_BYTES,
            lock: Mutex::new(()),
        }
    }

    pub fn with_limits(
        path: impl Into<PathBuf>,
        max_entries: usize,
        max_bytes: u64,
    ) -> Result<Self> {
        if max_entries == 0 || max_bytes == 0 {
            bail!("outbox limits must be greater than zero");
        }
        Ok(Self {
            path: path.into(),
            max_entries,
            max_bytes,
            lock: Mutex::new(()),
        })
    }

    pub fn enqueue(
        &self,
        conversation_id: impl Into<String>,
        request: SubmitMessageRequest,
    ) -> Result<()> {
        let _guard = self.lock()?;
        let conversation_id = conversation_id.into();
        let mut items = self.load_unlocked()?;
        if let Some(existing) = items
            .iter()
            .find(|item| item.request.message_id == request.message_id)
        {
            if existing.conversation_id == conversation_id && existing.request == request {
                return Ok(());
            }
            bail!("outbox message ID is already bound to different content");
        }
        if items.len() >= self.max_entries {
            bail!("conversation outbox entry limit reached");
        }
        items.push(QueuedMessage {
            conversation_id,
            request,
            attempts: 0,
            next_attempt_ms: now_ms(),
            last_error: None,
        });
        self.store_unlocked(&items)
    }

    pub fn due(&self, current_time_ms: i64, limit: usize) -> Result<Vec<QueuedMessage>> {
        let _guard = self.lock()?;
        Ok(self
            .load_unlocked()?
            .into_iter()
            .filter(|item| item.next_attempt_ms <= current_time_ms)
            .take(limit)
            .collect())
    }

    pub fn mark_sent(&self, message_id: Uuid) -> Result<()> {
        let _guard = self.lock()?;
        let mut items = self.load_unlocked()?;
        items.retain(|item| item.request.message_id != message_id);
        self.store_unlocked(&items)
    }

    pub fn mark_failed(
        &self,
        message_id: Uuid,
        error: impl Into<String>,
        current_time_ms: i64,
    ) -> Result<()> {
        let _guard = self.lock()?;
        let mut items = self.load_unlocked()?;
        let item = items
            .iter_mut()
            .find(|item| item.request.message_id == message_id)
            .ok_or_else(|| anyhow!("outbox message not found"))?;
        item.attempts = item.attempts.saturating_add(1);
        let delay = 250_i64
            .saturating_mul(1_i64 << item.attempts.min(8))
            .min(60_000);
        item.next_attempt_ms = current_time_ms.saturating_add(delay);
        item.last_error = Some(error.into().chars().take(MAX_OUTBOX_ERROR_CHARS).collect());
        self.store_unlocked(&items)
    }
    pub async fn flush(&self, client: &ConversationClient, limit: usize) -> Result<usize> {
        let current = now_ms();
        let items = self.due(current, limit)?;
        let mut sent = 0;
        for item in items {
            match client.submit(&item.conversation_id, &item.request).await {
                Ok(_) => {
                    self.mark_sent(item.request.message_id)?;
                    sent += 1;
                }
                Err(error) => {
                    self.mark_failed(item.request.message_id, format!("{error:#}"), current)?;
                }
            }
        }
        Ok(sent)
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ()>> {
        self.lock
            .lock()
            .map_err(|_| anyhow!("conversation outbox lock is poisoned"))
    }

    fn load_unlocked(&self) -> Result<Vec<QueuedMessage>> {
        if let Ok(metadata) = fs::metadata(&self.path) {
            if metadata.len() > self.max_bytes {
                bail!("conversation outbox byte limit exceeded");
            }
        }
        match fs::read(&self.path) {
            Ok(bytes) => {
                let items: Vec<QueuedMessage> =
                    serde_json::from_slice(&bytes).context("decode conversation outbox")?;
                if items.len() > self.max_entries {
                    bail!("conversation outbox entry limit exceeded");
                }
                Ok(items)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(error).context("read conversation outbox"),
        }
    }

    fn store_unlocked(&self, items: &[QueuedMessage]) -> Result<()> {
        if items.len() > self.max_entries {
            bail!("conversation outbox entry limit exceeded");
        }
        let bytes = serde_json::to_vec(items).context("encode conversation outbox")?;
        if bytes.len() as u64 > self.max_bytes {
            bail!("conversation outbox byte limit exceeded");
        }
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).context("create outbox directory")?;
        }
        let mut suffix = [0u8; 16];
        OsRng.fill_bytes(&mut suffix);
        let temp = self
            .path
            .with_extension(format!("tmp-{}", hex::encode(suffix)));
        let result = (|| -> Result<()> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temp).context("create temporary outbox")?;
            file.write_all(&bytes).context("write temporary outbox")?;
            file.sync_all().context("sync temporary outbox")?;
            drop(file);
            fs::rename(&temp, &self.path).context("replace conversation outbox")?;
            #[cfg(unix)]
            if let Some(parent) = self.path.parent() {
                fs::File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .context("sync outbox directory")?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
}

pub fn conversation_profile_from_metadata(metadata: &[u8]) -> Result<ConversationProfileV2> {
    if metadata.len() > 4_096 {
        bail!("conversation profile exceeds agent metadata limit");
    }
    let profile: ConversationProfileV2 =
        serde_json::from_slice(metadata).context("decode conversation profile")?;
    validate_conversation_profile(&profile)?;
    Ok(profile)
}

pub fn conversation_profile_metadata(profile: &ConversationProfileV2) -> Result<Vec<u8>> {
    validate_conversation_profile(profile)?;
    let bytes = serde_jcs::to_vec(profile).context("encode conversation profile")?;
    if bytes.len() > 4_096 {
        bail!("conversation profile exceeds agent metadata limit");
    }
    Ok(bytes)
}

pub fn verify_conversation_service_profile(
    advertised: &ConversationProfileV2,
    live: &ConversationProfileV2,
) -> Result<()> {
    validate_conversation_profile(advertised)?;
    validate_conversation_profile(live)?;
    if advertised != live {
        bail!("live conversation profile does not match authenticated agent metadata");
    }
    Ok(())
}

pub fn validate_conversation_profile(profile: &ConversationProfileV2) -> Result<()> {
    if profile.version != 2 || !profile.protocol_versions.contains(&1) {
        bail!("unsupported conversation profile");
    }
    validate_service_id(&profile.service_id)?;
    if profile.privacy_modes.is_empty()
        || profile
            .privacy_modes
            .iter()
            .enumerate()
            .any(|(index, mode)| profile.privacy_modes[..index].contains(mode))
        || profile.protocol_versions.is_empty()
        || profile.protocol_versions.len() > MAX_PROTOCOL_VERSIONS
        || profile.protocol_versions.contains(&0)
        || profile
            .protocol_versions
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            != profile.protocol_versions.len()
    {
        bail!("conversation profile capabilities must be non-empty and unique");
    }
    if profile.interfaces.is_empty() || profile.interfaces.len() > 4 {
        bail!("conversation profile must advertise 1-4 interfaces");
    }
    let mut identities = BTreeSet::new();
    for interface in &profile.interfaces {
        let identity = match interface {
            ConversationInterface::Https { url } => {
                if url.chars().count() > MAX_HTTPS_INTERFACE_URL_LENGTH {
                    bail!("HTTPS conversation interface URL exceeds the supported length");
                }
                let parsed = Url::parse(url)
                    .context("conversation profile HTTPS interface URL is invalid")?;
                validate_conversation_url(&parsed)?;
                if parsed.scheme() != "https" {
                    bail!("advertised HTTPS interface must use HTTPS");
                }
                format!("https:{parsed}")
            }
            ConversationInterface::ZinchaTlsV1 {
                host,
                port,
                certificate_pins,
            } => {
                let address: std::net::IpAddr = host
                    .parse()
                    .context("zincha-tls-v1 host must be a literal IP address")?;
                if *host != address.to_string() || *port == 0 {
                    bail!("zincha-tls-v1 host or port is not canonical");
                }
                if certificate_pins.is_empty() || certificate_pins.len() > 2 {
                    bail!("zincha-tls-v1 requires one active and at most one next pin");
                }
                let mut hashes = BTreeSet::new();
                for pin in certificate_pins {
                    if pin.sha256.len() != 64
                        || !pin
                            .sha256
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                        || pin.not_before_ms >= pin.not_after_ms
                        || !hashes.insert(&pin.sha256)
                    {
                        bail!("zincha-tls-v1 certificate pin is invalid or duplicated");
                    }
                }
                format!("zincha_tls_v1:{host}:{port}")
            }
        };
        if !identities.insert(identity) {
            bail!("conversation profile interfaces must be unique");
        }
    }
    if serde_jcs::to_vec(profile)
        .context("encode conversation profile")?
        .len()
        > 4_096
    {
        bail!("conversation profile exceeds agent metadata limit");
    }
    Ok(())
}

fn direct_tls_url(host: &str, port: u16) -> Result<Url> {
    let address: std::net::IpAddr = host
        .parse()
        .context("zincha-tls-v1 host must be a literal IP address")?;
    let authority = if address.is_ipv6() {
        format!("[{address}]:{port}")
    } else {
        format!("{address}:{port}")
    };
    Url::parse(&format!("https://{authority}/")).context("build zincha-tls-v1 URL")
}

pub fn validate_subject_ref(subject: &SubjectRef) -> Result<()> {
    if subject.network.trim().is_empty()
        || subject.network.len() > 64
        || subject.network.chars().any(char::is_control)
        || subject.chain_id.trim().is_empty()
        || subject.chain_id.len() > 128
        || subject.chain_id.chars().any(char::is_control)
    {
        bail!("conversation subject network or chain ID is invalid");
    }
    validate_conversation_id(&subject.id).context("conversation subject identifier is invalid")
}

pub fn validate_conversation_id(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("identifier must be 32 bytes of lowercase hexadecimal");
    }
    Ok(())
}

fn validate_service_id(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.chars().count() > 256 || value.chars().any(char::is_control)
    {
        bail!("conversation profile service ID is invalid");
    }
    Ok(())
}

fn validate_address(value: &str) -> Result<()> {
    let body = value
        .strip_prefix("zn1")
        .ok_or_else(|| anyhow!("conversation address must use the zn1 prefix"))?;
    if body.len() != 40
        || !body
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("conversation address is invalid");
    }
    Ok(())
}

fn validate_conversation_url(url: &Url) -> Result<()> {
    if !url.username().is_empty() || url.password().is_some() {
        bail!("conversation service URL must not contain credentials");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("conversation service URL has no host"))?;
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        bail!("conversation service URL must use HTTPS, except for loopback development");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("conversation service URL cannot contain a query or fragment");
    }
    Ok(())
}

pub fn outbox_path(parent: &Path) -> PathBuf {
    parent.join("zincha-conversation-outbox.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn valid_profile() -> ConversationProfileV2 {
        ConversationProfileV2 {
            version: 2,
            service_id: "marketplace.example/conversations".into(),
            interfaces: vec![
                ConversationInterface::ZinchaTlsV1 {
                    host: "203.0.113.25".into(),
                    port: 443,
                    certificate_pins: vec![TlsCertificatePin {
                        sha256: "ab".repeat(32),
                        not_before_ms: 1_791_000_000_000,
                        not_after_ms: 1_822_536_000_000,
                    }],
                },
                ConversationInterface::Https {
                    url: "https://conversations.example/v1".into(),
                },
            ],
            privacy_modes: vec![PrivacyMode::PlatformReadable, PrivacyMode::EndToEnd],
            protocol_versions: vec![1],
        }
    }

    fn queued_request(message_id: Uuid) -> SubmitMessageRequest {
        SubmitMessageRequest {
            message_id,
            client_timestamp_ms: 1,
            reply_to: None,
            key_epoch: None,
            payload: MessagePayload::Plaintext {
                parts: vec![MessagePart::Text {
                    text: "hello".into(),
                }],
            },
            signing_key_id: Uuid::nil().to_string(),
            signature: "00".repeat(64),
        }
    }

    #[test]
    fn e2e_round_trip_and_wrong_context_fails() {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        let plaintext = MessagePayload::Plaintext {
            parts: vec![MessagePart::Text {
                text: "hello".into(),
            }],
        };
        let encrypted = encrypt_e2e(
            &"cd".repeat(32),
            7,
            &plaintext,
            &[E2eRecipient {
                key_id: "recipient".into(),
                public_key: hex::encode(public.as_bytes()),
            }],
        )
        .unwrap();
        assert!(encrypt_e2e(
            &"cd".repeat(32),
            7,
            &MessagePayload::Plaintext { parts: vec![] },
            &[E2eRecipient {
                key_id: "recipient".into(),
                public_key: hex::encode(public.as_bytes()),
            }],
        )
        .is_err());
        assert_eq!(
            decrypt_e2e(
                &"cd".repeat(32),
                7,
                &encrypted,
                "recipient",
                secret.to_bytes()
            )
            .unwrap(),
            plaintext
        );
        assert!(decrypt_e2e(
            &"ef".repeat(32),
            7,
            &encrypted,
            "recipient",
            secret.to_bytes()
        )
        .is_err());
        assert!(decrypt_e2e(
            &"cd".repeat(32),
            8,
            &encrypted,
            "recipient",
            secret.to_bytes()
        )
        .is_err());
        assert!(decrypt_e2e(
            &"cd".repeat(32),
            7,
            &encrypted,
            "missing-recipient",
            secret.to_bytes()
        )
        .is_err());

        let MessagePayload::Ciphertext { ciphertext } = &encrypted else {
            panic!("E2E encryption must produce ciphertext");
        };
        let mut envelope: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(ciphertext).unwrap()).unwrap();
        let mut content = URL_SAFE_NO_PAD
            .decode(envelope["ciphertext"].as_str().unwrap())
            .unwrap();
        content[0] ^= 1;
        envelope["ciphertext"] = Value::String(URL_SAFE_NO_PAD.encode(content));
        let tampered = MessagePayload::Ciphertext {
            ciphertext: URL_SAFE_NO_PAD.encode(serde_jcs::to_vec(&envelope).unwrap()),
        };
        assert!(decrypt_e2e(
            &"cd".repeat(32),
            7,
            &tampered,
            "recipient",
            secret.to_bytes()
        )
        .is_err());

        let mut non_contributory_ephemeral: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(ciphertext).unwrap()).unwrap();
        non_contributory_ephemeral["ephemeral_public_key"] = Value::String("00".repeat(32));
        let non_contributory_ephemeral = MessagePayload::Ciphertext {
            ciphertext: URL_SAFE_NO_PAD
                .encode(serde_jcs::to_vec(&non_contributory_ephemeral).unwrap()),
        };
        assert!(decrypt_e2e(
            &"cd".repeat(32),
            7,
            &non_contributory_ephemeral,
            "recipient",
            secret.to_bytes()
        )
        .is_err());

        assert!(encrypt_e2e(
            &"cd".repeat(32),
            7,
            &plaintext,
            &[E2eRecipient {
                key_id: "non-contributory".into(),
                public_key: "00".repeat(32),
            }],
        )
        .is_err());
        assert!(encrypt_e2e(
            &"cd".repeat(32),
            u64::MAX,
            &plaintext,
            &[E2eRecipient {
                key_id: "recipient".into(),
                public_key: hex::encode(public.as_bytes()),
            }],
        )
        .is_err());
    }

    #[test]
    fn message_signing_rejects_payload_and_epoch_mismatches() {
        let operational = Keypair::from_secret_bytes(&[9; 32]);
        let sender = operational.address().to_string();
        let plaintext = MessagePayload::Plaintext {
            parts: vec![MessagePart::Text {
                text: "hello".into(),
            }],
        };
        assert!(sign_message(
            &operational,
            Uuid::nil(),
            &"cd".repeat(32),
            &sender,
            plaintext,
            None,
            Some(1),
        )
        .is_err());
        assert!(sign_message(
            &operational,
            Uuid::nil(),
            &"cd".repeat(32),
            &sender,
            MessagePayload::Ciphertext {
                ciphertext: "AA".into(),
            },
            None,
            None,
        )
        .is_err());
        assert!(sign_message(
            &operational,
            Uuid::nil(),
            &"cd".repeat(32),
            &sender,
            MessagePayload::Plaintext {
                parts: vec![MessagePart::ArtifactReference {
                    artifact_id: Uuid::nil(),
                    digest: "GG".repeat(32),
                    media_type: "text/plain".into(),
                    size: 1,
                }],
            },
            None,
            None,
        )
        .is_err());
    }

    #[test]
    fn protocol_bytes_match_cross_language_golden() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../sdk/testdata/golden-conversation-v1.json");
        let value: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let delegation: ConversationKeyDelegationV1 =
            serde_json::from_value(value["delegation"].clone()).unwrap();
        let payload: MessagePayload = serde_json::from_value(value["payload"].clone()).unwrap();
        let request: SubmitMessageRequest =
            serde_json::from_value(value["message"].clone()).unwrap();
        assert_eq!(
            hex::encode(delegation_signing_bytes(&delegation)),
            value["delegation_signing_hex"]
        );
        let digest = payload_digest(&payload).unwrap();
        assert_eq!(digest, value["payload_digest"]);
        assert_eq!(
            hex::encode(message_signing_bytes(
                value["conversation_id"].as_str().unwrap(),
                value["sender"].as_str().unwrap(),
                &request,
                &digest,
            )),
            value["message_signing_hex"]
        );
    }

    #[test]
    fn e2e_decrypts_cross_language_golden() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../sdk/testdata/golden-conversation-e2e-v1.json");
        let value: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let payload: MessagePayload = serde_json::from_value(value["payload"].clone()).unwrap();
        let secret: [u8; 32] = hex::decode(value["recipient_secret_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let plaintext = decrypt_e2e(
            value["conversation_id"].as_str().unwrap(),
            value["epoch"].as_u64().unwrap(),
            &payload,
            value["recipient_key_id"].as_str().unwrap(),
            secret,
        )
        .unwrap();
        assert_eq!(serde_json::to_value(plaintext).unwrap(), value["plaintext"]);
    }

    #[test]
    fn sse_parser_handles_crlf_and_multiline_data() {
        let bytes = b"event: message\r\ndata: {\"a\":\r\ndata: 1}\r\n\r\ntrailing";
        let (boundary, separator) = sse_boundary(bytes).unwrap();
        assert_eq!(separator, 4);
        let parsed = parse_sse_block(&bytes[..boundary]).unwrap();
        assert_eq!(parsed.kind.as_deref(), Some("message"));
        assert_eq!(parsed.data.as_deref(), Some("{\"a\":\n1}"));
    }

    #[test]
    fn profiles_and_client_urls_are_strictly_validated() {
        let profile = valid_profile();
        let metadata = conversation_profile_metadata(&profile).unwrap();
        assert_eq!(
            conversation_profile_from_metadata(&metadata).unwrap(),
            profile
        );
        verify_conversation_service_profile(&profile, &profile).unwrap();
        let mut mismatched = profile.clone();
        mismatched.service_id = "different.example/conversations".into();
        assert!(verify_conversation_service_profile(&profile, &mismatched).is_err());

        let mut invalid = profile.clone();
        invalid.interfaces = vec![ConversationInterface::Https {
            url: "http://conversations.example".into(),
        }];
        assert!(validate_conversation_profile(&invalid).is_err());
        invalid = profile.clone();
        let ConversationInterface::ZinchaTlsV1 {
            certificate_pins, ..
        } = &mut invalid.interfaces[0]
        else {
            unreachable!()
        };
        certificate_pins.push(certificate_pins[0].clone());
        assert!(validate_conversation_profile(&invalid).is_err());
        invalid = profile.clone();
        let ConversationInterface::ZinchaTlsV1 {
            certificate_pins, ..
        } = &mut invalid.interfaces[0]
        else {
            unreachable!()
        };
        certificate_pins[0].sha256 = "AB".repeat(32);
        assert!(validate_conversation_profile(&invalid).is_err());
        invalid = profile.clone();
        let ConversationInterface::ZinchaTlsV1 {
            certificate_pins, ..
        } = &mut invalid.interfaces[0]
        else {
            unreachable!()
        };
        certificate_pins[0].not_after_ms = certificate_pins[0].not_before_ms;
        assert!(validate_conversation_profile(&invalid).is_err());
        invalid.interfaces = vec![ConversationInterface::Https {
            url: "https://user:secret@conversations.example".into(),
        }];
        assert!(validate_conversation_profile(&invalid).is_err());
        invalid.interfaces = vec![ConversationInterface::ZinchaTlsV1 {
            host: "203.000.113.25".into(),
            port: 443,
            certificate_pins: vec![TlsCertificatePin {
                sha256: "ab".repeat(32),
                not_before_ms: 1,
                not_after_ms: 2,
            }],
        }];
        assert!(validate_conversation_profile(&invalid).is_err());
        invalid.interfaces = vec![ConversationInterface::Https {
            url: format!("https://conversations.example/{}", "x".repeat(4_096)),
        }];
        assert!(validate_conversation_profile(&invalid).is_err());
        invalid = profile.clone();
        invalid.protocol_versions = (1..=65).collect();
        assert!(validate_conversation_profile(&invalid).is_err());
        invalid = profile.clone();
        invalid.protocol_versions = vec![1, 0];
        assert!(validate_conversation_profile(&invalid).is_err());
        invalid = profile.clone();
        invalid.service_id = "💻".repeat(256);
        assert!(validate_conversation_profile(&invalid).is_ok());
        invalid.service_id.push('💻');
        assert!(validate_conversation_profile(&invalid).is_err());
        assert!(ConversationClient::new("http://127.0.0.1:8080/base").is_ok());
        assert!(ConversationClient::new("http://conversations.example").is_err());
        assert!(ConversationClient::new("https://user:secret@conversations.example").is_err());
        assert!(conversation_profile_from_metadata(&vec![b'x'; 4_097]).is_err());
        let client = ConversationClient::new("https://conversations.example").unwrap();
        assert!(client.events_url("../profile", 0).is_err());
        assert!(validate_subject_ref(&SubjectRef {
            network: "testnet".into(),
            chain_id: "zincha-test".into(),
            kind: SubjectKind::Task,
            id: "AB".repeat(32),
        })
        .is_err());
    }

    #[test]
    fn profile_v2_matches_cross_language_golden_vector() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../sdk/testdata/golden-conversation-profile-v2.json"
        ))
        .unwrap();
        let profile: ConversationProfileV2 =
            serde_json::from_value(vector["profile"].clone()).unwrap();
        assert_eq!(
            String::from_utf8(conversation_profile_metadata(&profile).unwrap()).unwrap(),
            vector["canonical_json"].as_str().unwrap()
        );
        assert_eq!(
            conversation_profile_from_metadata(
                vector["canonical_json"].as_str().unwrap().as_bytes()
            )
            .unwrap(),
            profile
        );
    }

    #[tokio::test]
    async fn live_profile_response_is_bounded_before_decode() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0u8; 8 * 1024];
            let read = stream.read(&mut request).await.unwrap();
            request.truncate(read);
            let body = vec![b'x'; MAX_PROFILE_RESPONSE_BYTES + 1];
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(headers.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
            request
        });
        let client = ConversationClient::new(format!("http://{address}")).unwrap();
        let error = client.profile().await.unwrap_err();
        assert!(format!("{error:#}").contains("bounded limit"));
        let request = server.await.unwrap();
        assert!(!String::from_utf8_lossy(&request)
            .to_ascii_lowercase()
            .contains("authorization:"));
    }

    fn rotation_test_identity_for(
        not_before_year: i32,
        not_after_year: i32,
    ) -> (CertificateDer<'static>, Vec<u8>, TlsCertificatePin) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut parameters = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
        parameters.not_before = rcgen::date_time_ymd(not_before_year, 1, 1);
        parameters.not_after = rcgen::date_time_ymd(not_after_year, 1, 1);
        let certificate = parameters.self_signed(&key).unwrap();
        let (_, parsed) = x509_parser::parse_x509_certificate(certificate.der()).unwrap();
        let pin = TlsCertificatePin {
            sha256: hex::encode(Sha256::digest(certificate.der())),
            not_before_ms: parsed.validity().not_before.timestamp() * 1_000,
            not_after_ms: parsed.validity().not_after.timestamp() * 1_000,
        };
        (certificate.der().clone(), key.serialize_der(), pin)
    }

    fn rotation_test_identity() -> (CertificateDer<'static>, Vec<u8>, TlsCertificatePin) {
        rotation_test_identity_for(2026, 2030)
    }

    async fn spawn_rotation_profile_server(
        certificate: CertificateDer<'static>,
        private_key: Vec<u8>,
        pins: Vec<TlsCertificatePin>,
        unavailable_port: Option<u16>,
    ) -> (
        ConversationProfileV2,
        tokio::task::JoinHandle<()>,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut interfaces = vec![ConversationInterface::ZinchaTlsV1 {
            host: "127.0.0.1".to_string(),
            port,
            certificate_pins: pins,
        }];
        if let Some(unavailable_port) = unavailable_port {
            interfaces.insert(
                0,
                ConversationInterface::Https {
                    url: format!("https://127.0.0.1:{unavailable_port}"),
                },
            );
            interfaces.push(ConversationInterface::Https {
                url: format!("https://127.0.0.1:{unavailable_port}/after-pin-failure"),
            });
        }
        let profile = ConversationProfileV2 {
            version: 2,
            service_id: "provider/conversations".to_string(),
            interfaces,
            privacy_modes: vec![PrivacyMode::PlatformReadable],
            protocol_versions: vec![1],
        };
        let body = Arc::new(
            serde_json::to_vec(&serde_json::json!({"success": true, "data": &profile})).unwrap(),
        );
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut server = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate],
                rustls::pki_types::PrivatePkcs8KeyDer::from(private_key).into(),
            )
            .unwrap();
        server.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server_requests = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                let body = body.clone();
                let requests = server_requests.clone();
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut request = vec![0u8; 8 * 1024];
                    if stream.read(&mut request).await.is_err() {
                        return;
                    }
                    requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let headers = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(headers.as_bytes()).await;
                    let _ = stream.write_all(&body).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        (profile, task, requests)
    }

    #[tokio::test]
    async fn pinned_transport_enforces_complete_rotation_matrix() {
        let (old_certificate, old_key, old_pin) = rotation_test_identity();
        let (next_certificate, next_key, next_pin) = rotation_test_identity();
        assert_ne!(old_pin.sha256, next_pin.sha256);
        let unavailable = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unavailable_port = unavailable.local_addr().unwrap().port();
        drop(unavailable);
        let mut tasks = Vec::new();

        let (old_only, task, old_only_requests) = spawn_rotation_profile_server(
            old_certificate.clone(),
            old_key.clone(),
            vec![old_pin.clone()],
            None,
        )
        .await;
        tasks.push(task);
        ConversationClient::from_profile(&old_only, ConversationTransportPolicy::ZinchaTlsOnly)
            .await
            .unwrap();
        assert_eq!(
            old_only_requests.load(std::sync::atomic::Ordering::Relaxed),
            1
        );

        let (overlap_old, task, overlap_old_requests) = spawn_rotation_profile_server(
            old_certificate.clone(),
            old_key,
            vec![old_pin.clone(), next_pin.clone()],
            Some(unavailable_port),
        )
        .await;
        tasks.push(task);
        ConversationClient::from_profile(&overlap_old, ConversationTransportPolicy::Auto)
            .await
            .unwrap();
        assert_eq!(
            overlap_old_requests.load(std::sync::atomic::Ordering::Relaxed),
            1
        );

        let (overlap_new, task, overlap_new_requests) = spawn_rotation_profile_server(
            next_certificate.clone(),
            next_key.clone(),
            vec![old_pin, next_pin.clone()],
            None,
        )
        .await;
        tasks.push(task);
        ConversationClient::from_profile(&overlap_new, ConversationTransportPolicy::ZinchaTlsOnly)
            .await
            .unwrap();
        assert_eq!(
            overlap_new_requests.load(std::sync::atomic::Ordering::Relaxed),
            1
        );

        let (new_only, task, new_only_requests) =
            spawn_rotation_profile_server(next_certificate, next_key, vec![next_pin.clone()], None)
                .await;
        tasks.push(task);
        ConversationClient::from_profile(&new_only, ConversationTransportPolicy::ZinchaTlsOnly)
            .await
            .unwrap();
        assert_eq!(
            new_only_requests.load(std::sync::atomic::Ordering::Relaxed),
            1
        );

        let mut mismatched_validity = overlap_old.clone();
        let ConversationInterface::ZinchaTlsV1 {
            certificate_pins, ..
        } = mismatched_validity
            .interfaces
            .iter_mut()
            .find(|interface| matches!(interface, ConversationInterface::ZinchaTlsV1 { .. }))
            .unwrap()
        else {
            unreachable!()
        };
        certificate_pins[0].not_before_ms += 1_000;
        let error = match ConversationClient::from_profile(
            &mismatched_validity,
            ConversationTransportPolicy::Auto,
        )
        .await
        {
            Ok(_) => panic!("mismatched certificate validity unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("validity does not match"));
        assert_eq!(
            overlap_old_requests.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "mismatched validity must fail before HTTP application data"
        );

        for (not_before_year, not_after_year) in [(2040, 2041), (2020, 2021)] {
            let (certificate, key, pin) =
                rotation_test_identity_for(not_before_year, not_after_year);
            let (invalid_time, task, requests) =
                spawn_rotation_profile_server(certificate, key, vec![pin], None).await;
            tasks.push(task);
            let error = match ConversationClient::from_profile(
                &invalid_time,
                ConversationTransportPolicy::ZinchaTlsOnly,
            )
            .await
            {
                Ok(_) => panic!("invalid certificate time unexpectedly succeeded"),
                Err(error) => error,
            };
            assert!(format!("{error:#}").contains("outside its advertised validity"));
            assert_eq!(
                requests.load(std::sync::atomic::Ordering::Relaxed),
                0,
                "invalid certificate time must fail before HTTP application data"
            );
        }

        let mut old_removed = overlap_old;
        let ConversationInterface::ZinchaTlsV1 {
            certificate_pins, ..
        } = old_removed
            .interfaces
            .iter_mut()
            .find(|interface| matches!(interface, ConversationInterface::ZinchaTlsV1 { .. }))
            .unwrap()
        else {
            unreachable!()
        };
        *certificate_pins = vec![next_pin];
        let error =
            match ConversationClient::from_profile(&old_removed, ConversationTransportPolicy::Auto)
                .await
            {
                Ok(_) => panic!("wrong certificate pin unexpectedly succeeded"),
                Err(error) => error,
            };
        assert!(
            format!("{error:#}").contains("certificate pin mismatch"),
            "pin failure must be terminal instead of falling through: {error:#}"
        );
        assert_eq!(
            overlap_old_requests.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "removed old pin must fail before HTTP application data"
        );
        for task in tasks {
            task.abort();
        }
    }

    #[test]
    fn file_outbox_is_durable_private_and_bounded() {
        let directory = std::env::temp_dir().join(format!("zincha-outbox-{}", Uuid::new_v4()));
        let path = directory.join("outbox.json");
        let outbox = FileOutbox::with_limits(&path, 1, 1024 * 1024).unwrap();
        let request = queued_request(Uuid::new_v4());
        outbox.enqueue("conversation", request.clone()).unwrap();
        outbox.enqueue("conversation", request).unwrap();
        assert_eq!(outbox.due(i64::MAX, 10).unwrap().len(), 1);
        assert!(outbox
            .enqueue("conversation", queued_request(Uuid::new_v4()))
            .is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(directory).unwrap();
    }
}
