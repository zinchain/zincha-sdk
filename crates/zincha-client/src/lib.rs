use anyhow::{Context, Result};
use rand::RngCore;
use reqwest::{Client, Method, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zincha_primitives::crypto::{hash_bytes, Keypair};
use zincha_primitives::release::{canonical_rpc_url_for_alias, canonical_websocket_url_for_alias};

const USER_AGENT: &str = concat!("zincha-sdk-rust/", env!("CARGO_PKG_VERSION"));
const SIGNED_REQUEST_PREFIX: &str = "zincha-rpc-signed-request-v1";

#[derive(Clone)]
pub struct ZinchaClient {
    http: Client,
    base_url: Url,
    faucet_url: Option<Url>,
    websocket_url: Option<Url>,
    bearer_token: Option<String>,
    signer: Option<Arc<Keypair>>,
}

impl ZinchaClient {
    pub fn new(base_url: impl AsRef<str>) -> Result<Self> {
        ZinchaClientBuilder::new().base_url(base_url).build()
    }

    pub fn builder() -> ZinchaClientBuilder {
        ZinchaClientBuilder::new()
    }

    pub fn for_release(alias: &str) -> Result<Self> {
        ZinchaClientBuilder::new().release(alias).build()
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    pub fn faucet_url(&self) -> Option<&Url> {
        self.faucet_url.as_ref()
    }

    pub fn websocket_url(&self) -> Option<&Url> {
        self.websocket_url.as_ref()
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.request(Method::GET, path, RequestOptions::default())
            .await
    }

    pub async fn post_json<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let body = serde_json::to_value(body).context("encode request body as JSON value")?;
        self.request(
            Method::POST,
            path,
            RequestOptions {
                body: Some(body),
                ..RequestOptions::default()
            },
        )
        .await
    }

    pub async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        options: RequestOptions,
    ) -> Result<T> {
        let request_target = build_request_target(path, &options.query);
        let url = join_path(&self.base_url, &request_target)?;
        let body_bytes = match options.body {
            Some(body) => Some(serde_json::to_vec(&body).context("serialize JSON request body")?),
            None => None,
        };
        let mut request = self.http.request(method.clone(), url);
        request = request.header(reqwest::header::ACCEPT, "application/json");

        if let Some(bytes) = body_bytes.clone() {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(bytes);
        }

        if let Some(token) = options.bearer_token.as_ref().or(self.bearer_token.as_ref()) {
            request = request.bearer_auth(token);
        }

        if options.signed {
            let signer = options
                .signer
                .as_deref()
                .or(self.signer.as_deref())
                .ok_or_else(|| anyhow::anyhow!("signed request requires a signer"))?;
            let headers = signed_request_headers(
                signer,
                method.as_str(),
                &request_target,
                body_bytes.as_deref().unwrap_or_default(),
                options.timestamp_ms,
                options.nonce.as_deref(),
            )?;
            for (name, value) in headers {
                request = request.header(name, value);
            }
        }

        let response = request.send().await.context("send API request")?;
        decode_response(response).await
    }

    pub async fn chain_info(&self) -> Result<Value> {
        self.get("/v1/chain/info").await
    }

    pub async fn nonce(&self, address: &str) -> Result<Value> {
        self.get(&format!("/v1/accounts/{address}/nonce")).await
    }

    pub async fn account_transactions(
        &self,
        address: &str,
        query: TransactionHistoryQuery,
    ) -> Result<Value> {
        self.request(
            Method::GET,
            &format!("/v1/accounts/{address}/transactions"),
            query.into_request_options(),
        )
        .await
    }

    pub async fn contract_transactions(
        &self,
        address: &str,
        query: TransactionHistoryQuery,
    ) -> Result<Value> {
        self.request(
            Method::GET,
            &format!("/v1/contracts/{address}/transactions"),
            query.into_request_options(),
        )
        .await
    }

    pub async fn token_transactions(
        &self,
        token_id: &str,
        query: TransactionHistoryQuery,
    ) -> Result<Value> {
        self.request(
            Method::GET,
            &format!("/v1/tokens/{token_id}/transactions"),
            query.into_request_options(),
        )
        .await
    }

    pub async fn transaction_status(&self, hash: &str) -> Result<Value> {
        self.get(&format!("/v1/tx/{hash}")).await
    }

    pub async fn wait_for_transaction(
        &self,
        hash: &str,
        timeout: Duration,
        interval: Duration,
    ) -> Result<Value> {
        let started = Instant::now();
        loop {
            let status = self.transaction_status(hash).await?;
            if !is_pending_transaction_status(&status) {
                return Ok(status);
            }
            if started.elapsed() >= timeout {
                anyhow::bail!("timed out waiting for transaction {hash}");
            }
            tokio::time::sleep(interval).await;
        }
    }

    pub async fn submit_signed_transaction_hex(&self, signed_tx_hex: &str) -> Result<Value> {
        self.post_json(
            "/v1/tx/submit",
            &SubmitTransactionRequest {
                signed_tx_hex: signed_tx_hex.to_string(),
            },
        )
        .await
    }

    pub async fn submit_batch(&self, signed_txs_hex: Vec<String>) -> Result<Value> {
        self.post_json(
            "/v1/tx/submit/batch",
            &SubmitBatchRequest { signed_txs_hex },
        )
        .await
    }

    pub async fn submit_protected(
        &self,
        signed_tx_hex: String,
        options: ProtectedSubmitOptions,
    ) -> Result<Value> {
        let mut request = RequestOptions::default();
        request.bearer_token = options.bearer_token;
        request.body = Some(json!(ProtectedSubmitRequest {
            signed_tx_hex,
            max_priority_fee_per_gas: options.max_priority_fee_per_gas,
        }));
        self.request(Method::POST, "/v1/tx/submit/protected", request)
            .await
    }

    pub async fn submit_orderflow_bundle(
        &self,
        signed_txs_hex: Vec<String>,
        options: OrderflowBundleOptions,
    ) -> Result<Value> {
        let mut request = RequestOptions::default();
        request.bearer_token = options.bearer_token;
        request.body = Some(json!(OrderflowBundleRequest {
            signed_txs_hex,
            atomic: options.atomic,
            expiration_height: options.expiration_height,
            max_total_fee: options.max_total_fee,
            max_priority_fee_per_gas: options.max_priority_fee_per_gas,
        }));
        self.request(Method::POST, "/v1/orderflow/bundles", request)
            .await
    }

    pub async fn request_faucet(
        &self,
        address: &str,
        amount_micro_zin: Option<u64>,
        amount_zin: Option<u64>,
    ) -> Result<Value> {
        let client = if let Some(url) = &self.faucet_url {
            let mut clone = self.clone();
            clone.base_url = url.clone();
            clone
        } else {
            self.clone()
        };
        client
            .post_json(
                "/v1/faucet",
                &FaucetRequest {
                    address: address.to_string(),
                    amount_micro_zin,
                    amount_zin,
                },
            )
            .await
    }
}

pub struct ZinchaClientBuilder {
    base_url: Option<String>,
    release: Option<String>,
    faucet_url: Option<String>,
    websocket_url: Option<String>,
    bearer_token: Option<String>,
    signer: Option<Keypair>,
}

impl ZinchaClientBuilder {
    pub fn new() -> Self {
        Self {
            base_url: None,
            release: None,
            faucet_url: None,
            websocket_url: None,
            bearer_token: None,
            signer: None,
        }
    }

    pub fn base_url(mut self, base_url: impl AsRef<str>) -> Self {
        self.base_url = Some(base_url.as_ref().to_string());
        self
    }

    pub fn release(mut self, release: impl AsRef<str>) -> Self {
        self.release = Some(release.as_ref().to_string());
        self
    }

    pub fn faucet_url(mut self, faucet_url: impl AsRef<str>) -> Self {
        self.faucet_url = Some(faucet_url.as_ref().to_string());
        self
    }

    pub fn websocket_url(mut self, websocket_url: impl AsRef<str>) -> Self {
        self.websocket_url = Some(websocket_url.as_ref().to_string());
        self
    }

    pub fn bearer_token(mut self, bearer_token: impl Into<String>) -> Self {
        self.bearer_token = Some(bearer_token.into());
        self
    }

    pub fn signer(mut self, signer: Keypair) -> Self {
        self.signer = Some(signer);
        self
    }

    pub fn build(self) -> Result<ZinchaClient> {
        let release_url = match &self.release {
            Some(alias) => Some(
                canonical_rpc_url_for_alias(alias)
                    .ok_or_else(|| anyhow::anyhow!("unknown release alias {alias}"))?
                    .to_string(),
            ),
            None => None,
        };
        let base_url = self
            .base_url
            .as_deref()
            .or(release_url.as_deref())
            .ok_or_else(|| anyhow::anyhow!("base_url or release is required"))?;
        let base_url = normalize_base_url(base_url)?;
        let faucet_url = self
            .faucet_url
            .as_deref()
            .map(normalize_base_url)
            .transpose()?;
        let websocket_url = match self.websocket_url.as_deref() {
            Some(url) => {
                Some(Url::parse(url).with_context(|| format!("parse websocket URL {url}"))?)
            }
            None => match self
                .release
                .as_deref()
                .and_then(canonical_websocket_url_for_alias)
            {
                Some(url) => {
                    Some(Url::parse(url).context("parse canonical release websocket URL")?)
                }
                None => derive_websocket_url(&base_url).ok(),
            },
        };
        let http = Client::builder()
            .user_agent(USER_AGENT)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build()
            .context("build HTTP client")?;
        Ok(ZinchaClient {
            http,
            base_url,
            faucet_url,
            websocket_url,
            bearer_token: self.bearer_token,
            signer: self.signer.map(Arc::new),
        })
    }
}

impl Default for ZinchaClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Default)]
pub struct RequestOptions {
    pub query: Vec<(String, String)>,
    pub body: Option<Value>,
    pub bearer_token: Option<String>,
    pub signed: bool,
    pub signer: Option<Arc<Keypair>>,
    pub timestamp_ms: Option<u64>,
    pub nonce: Option<String>,
}

impl RequestOptions {
    pub fn query_param(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.query.push((name.into(), value.into()));
        self
    }

    pub fn body_json(mut self, body: Value) -> Self {
        self.body = Some(body);
        self
    }

    pub fn bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
        self
    }

    pub fn signed(mut self) -> Self {
        self.signed = true;
        self
    }

    pub fn signer(mut self, signer: Keypair) -> Self {
        self.signer = Some(Arc::new(signer));
        self
    }

    pub fn timestamp_ms(mut self, timestamp_ms: u64) -> Self {
        self.timestamp_ms = Some(timestamp_ms);
        self
    }

    pub fn nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }
}

#[derive(Clone, Debug, Default)]
pub struct TransactionHistoryQuery {
    pub limit: Option<u64>,
    pub cursor: Option<String>,
}

impl TransactionHistoryQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn limit(mut self, limit: u64) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn cursor(mut self, cursor: impl Into<String>) -> Self {
        self.cursor = Some(cursor.into());
        self
    }

    fn into_request_options(self) -> RequestOptions {
        let mut options = RequestOptions::default();
        if let Some(limit) = self.limit {
            options = options.query_param("limit", limit.to_string());
        }
        if let Some(cursor) = self.cursor {
            options = options.query_param("cursor", cursor);
        }
        options
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTransactionRequest {
    pub signed_tx_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitBatchRequest {
    pub signed_txs_hex: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedSubmitRequest {
    pub signed_tx_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_priority_fee_per_gas: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct ProtectedSubmitOptions {
    pub bearer_token: Option<String>,
    pub max_priority_fee_per_gas: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderflowBundleRequest {
    pub signed_txs_hex: Vec<String>,
    #[serde(default)]
    pub atomic: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_total_fee: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_priority_fee_per_gas: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct OrderflowBundleOptions {
    pub bearer_token: Option<String>,
    pub atomic: bool,
    pub expiration_height: Option<u64>,
    pub max_total_fee: Option<u64>,
    pub max_priority_fee_per_gas: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaucetRequest {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_micro_zin: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_zin: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRequestParts {
    pub message: String,
    pub body_sha256: String,
    pub timestamp_ms: u64,
    pub nonce: String,
    pub address: String,
    pub public_key: String,
    pub signature: String,
}

pub fn signed_request_parts(
    signer: &Keypair,
    method: &str,
    request_target: &str,
    body_bytes: &[u8],
    timestamp_ms: Option<u64>,
    nonce: Option<&str>,
) -> Result<SignedRequestParts> {
    let timestamp_ms = timestamp_ms.unwrap_or_else(unix_timestamp_millis);
    let nonce = match nonce {
        Some(nonce) => nonce.to_string(),
        None => random_nonce_hex(),
    };
    let body_sha256 = hash_bytes(body_bytes).to_hex();
    let address = signer.address().to_string();
    let public_key = hex::encode(signer.public_key().as_bytes());
    let message = [
        SIGNED_REQUEST_PREFIX.to_string(),
        method.to_ascii_uppercase(),
        request_target.to_string(),
        timestamp_ms.to_string(),
        nonce.clone(),
        body_sha256.clone(),
        address.clone(),
        public_key.clone(),
    ]
    .join("\n");
    let signature = hex::encode(signer.sign(message.as_bytes()).to_bytes());
    Ok(SignedRequestParts {
        message,
        body_sha256,
        timestamp_ms,
        nonce,
        address,
        public_key,
        signature,
    })
}

pub fn signed_request_headers(
    signer: &Keypair,
    method: &str,
    request_target: &str,
    body_bytes: &[u8],
    timestamp_ms: Option<u64>,
    nonce: Option<&str>,
) -> Result<BTreeMap<String, String>> {
    let parts = signed_request_parts(
        signer,
        method,
        request_target,
        body_bytes,
        timestamp_ms,
        nonce,
    )?;
    Ok(BTreeMap::from([
        ("x-zincha-address".to_string(), parts.address),
        ("x-zincha-public-key".to_string(), parts.public_key),
        ("x-zincha-signature".to_string(), parts.signature),
        (
            "x-zincha-timestamp-ms".to_string(),
            parts.timestamp_ms.to_string(),
        ),
        ("x-zincha-nonce".to_string(), parts.nonce),
        ("x-zincha-body-sha256".to_string(), parts.body_sha256),
    ]))
}

#[derive(Debug, Clone)]
pub struct ZinchaApiError {
    pub status: Option<u16>,
    pub message: String,
    pub data: Option<Value>,
}

impl fmt::Display for ZinchaApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.status {
            Some(status) => write!(f, "API request failed with HTTP {status}: {}", self.message),
            None => write!(f, "API request failed: {}", self.message),
        }
    }
}

impl Error for ZinchaApiError {}

async fn decode_response<T: DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let status = response.status();
    let bytes = response.bytes().await.context("read response body")?;
    let envelope = serde_json::from_slice::<ApiResponse>(&bytes);

    if !status.is_success() {
        return Err(match envelope {
            Ok(api) => ZinchaApiError {
                status: Some(status.as_u16()),
                message: api
                    .error
                    .unwrap_or_else(|| format!("HTTP {status} without API error message")),
                data: api.data,
            }
            .into(),
            Err(_) => ZinchaApiError {
                status: Some(status.as_u16()),
                message: String::from_utf8_lossy(&bytes).to_string(),
                data: None,
            }
            .into(),
        });
    }

    let api = envelope.context("decode API response envelope")?;
    if !api.success {
        return Err(ZinchaApiError {
            status: Some(status.as_u16()),
            message: api
                .error
                .unwrap_or_else(|| "API response reported failure".to_string()),
            data: api.data,
        }
        .into());
    }
    serde_json::from_value(api.data.unwrap_or(Value::Null)).context("decode API response data")
}

#[derive(Debug, Deserialize)]
struct ApiResponse {
    success: bool,
    #[serde(default)]
    data: Option<Value>,
    error: Option<String>,
}

fn normalize_base_url(raw: &str) -> Result<Url> {
    let mut url = Url::parse(raw).with_context(|| format!("parse API URL {raw}"))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        anyhow::bail!("API URL must use http or https");
    }
    let path = url.path().trim_end_matches('/').to_string();
    url.set_path(&path);
    Ok(url)
}

fn derive_websocket_url(base: &Url) -> Result<Url> {
    let mut websocket = base.clone();
    websocket
        .set_scheme(match base.scheme() {
            "http" => "ws",
            "https" => "wss",
            other => anyhow::bail!("cannot derive websocket URL from scheme {other}"),
        })
        .map_err(|_| anyhow::anyhow!("derive websocket URL scheme"))?;
    Ok(websocket)
}

fn join_path(base: &Url, path: &str) -> Result<Url> {
    let normalized = path.trim_start_matches('/');
    base.join(normalized)
        .with_context(|| format!("join API path {path}"))
}

fn build_request_target(path: &str, query: &[(String, String)]) -> String {
    let mut target = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    if !query.is_empty() {
        let mut encoded = url::form_urlencoded::Serializer::new(String::new());
        for (name, value) in query {
            encoded.append_pair(name, value);
        }
        target.push(if target.contains('?') { '&' } else { '?' });
        target.push_str(&encoded.finish());
    }
    target
}

fn unix_timestamp_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn random_nonce_hex() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn is_pending_transaction_status(value: &Value) -> bool {
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .or_else(|| value.pointer("/transaction/status").and_then(Value::as_str))
        .unwrap_or("unknown");
    matches!(
        status,
        "unknown" | "pending" | "accepted" | "queued" | "mempool" | "submitted"
    )
}
