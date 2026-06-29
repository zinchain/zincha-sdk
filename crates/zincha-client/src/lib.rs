use anyhow::{Context, Result};
use reqwest::{Client, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use zincha_primitives::release::{canonical_rpc_url_for_alias, canonical_websocket_url_for_alias};

#[derive(Debug, Clone)]
pub struct ZinchaClient {
    http: Client,
    base_url: Url,
    websocket_url: Option<Url>,
}

impl ZinchaClient {
    pub fn new(base_url: impl AsRef<str>) -> Result<Self> {
        let base_url = normalize_base_url(base_url.as_ref())?;
        let websocket_url = derive_websocket_url(&base_url).ok();
        let http = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build()
            .context("build HTTP client")?;
        Ok(Self {
            http,
            base_url,
            websocket_url,
        })
    }

    pub fn for_release(alias: &str) -> Result<Self> {
        let Some(url) = canonical_rpc_url_for_alias(alias) else {
            anyhow::bail!("unknown release alias {alias}");
        };
        let mut client = Self::new(url)?;
        client.websocket_url = canonical_websocket_url_for_alias(alias)
            .map(Url::parse)
            .transpose()
            .context("parse canonical release websocket URL")?;
        Ok(client)
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    pub fn websocket_url(&self) -> Option<&Url> {
        self.websocket_url.as_ref()
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let response = self
            .http
            .get(join_path(&self.base_url, path)?)
            .send()
            .await
            .context("send GET request")?;
        decode_response(response).await
    }

    pub async fn post_json<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let response = self
            .http
            .post(join_path(&self.base_url, path)?)
            .json(body)
            .send()
            .await
            .context("send POST request")?;
        decode_response(response).await
    }

    pub async fn chain_info(&self) -> Result<Value> {
        self.get("/v1/chain/info").await
    }

    pub async fn submit_signed_transaction_hex(&self, signed_tx_hex: &str) -> Result<Value> {
        self.post_json(
            "/v1/transactions",
            &SubmitTransactionRequest {
                signed_tx_hex: signed_tx_hex.to_string(),
            },
        )
        .await
    }

    pub async fn request_faucet(&self, address: &str, amount: Option<u64>) -> Result<Value> {
        self.post_json(
            "/v1/faucet/request",
            &FaucetRequest {
                address: address.to_string(),
                amount,
            },
        )
        .await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTransactionRequest {
    pub signed_tx_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaucetRequest {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
}

async fn decode_response<T: DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let status = response.status();
    let bytes = response.bytes().await.context("read response body")?;
    if !status.is_success() {
        let body = String::from_utf8_lossy(&bytes);
        anyhow::bail!("API request failed with HTTP {status}: {body}");
    }
    serde_json::from_slice(&bytes).context("decode JSON response")
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
