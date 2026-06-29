use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use zincha_client::ZinchaClient;
use zincha_primitives::crypto::{Address, Hash256, Keypair};
use zincha_primitives::primitives::Transaction;

#[derive(Debug, Parser)]
#[command(
    name = "zincha",
    about = "Public Zincha developer CLI",
    version = "0.1.0"
)]
pub struct Cli {
    #[arg(long, global = true, default_value = "http://127.0.0.1:9944")]
    pub api_url: String,
    #[arg(long, global = true)]
    pub release: Option<String>,
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Keygen(KeygenCommand),
    Wallet(WalletCommand),
    Tx(TxCommand),
    Query(QueryCommand),
    Info,
    Faucet(FaucetCommand),
    Watch(WatchCommand),
}

#[derive(Debug, Parser)]
pub struct KeygenCommand {
    #[arg(long)]
    pub out: Option<PathBuf>,
    #[arg(long)]
    pub force: bool,
    #[arg(long, conflicts_with = "out")]
    pub unsafe_print_secret: bool,
}

#[derive(Debug, Parser)]
pub struct WalletCommand {
    #[command(subcommand)]
    pub command: WalletCommands,
}

#[derive(Debug, Subcommand)]
pub enum WalletCommands {
    Address {
        #[arg(long)]
        secret_key: String,
    },
}

#[derive(Debug, Parser)]
pub struct TxCommand {
    #[command(subcommand)]
    pub command: TxCommands,
}

#[derive(Debug, Subcommand)]
pub enum TxCommands {
    Transfer {
        #[arg(long)]
        secret_key: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        fee: u64,
        #[arg(long, default_value_t = 0)]
        priority_fee: u64,
        #[arg(long)]
        nonce: u64,
        #[arg(long, default_value = "zincha-vega-1")]
        chain_id: String,
        #[arg(long)]
        reference_block_height: Option<u64>,
        #[arg(long)]
        reference_block_hash: Option<String>,
        #[arg(long)]
        ttl_blocks: Option<u64>,
        #[arg(long)]
        submit: bool,
    },
}

#[derive(Debug, Parser)]
pub struct QueryCommand {
    pub path: String,
}

#[derive(Debug, Parser)]
pub struct FaucetCommand {
    #[arg(long)]
    pub address: String,
    #[arg(long)]
    pub amount_micro_zin: Option<u64>,
    #[arg(long)]
    pub amount_zin: Option<u64>,
}

#[derive(Debug, Parser)]
pub struct WatchCommand {
    #[arg(long, default_value = "/v1/chain/info")]
    pub path: String,
}

pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    run_cli(cli).await
}

pub async fn run_cli(cli: Cli) -> Result<()> {
    let json = cli.json;
    let api_url = cli.api_url.clone();
    let release = cli.release.clone();
    match cli.command {
        Commands::Keygen(command) => run_keygen(command, json),
        Commands::Wallet(command) => run_wallet(command, json),
        Commands::Tx(command) => run_tx(command, client(api_url, release)?, json).await,
        Commands::Query(command) => run_query(command, client(api_url, release)?, json).await,
        Commands::Info => run_info(client(api_url, release)?, json).await,
        Commands::Faucet(command) => run_faucet(command, client(api_url, release)?, json).await,
        Commands::Watch(command) => run_watch(command, client(api_url, release)?, json).await,
    }
}

fn client(api_url: String, release: Option<String>) -> Result<ZinchaClient> {
    match release.as_deref() {
        Some(release) => ZinchaClient::for_release(release),
        None => ZinchaClient::new(&api_url),
    }
}

fn run_keygen(command: KeygenCommand, json: bool) -> Result<()> {
    let keypair = Keypair::generate();
    let address = keypair.address();
    if let Some(path) = command.out.as_ref() {
        write_secret_file(path, &hex::encode(keypair.secret_bytes()), command.force)?;
    }
    let payload = serde_json::json!({
        "address": address.to_string(),
        "public_key": hex::encode(keypair.public_key().as_bytes()),
        "secret_file": command.out.as_ref().map(|path| path.display().to_string()),
        "secret_key": command.unsafe_print_secret.then(|| hex::encode(keypair.secret_bytes())),
    });
    emit("keygen", payload, json)
}

fn run_wallet(command: WalletCommand, json: bool) -> Result<()> {
    match command.command {
        WalletCommands::Address { secret_key } => {
            let keypair = parse_secret_key(&secret_key)?;
            emit(
                "wallet-address",
                serde_json::json!({
                    "address": keypair.address().to_string(),
                    "public_key": hex::encode(keypair.public_key().as_bytes()),
                }),
                json,
            )
        }
    }
}

async fn run_tx(command: TxCommand, client: ZinchaClient, json: bool) -> Result<()> {
    match command.command {
        TxCommands::Transfer {
            secret_key,
            to,
            amount,
            fee,
            priority_fee,
            nonce,
            chain_id,
            reference_block_height,
            reference_block_hash,
            ttl_blocks,
            submit,
        } => {
            let keypair = parse_secret_key(&secret_key)?;
            let recipient =
                Address::from_hex(&to).with_context(|| format!("parse recipient address {to}"))?;
            let mut tx = Transaction::new_transfer(
                keypair.address(),
                recipient,
                amount,
                fee,
                nonce,
                &chain_id,
            );
            tx.timestamp = now_millis()?;
            tx.max_priority_fee_per_gas = priority_fee;
            match (reference_block_height, reference_block_hash, ttl_blocks) {
                (Some(height), Some(hash), Some(ttl)) => {
                    tx.set_validity_window(height, Hash256::from_hex(&hash)?, ttl);
                }
                (None, None, None) => {}
                _ => bail!("reference_block_height, reference_block_hash, and ttl_blocks must be provided together"),
            }
            let signed = tx.sign(&keypair);
            let signed_tx_hex = hex::encode(bincode::serialize(&signed)?);
            let mut payload = serde_json::json!({
                "hash": signed.hash.to_hex(),
                "sender": signed.transaction.sender.to_string(),
                "signed_tx_hex": signed_tx_hex,
            });
            if submit {
                payload["submission"] = client
                    .submit_signed_transaction_hex(
                        payload["signed_tx_hex"].as_str().expect("signed hex"),
                    )
                    .await?;
            }
            emit("tx-transfer", payload, json)
        }
    }
}

async fn run_query(command: QueryCommand, client: ZinchaClient, json: bool) -> Result<()> {
    let payload: Value = client.get(&command.path).await?;
    emit("query", payload, json)
}

async fn run_info(client: ZinchaClient, json: bool) -> Result<()> {
    emit("info", client.chain_info().await?, json)
}

async fn run_faucet(command: FaucetCommand, client: ZinchaClient, json: bool) -> Result<()> {
    emit(
        "faucet",
        client
            .request_faucet(
                &command.address,
                command.amount_micro_zin,
                command.amount_zin,
            )
            .await?,
        json,
    )
}

async fn run_watch(command: WatchCommand, client: ZinchaClient, json: bool) -> Result<()> {
    let payload: Value = client.get(&command.path).await?;
    emit("watch", payload, json)
}

fn parse_secret_key(raw: &str) -> Result<Keypair> {
    let secret = if raw.len() == 64 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
        raw.to_string()
    } else {
        std::fs::read_to_string(raw)
            .with_context(|| format!("read secret key file {raw}"))?
            .trim()
            .to_string()
    };
    let bytes = hex::decode(&secret).context("decode secret key hex")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("secret key must be 32 bytes"))?;
    Ok(Keypair::from_secret_bytes(&bytes))
}

fn write_secret_file(path: &PathBuf, contents: &str, force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!("refusing to overwrite existing key file {}", path.display());
    }
    std::fs::write(path, contents).with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("set private permissions on {}", path.display()))?;
    }
    Ok(())
}

fn emit(command: &'static str, payload: Value, json: bool) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "version": 1,
                "ok": true,
                "command": command,
                "data": payload,
            }))?
        );
    } else {
        println!("{}", serde_json::to_string_pretty(&payload)?);
    }
    Ok(())
}

fn now_millis() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before Unix epoch")?
        .as_millis() as u64)
}
