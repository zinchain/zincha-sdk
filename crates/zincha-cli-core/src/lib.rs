use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::env;
use zincha_client::ZinchaClient;

mod output;
mod query;
mod secret;
mod support;
mod surface;
mod tx;
mod wallet;
mod watch;

pub use output::emit;

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
    #[arg(long, global = true)]
    pub bearer_token: Option<String>,
    #[arg(long, global = true, default_value = "ZINCHA_BEARER_TOKEN")]
    pub bearer_token_env: String,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Keygen(wallet::KeygenCommand),
    Wallet(wallet::WalletCommand),
    Tx(tx::TxCommand),
    Query(query::QueryCommand),
    Info,
    Faucet(wallet::FaucetCommand),
    Watch(watch::WatchCommand),
}

#[derive(Clone)]
pub struct CliContext {
    pub json: bool,
    pub bearer_token: Option<String>,
}

pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    run_cli(cli).await
}

pub async fn run_cli(cli: Cli) -> Result<()> {
    surface::assert_public_surface();
    let bearer_token = cli.bearer_token.clone().or_else(|| {
        env::var(&cli.bearer_token_env)
            .ok()
            .filter(|value| !value.is_empty())
    });
    let context = CliContext {
        json: cli.json,
        bearer_token: bearer_token.clone(),
    };
    let api_url = cli.api_url.clone();
    let release = cli.release.clone();
    match cli.command {
        Commands::Keygen(command) => wallet::run_keygen(command, &context),
        Commands::Wallet(command) => wallet::run_wallet(command, &context),
        Commands::Tx(command) => {
            tx::run_tx(command, client(api_url, release, bearer_token)?, &context).await
        }
        Commands::Query(command) => {
            query::run_query(command, client(api_url, release, bearer_token)?, &context).await
        }
        Commands::Info => emit(
            "info",
            client(api_url, release, bearer_token)?.chain_info().await?,
            context.json,
        ),
        Commands::Faucet(command) => {
            wallet::run_faucet(command, client(api_url, release, bearer_token)?, &context).await
        }
        Commands::Watch(command) => {
            watch::run_watch(command, client(api_url, release, bearer_token)?, &context).await
        }
    }
}

fn client(
    api_url: String,
    release: Option<String>,
    bearer_token: Option<String>,
) -> Result<ZinchaClient> {
    let mut builder = ZinchaClient::builder();
    builder = match release.as_deref() {
        Some(release) => builder.release(release),
        None => builder.base_url(&api_url),
    };
    if let Some(token) = bearer_token {
        builder = builder.bearer_token(token);
    }
    builder.build().with_context(|| {
        release
            .map(|release| format!("build client for release {release}"))
            .unwrap_or_else(|| format!("build client for API URL {api_url}"))
    })
}
