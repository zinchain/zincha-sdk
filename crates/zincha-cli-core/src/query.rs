use crate::output::emit;
use crate::secret::{load_keypair, KeySourceArgs};
use crate::CliContext;
use anyhow::{bail, Result};
use clap::{Args, Parser, Subcommand};
use reqwest::Method;
use serde_json::Value;
use zincha_client::{RequestOptions, ZinchaClient};

#[derive(Debug, Parser)]
pub struct QueryCommand {
    #[command(subcommand)]
    pub command: Option<QueryCommands>,
    pub path: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum QueryCommands {
    Chain,
    Block {
        height_or_hash: String,
    },
    Blocks {
        #[arg(long)]
        limit: Option<u64>,
    },
    Account {
        address: String,
    },
    AccountNonce {
        address: String,
    },
    AccountTransactions {
        address: String,
        #[arg(long)]
        limit: Option<u64>,
    },
    Agent {
        address: String,
    },
    Agents,
    RequesterReputation {
        address: String,
    },
    Task {
        task_id: String,
    },
    Tasks,
    Tool {
        tool_id: String,
    },
    Tools,
    Subscription {
        subscription_id: String,
    },
    Agreement {
        agreement_id: String,
    },
    Contract {
        address: String,
    },
    Route {
        deployer: String,
        route_name: String,
    },
    Token {
        token_id: String,
    },
    Arbitrator {
        address: String,
    },
    Events {
        #[arg(long)]
        topic: Option<String>,
        #[arg(long)]
        limit: Option<u64>,
    },
    Tx {
        hash: String,
    },
    Validator {
        address: String,
    },
    Validators,
    Participant(ParticipantQuery),
}

#[derive(Debug, Args)]
pub struct ParticipantQuery {
    #[command(flatten)]
    pub signer: KeySourceArgs,
    pub path: String,
}

pub async fn run_query(
    command: QueryCommand,
    client: ZinchaClient,
    context: &CliContext,
) -> Result<()> {
    let (label, payload) = match command.command {
        Some(QueryCommands::Chain) => ("query-chain", client.chain_info().await?),
        Some(QueryCommands::Block { height_or_hash }) => (
            "query-block",
            client.get(&format!("/v1/blocks/{height_or_hash}")).await?,
        ),
        Some(QueryCommands::Blocks { limit }) => (
            "query-blocks",
            get_with_limit(&client, "/v1/blocks", limit).await?,
        ),
        Some(QueryCommands::Account { address }) => (
            "query-account",
            client.get(&format!("/v1/accounts/{address}")).await?,
        ),
        Some(QueryCommands::AccountNonce { address }) => {
            ("query-account-nonce", client.nonce(&address).await?)
        }
        Some(QueryCommands::AccountTransactions { address, limit }) => (
            "query-account-transactions",
            get_with_limit(
                &client,
                &format!("/v1/accounts/{address}/transactions"),
                limit,
            )
            .await?,
        ),
        Some(QueryCommands::Agent { address }) => (
            "query-agent",
            client.get(&format!("/v1/agents/{address}")).await?,
        ),
        Some(QueryCommands::Agents) => ("query-agents", client.get("/v1/agents").await?),
        Some(QueryCommands::RequesterReputation { address }) => (
            "query-requester-reputation",
            client
                .get(&format!("/v1/requesters/{address}/reputation"))
                .await?,
        ),
        Some(QueryCommands::Task { task_id }) => (
            "query-task",
            client.get(&format!("/v1/tasks/{task_id}")).await?,
        ),
        Some(QueryCommands::Tasks) => ("query-tasks", client.get("/v1/tasks").await?),
        Some(QueryCommands::Tool { tool_id }) => (
            "query-tool",
            client.get(&format!("/v1/tools/{tool_id}")).await?,
        ),
        Some(QueryCommands::Tools) => ("query-tools", client.get("/v1/tools").await?),
        Some(QueryCommands::Subscription { subscription_id }) => (
            "query-subscription",
            client
                .get(&format!("/v1/tool-subscriptions/{subscription_id}"))
                .await?,
        ),
        Some(QueryCommands::Agreement { agreement_id }) => (
            "query-agreement",
            client
                .get(&format!("/v1/agreements/{agreement_id}"))
                .await?,
        ),
        Some(QueryCommands::Contract { address }) => (
            "query-contract",
            client.get(&format!("/v1/contracts/{address}")).await?,
        ),
        Some(QueryCommands::Route {
            deployer,
            route_name,
        }) => (
            "query-route",
            client
                .get(&format!("/v1/contracts/routes/{deployer}/{route_name}"))
                .await?,
        ),
        Some(QueryCommands::Token { token_id }) => (
            "query-token",
            client.get(&format!("/v1/tokens/{token_id}")).await?,
        ),
        Some(QueryCommands::Arbitrator { address }) => (
            "query-arbitrator",
            client.get(&format!("/v1/arbitrators/{address}")).await?,
        ),
        Some(QueryCommands::Events { topic, limit }) => {
            let mut opts = RequestOptions::default();
            if let Some(topic) = topic {
                opts = opts.query_param("topic", topic);
            }
            if let Some(limit) = limit {
                opts = opts.query_param("limit", limit.to_string());
            }
            (
                "query-events",
                client.request(Method::GET, "/v1/events", opts).await?,
            )
        }
        Some(QueryCommands::Tx { hash }) => ("query-tx", client.transaction_status(&hash).await?),
        Some(QueryCommands::Validator { address }) => (
            "query-validator",
            client.get(&format!("/v1/validators/{address}")).await?,
        ),
        Some(QueryCommands::Validators) => {
            ("query-validators", client.get("/v1/validators").await?)
        }
        Some(QueryCommands::Participant(participant)) => (
            "query-participant",
            run_participant_query(participant, client).await?,
        ),
        None => {
            let path = command
                .path
                .ok_or_else(|| anyhow::anyhow!("query path or typed query command is required"))?;
            ("query", client.get(&path).await?)
        }
    };
    emit(label, payload, context.json)
}

async fn get_with_limit(client: &ZinchaClient, path: &str, limit: Option<u64>) -> Result<Value> {
    if let Some(limit) = limit {
        client
            .request(
                Method::GET,
                path,
                RequestOptions::default().query_param("limit", limit.to_string()),
            )
            .await
    } else {
        client.get(path).await
    }
}

async fn run_participant_query(command: ParticipantQuery, client: ZinchaClient) -> Result<Value> {
    let keypair = load_keypair(&command.signer)?;
    let signer_address = keypair.address().to_string();
    enforce_address_scope(&command.path, &signer_address)?;
    client
        .request(
            Method::GET,
            &command.path,
            RequestOptions::default().signed().signer(keypair),
        )
        .await
}

fn enforce_address_scope(path: &str, signer_address: &str) -> Result<()> {
    for prefix in ["/v1/accounts/", "/v1/agents/", "/v1/requesters/"] {
        if let Some(rest) = path.strip_prefix(prefix) {
            let path_address = rest.split('/').next().unwrap_or_default();
            if !path_address.is_empty() && path_address != signer_address {
                bail!(
                    "signed participant route address {path_address} does not match signer address {signer_address}"
                );
            }
        }
    }
    Ok(())
}
