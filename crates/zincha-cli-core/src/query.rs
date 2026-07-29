use crate::output::emit;
use crate::secret::{load_keypair, KeySourceArgs};
use crate::CliContext;
use anyhow::{bail, Result};
use clap::{Args, Parser, Subcommand};
use reqwest::Method;
use serde_json::Value;
use zincha_client::{
    CapabilityListQuery, CapabilitySearchQuery, CursorPageQuery, ParticipantWorkflowQuery,
    PendingTaskListQuery, RequestOptions, TransactionHistoryQuery, ZinchaClient,
};

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
        #[arg(long)]
        cursor: Option<String>,
    },
    Agent {
        address: String,
    },
    Agents {
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        cursor: Option<String>,
    },
    RequesterReputation {
        address: String,
    },
    Capabilities {
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        category: Option<String>,
        #[arg(long)]
        parent: Option<String>,
    },
    Capability {
        slug: String,
    },
    CapabilitySearch {
        text: String,
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        category: Option<String>,
    },
    CapabilityCategories,
    Task {
        #[command(flatten)]
        signer: KeySourceArgs,
        task_id: String,
    },
    TaskOpportunity {
        task_id: String,
    },
    PendingTasks {
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long = "discover-capability")]
        discover_capability: Vec<String>,
        #[arg(long = "discover-min-fee")]
        discover_min_fee: Option<u64>,
        #[arg(long = "discover-fee")]
        discover_fee: Vec<String>,
    },
    Tool {
        tool_id: String,
    },
    Tools {
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        cursor: Option<String>,
    },
    Subscription {
        subscription_id: String,
    },
    Agreement {
        #[command(flatten)]
        signer: KeySourceArgs,
        agreement_id: String,
    },
    AgreementsByParty {
        #[command(flatten)]
        signer: KeySourceArgs,
        address: String,
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        cursor: Option<String>,
    },
    AgreementsByArbitrator {
        #[command(flatten)]
        signer: KeySourceArgs,
        address: String,
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        cursor: Option<String>,
    },
    ToolJob {
        #[command(flatten)]
        signer: KeySourceArgs,
        job_id: String,
    },
    ToolJobsByRequester {
        #[command(flatten)]
        signer: KeySourceArgs,
        address: String,
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        cursor: Option<String>,
    },
    ToolJobsByProvider {
        #[command(flatten)]
        signer: KeySourceArgs,
        address: String,
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        cursor: Option<String>,
    },
    ToolUsageSession {
        #[command(flatten)]
        signer: KeySourceArgs,
        session_id: String,
    },
    ToolUsageSessionsByRequester {
        #[command(flatten)]
        signer: KeySourceArgs,
        address: String,
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        cursor: Option<String>,
    },
    ToolUsageSessionsByProvider {
        #[command(flatten)]
        signer: KeySourceArgs,
        address: String,
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        cursor: Option<String>,
    },
    Contract {
        address: String,
    },
    Contracts {
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        cursor: Option<String>,
    },
    ContractTransactions {
        address: String,
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        cursor: Option<String>,
    },
    Route {
        deployer: String,
        route_name: String,
    },
    Token {
        token_id: String,
    },
    Tokens {
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        cursor: Option<String>,
    },
    TokenTransactions {
        token_id: String,
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        cursor: Option<String>,
    },
    Arbitrator {
        address: String,
    },
    Arbitrators {
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        cursor: Option<String>,
    },
    MarketRates {
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        cursor: Option<String>,
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
        Some(QueryCommands::AccountTransactions {
            address,
            limit,
            cursor,
        }) => (
            "query-account-transactions",
            client
                .account_transactions(&address, transaction_history_query(limit, cursor))
                .await?,
        ),
        Some(QueryCommands::Agent { address }) => (
            "query-agent",
            client.get(&format!("/v1/agents/{address}")).await?,
        ),
        Some(QueryCommands::Agents { limit, cursor }) => (
            "query-agents",
            client.agents(cursor_page_query(limit, cursor)).await?,
        ),
        Some(QueryCommands::RequesterReputation { address }) => (
            "query-requester-reputation",
            client.requester_reputation(&address).await?,
        ),
        Some(QueryCommands::Capabilities {
            limit,
            cursor,
            status,
            category,
            parent,
        }) => (
            "query-capabilities",
            client
                .capabilities(capability_list_query(
                    limit, cursor, status, category, parent,
                ))
                .await?,
        ),
        Some(QueryCommands::Capability { slug }) => {
            ("query-capability", client.capability(&slug).await?)
        }
        Some(QueryCommands::CapabilitySearch {
            text,
            limit,
            cursor,
            status,
            category,
        }) => (
            "query-capability-search",
            client
                .capability_search(
                    &text,
                    capability_search_query(limit, cursor, status, category),
                )
                .await?,
        ),
        Some(QueryCommands::CapabilityCategories) => (
            "query-capability-categories",
            client.capability_categories().await?,
        ),
        Some(QueryCommands::Task { signer, task_id }) => {
            let keypair = load_keypair(&signer)?;
            (
                "query-task",
                client
                    .request(
                        Method::GET,
                        &format!("/v1/tasks/{task_id}"),
                        RequestOptions::default().signed().signer(keypair),
                    )
                    .await?,
            )
        }
        Some(QueryCommands::TaskOpportunity { task_id }) => (
            "query-task-opportunity",
            client.task_opportunity(&task_id).await?,
        ),
        Some(QueryCommands::PendingTasks {
            limit,
            cursor,
            discover_capability,
            discover_min_fee,
            discover_fee,
        }) => (
            "query-pending-tasks",
            client
                .pending_tasks(pending_task_list_query(
                    limit,
                    cursor,
                    discover_capability,
                    discover_min_fee,
                    discover_fee,
                )?)
                .await?,
        ),
        Some(QueryCommands::Tool { tool_id }) => (
            "query-tool",
            client.get(&format!("/v1/tools/{tool_id}")).await?,
        ),
        Some(QueryCommands::Tools { limit, cursor }) => (
            "query-tools",
            client.tools(cursor_page_query(limit, cursor)).await?,
        ),
        Some(QueryCommands::Subscription { subscription_id }) => (
            "query-subscription",
            client
                .get(&format!("/v1/tool-subscriptions/{subscription_id}"))
                .await?,
        ),
        Some(QueryCommands::Agreement {
            signer,
            agreement_id,
        }) => {
            let keypair = load_keypair(&signer)?;
            (
                "query-agreement",
                signed_get(&client, &format!("/v1/agreements/{agreement_id}"), keypair).await?,
            )
        }
        Some(QueryCommands::AgreementsByParty {
            signer,
            address,
            limit,
            cursor,
        }) => (
            "query-agreements-by-party",
            signed_workflow_list(
                &client,
                signer,
                &address,
                &format!("/v1/agreements/party/{address}"),
                limit,
                cursor,
            )
            .await?,
        ),
        Some(QueryCommands::AgreementsByArbitrator {
            signer,
            address,
            limit,
            cursor,
        }) => (
            "query-agreements-by-arbitrator",
            signed_workflow_list(
                &client,
                signer,
                &address,
                &format!("/v1/agreements/arbitrator/{address}"),
                limit,
                cursor,
            )
            .await?,
        ),
        Some(QueryCommands::ToolJob { signer, job_id }) => {
            let keypair = load_keypair(&signer)?;
            (
                "query-tool-job",
                signed_get(&client, &format!("/v1/tool-jobs/{job_id}"), keypair).await?,
            )
        }
        Some(QueryCommands::ToolJobsByRequester {
            signer,
            address,
            limit,
            cursor,
        }) => (
            "query-tool-jobs-by-requester",
            signed_workflow_list(
                &client,
                signer,
                &address,
                &format!("/v1/tool-jobs/requester/{address}"),
                limit,
                cursor,
            )
            .await?,
        ),
        Some(QueryCommands::ToolJobsByProvider {
            signer,
            address,
            limit,
            cursor,
        }) => (
            "query-tool-jobs-by-provider",
            signed_workflow_list(
                &client,
                signer,
                &address,
                &format!("/v1/tool-jobs/provider/{address}"),
                limit,
                cursor,
            )
            .await?,
        ),
        Some(QueryCommands::ToolUsageSession { signer, session_id }) => {
            let keypair = load_keypair(&signer)?;
            (
                "query-tool-usage-session",
                signed_get(
                    &client,
                    &format!("/v1/tool-usage-sessions/{session_id}"),
                    keypair,
                )
                .await?,
            )
        }
        Some(QueryCommands::ToolUsageSessionsByRequester {
            signer,
            address,
            limit,
            cursor,
        }) => (
            "query-tool-usage-sessions-by-requester",
            signed_workflow_list(
                &client,
                signer,
                &address,
                &format!("/v1/tool-usage-sessions/requester/{address}"),
                limit,
                cursor,
            )
            .await?,
        ),
        Some(QueryCommands::ToolUsageSessionsByProvider {
            signer,
            address,
            limit,
            cursor,
        }) => (
            "query-tool-usage-sessions-by-provider",
            signed_workflow_list(
                &client,
                signer,
                &address,
                &format!("/v1/tool-usage-sessions/provider/{address}"),
                limit,
                cursor,
            )
            .await?,
        ),
        Some(QueryCommands::Contract { address }) => (
            "query-contract",
            client.get(&format!("/v1/contracts/{address}")).await?,
        ),
        Some(QueryCommands::Contracts { limit, cursor }) => (
            "query-contracts",
            client.contracts(cursor_page_query(limit, cursor)).await?,
        ),
        Some(QueryCommands::ContractTransactions {
            address,
            limit,
            cursor,
        }) => (
            "query-contract-transactions",
            client
                .contract_transactions(&address, transaction_history_query(limit, cursor))
                .await?,
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
        Some(QueryCommands::Tokens { limit, cursor }) => (
            "query-tokens",
            client.tokens(cursor_page_query(limit, cursor)).await?,
        ),
        Some(QueryCommands::TokenTransactions {
            token_id,
            limit,
            cursor,
        }) => (
            "query-token-transactions",
            client
                .token_transactions(&token_id, transaction_history_query(limit, cursor))
                .await?,
        ),
        Some(QueryCommands::Arbitrator { address }) => (
            "query-arbitrator",
            client.get(&format!("/v1/arbitrators/{address}")).await?,
        ),
        Some(QueryCommands::Arbitrators { limit, cursor }) => (
            "query-arbitrators",
            client.arbitrators(cursor_page_query(limit, cursor)).await?,
        ),
        Some(QueryCommands::MarketRates { limit, cursor }) => (
            "query-market-rates",
            client
                .market_rates(cursor_page_query(limit, cursor))
                .await?,
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
        Some(QueryCommands::Validators) => ("query-validators", client.validators().await?),
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

fn transaction_history_query(
    limit: Option<u64>,
    cursor: Option<String>,
) -> TransactionHistoryQuery {
    let mut query = TransactionHistoryQuery::new();
    if let Some(limit) = limit {
        query = query.limit(limit);
    }
    if let Some(cursor) = cursor {
        query = query.cursor(cursor);
    }
    query
}

fn capability_list_query(
    limit: Option<u64>,
    cursor: Option<String>,
    status: Option<String>,
    category: Option<String>,
    parent: Option<String>,
) -> CapabilityListQuery {
    let mut query = CapabilityListQuery::new();
    if let Some(limit) = limit {
        query = query.limit(limit);
    }
    if let Some(cursor) = cursor {
        query = query.cursor(cursor);
    }
    if let Some(status) = status {
        query = query.status(status);
    }
    if let Some(category) = category {
        query = query.category(category);
    }
    if let Some(parent) = parent {
        query = query.parent(parent);
    }
    query
}

fn capability_search_query(
    limit: Option<u64>,
    cursor: Option<String>,
    status: Option<String>,
    category: Option<String>,
) -> CapabilitySearchQuery {
    let mut query = CapabilitySearchQuery::new();
    if let Some(limit) = limit {
        query = query.limit(limit);
    }
    if let Some(cursor) = cursor {
        query = query.cursor(cursor);
    }
    if let Some(status) = status {
        query = query.status(status);
    }
    if let Some(category) = category {
        query = query.category(category);
    }
    query
}

fn cursor_page_query(limit: Option<u64>, cursor: Option<String>) -> CursorPageQuery {
    let mut query = CursorPageQuery::new();
    if let Some(limit) = limit {
        query = query.limit(limit);
    }
    if let Some(cursor) = cursor {
        query = query.cursor(cursor);
    }
    query
}

fn pending_task_list_query(
    limit: Option<u64>,
    cursor: Option<String>,
    discover_capabilities: Vec<String>,
    discover_min_fee: Option<u64>,
    discover_fees: Vec<String>,
) -> Result<PendingTaskListQuery> {
    let mut query = PendingTaskListQuery::new();
    if let Some(limit) = limit {
        query = query.limit(limit);
    }
    if let Some(cursor) = cursor {
        query = query.cursor(cursor);
    }
    for capability in discover_capabilities {
        query = query.discover_capability(capability);
    }
    if let Some(fee) = discover_min_fee {
        query = query.discover_min_fee(fee);
    }
    for entry in discover_fees {
        let (capability, fee) = entry.split_once(':').ok_or_else(|| {
            anyhow::anyhow!("invalid --discover-fee {entry:?}: expected capability:fee")
        })?;
        let fee = fee.parse::<u64>().map_err(|error| {
            anyhow::anyhow!("invalid --discover-fee {entry:?}: fee must be an integer: {error}")
        })?;
        query = query.discover_fee(capability, fee);
    }
    Ok(query)
}

fn participant_workflow_query(
    limit: Option<u64>,
    cursor: Option<String>,
) -> ParticipantWorkflowQuery {
    let mut query = ParticipantWorkflowQuery::new();
    if let Some(limit) = limit {
        query = query.limit(limit);
    }
    if let Some(cursor) = cursor {
        query = query.cursor(cursor);
    }
    query
}

async fn signed_get(
    client: &ZinchaClient,
    path: &str,
    keypair: zincha_primitives::crypto::Keypair,
) -> Result<Value> {
    client
        .request(
            Method::GET,
            path,
            RequestOptions::default().signed().signer(keypair),
        )
        .await
}

async fn signed_workflow_list(
    client: &ZinchaClient,
    signer: KeySourceArgs,
    address: &str,
    path: &str,
    limit: Option<u64>,
    cursor: Option<String>,
) -> Result<Value> {
    let keypair = load_keypair(&signer)?;
    let signer_address = keypair.address().to_string();
    if signer_address != address {
        bail!(
            "signed participant query address mismatch: signer address {signer_address} does not match path address {address}"
        );
    }
    let query = participant_workflow_query(limit, cursor);
    let mut options = RequestOptions::default().signed().signer(keypair);
    if let Some(limit) = query.limit {
        options = options.query_param("limit", limit.to_string());
    }
    if let Some(cursor) = query.cursor {
        options = options.query_param("cursor", cursor);
    }
    client.request(Method::GET, path, options).await
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    #[test]
    fn account_transactions_accepts_cursor_not_offset() {
        let parsed = QueryCommand::try_parse_from([
            "query",
            "account-transactions",
            "zn1abc",
            "--limit",
            "5",
            "--cursor",
            "abcdef",
        ])
        .expect("parse account transaction history query");

        match parsed.command.expect("typed query command") {
            QueryCommands::AccountTransactions {
                address,
                limit,
                cursor,
            } => {
                assert_eq!(address, "zn1abc");
                assert_eq!(limit, Some(5));
                assert_eq!(cursor.as_deref(), Some("abcdef"));
            }
            other => panic!("unexpected query command {other:?}"),
        }

        let err = QueryCommand::try_parse_from([
            "query",
            "account-transactions",
            "zn1abc",
            "--offset",
            "0",
        ])
        .expect_err("offset must not parse for transaction history");
        assert!(err.to_string().contains("--offset"), "{err}");
    }

    #[test]
    fn contract_and_token_transactions_accept_cursor_not_offset() {
        let contract = QueryCommand::try_parse_from([
            "query",
            "contract-transactions",
            "zn1contract",
            "--limit",
            "2",
            "--cursor",
            "c0ffee",
        ])
        .expect("parse contract transaction history query");
        match contract.command.expect("typed query command") {
            QueryCommands::ContractTransactions {
                address,
                limit,
                cursor,
            } => {
                assert_eq!(address, "zn1contract");
                assert_eq!(limit, Some(2));
                assert_eq!(cursor.as_deref(), Some("c0ffee"));
            }
            other => panic!("unexpected query command {other:?}"),
        }

        let token = QueryCommand::try_parse_from([
            "query",
            "token-transactions",
            "11",
            "--limit",
            "3",
            "--cursor",
            "abcdef",
        ])
        .expect("parse token transaction history query");
        match token.command.expect("typed query command") {
            QueryCommands::TokenTransactions {
                token_id,
                limit,
                cursor,
            } => {
                assert_eq!(token_id, "11");
                assert_eq!(limit, Some(3));
                assert_eq!(cursor.as_deref(), Some("abcdef"));
            }
            other => panic!("unexpected query command {other:?}"),
        }

        for command in ["contract-transactions", "token-transactions"] {
            let err = QueryCommand::try_parse_from(["query", command, "zn1abc", "--offset", "0"])
                .expect_err("offset must not parse for transaction history");
            assert!(err.to_string().contains("--offset"), "{err}");
        }
    }

    #[test]
    fn transaction_history_help_shows_cursor_not_offset() {
        let mut command = QueryCommand::command();
        for name in [
            "account-transactions",
            "contract-transactions",
            "token-transactions",
        ] {
            let help = command
                .find_subcommand_mut(name)
                .unwrap_or_else(|| panic!("missing subcommand {name}"))
                .render_long_help()
                .to_string();
            assert!(help.contains("--cursor"), "{help}");
            assert!(!help.contains("--offset"), "{help}");
        }
    }

    #[test]
    fn capability_catalog_queries_are_public_and_cursor_paged() {
        let parsed = QueryCommand::try_parse_from([
            "query",
            "capabilities",
            "--limit",
            "25",
            "--cursor",
            "ai.reasoning",
            "--status",
            "all",
            "--category",
            "ai",
            "--parent",
            "ai.reasoning",
        ])
        .expect("parse capability catalog query");
        match parsed.command.expect("typed query command") {
            QueryCommands::Capabilities {
                limit,
                cursor,
                status,
                category,
                parent,
            } => {
                assert_eq!(limit, Some(25));
                assert_eq!(cursor.as_deref(), Some("ai.reasoning"));
                assert_eq!(status.as_deref(), Some("all"));
                assert_eq!(category.as_deref(), Some("ai"));
                assert_eq!(parent.as_deref(), Some("ai.reasoning"));
            }
            other => panic!("unexpected query command {other:?}"),
        }

        let detail = QueryCommand::try_parse_from(["query", "capability", "ai.reasoning"])
            .expect("parse capability detail query");
        match detail.command.expect("typed query command") {
            QueryCommands::Capability { slug } => assert_eq!(slug, "ai.reasoning"),
            other => panic!("unexpected query command {other:?}"),
        }

        let search = QueryCommand::try_parse_from([
            "query",
            "capability-search",
            "smart contract",
            "--limit",
            "10",
            "--cursor",
            "search-page",
            "--status",
            "active",
            "--category",
            "blockchain",
        ])
        .expect("parse capability search query");
        match search.command.expect("typed query command") {
            QueryCommands::CapabilitySearch {
                text,
                limit,
                cursor,
                status,
                category,
            } => {
                assert_eq!(text, "smart contract");
                assert_eq!(limit, Some(10));
                assert_eq!(cursor.as_deref(), Some("search-page"));
                assert_eq!(status.as_deref(), Some("active"));
                assert_eq!(category.as_deref(), Some("blockchain"));
            }
            other => panic!("unexpected query command {other:?}"),
        }

        let categories = QueryCommand::try_parse_from(["query", "capability-categories"])
            .expect("parse capability categories query");
        assert!(matches!(
            categories.command.expect("typed query command"),
            QueryCommands::CapabilityCategories
        ));

        let err = QueryCommand::try_parse_from(["query", "capabilities", "--offset", "0"])
            .expect_err("offset must not parse for capability catalog list");
        assert!(err.to_string().contains("--offset"), "{err}");

        let mut command = QueryCommand::command();
        for name in [
            "capabilities",
            "capability",
            "capability-search",
            "capability-categories",
        ] {
            let help = command
                .find_subcommand_mut(name)
                .unwrap_or_else(|| panic!("missing subcommand {name}"))
                .render_long_help()
                .to_string();
            assert!(!help.contains("--secret-key"), "{help}");
            assert!(!help.contains("--key-file"), "{help}");
            assert!(!help.contains("--keystore"), "{help}");
        }
        let help = command
            .find_subcommand_mut("capabilities")
            .expect("missing capabilities subcommand")
            .render_long_help()
            .to_string();
        assert!(help.contains("--cursor"), "{help}");
        assert!(!help.contains("--offset"), "{help}");

        let search_help = command
            .find_subcommand_mut("capability-search")
            .expect("missing capability-search subcommand")
            .render_long_help()
            .to_string();
        assert!(search_help.contains("--cursor"), "{search_help}");
        assert!(!search_help.contains("--offset"), "{search_help}");
    }

    #[test]
    fn public_list_queries_accept_cursor_not_offset() {
        let mut command = QueryCommand::command();
        for name in [
            "agents",
            "tools",
            "contracts",
            "tokens",
            "arbitrators",
            "market-rates",
        ] {
            QueryCommand::try_parse_from(["query", name, "--limit", "5", "--cursor", "abcdef"])
                .unwrap_or_else(|error| panic!("parse {name}: {error}"));

            let help = command
                .find_subcommand_mut(name)
                .unwrap_or_else(|| panic!("missing subcommand {name}"))
                .render_long_help()
                .to_string();
            assert!(help.contains("--cursor"), "{name}: {help}");
            assert!(!help.contains("--offset"), "{name}: {help}");

            let error = QueryCommand::try_parse_from(["query", name, "--offset", "0"])
                .expect_err("public list unexpectedly accepted --offset");
            assert!(error.to_string().contains("--offset"), "{name}: {error}");
        }
    }

    #[test]
    fn task_query_requires_key_source_for_signed_participant_auth() {
        let task_id = "aa".repeat(32);
        let parsed =
            QueryCommand::try_parse_from(["query", "task", "--secret-key", "11", task_id.as_str()])
                .expect("parse signed task query");

        match parsed.command.expect("typed query command") {
            QueryCommands::Task {
                signer,
                task_id: id,
            } => {
                assert_eq!(id, task_id);
                assert_eq!(signer.secret_key.as_deref(), Some("11"));
            }
            other => panic!("unexpected query command {other:?}"),
        }

        let mut command = QueryCommand::command();
        let help = command
            .find_subcommand_mut("task")
            .expect("missing task subcommand")
            .render_long_help()
            .to_string();
        assert!(help.contains("--secret-key"), "{help}");
        assert!(help.contains("--key-file"), "{help}");
        assert!(help.contains("--keystore"), "{help}");
    }

    #[test]
    fn task_opportunity_query_is_public_and_does_not_expose_key_source_args() {
        let task_id = "aa".repeat(32);
        let parsed = QueryCommand::try_parse_from(["query", "task-opportunity", task_id.as_str()])
            .expect("parse task opportunity query");

        match parsed.command.expect("typed query command") {
            QueryCommands::TaskOpportunity { task_id: id } => assert_eq!(id, task_id),
            other => panic!("unexpected query command {other:?}"),
        }

        let mut command = QueryCommand::command();
        let help = command
            .find_subcommand_mut("task-opportunity")
            .expect("missing task-opportunity subcommand")
            .render_long_help()
            .to_string();
        assert!(!help.contains("--secret-key"), "{help}");
        assert!(!help.contains("--key-file"), "{help}");
        assert!(!help.contains("--keystore"), "{help}");
    }

    #[test]
    fn pending_tasks_query_uses_public_pending_task_surface() {
        let parsed = QueryCommand::try_parse_from([
            "query",
            "pending-tasks",
            "--limit",
            "25",
            "--cursor",
            "abcdef",
            "--discover-capability",
            "ai.reasoning",
            "--discover-capability",
            "ai.code.execution",
            "--discover-min-fee",
            "100",
            "--discover-fee",
            "ai.code.execution:25",
        ])
        .expect("parse pending tasks query");

        match parsed.command.expect("typed query command") {
            QueryCommands::PendingTasks {
                limit,
                cursor,
                discover_capability,
                discover_min_fee,
                discover_fee,
            } => {
                assert_eq!(limit, Some(25));
                assert_eq!(cursor.as_deref(), Some("abcdef"));
                assert_eq!(
                    discover_capability,
                    vec!["ai.reasoning", "ai.code.execution"]
                );
                assert_eq!(discover_min_fee, Some(100));
                assert_eq!(discover_fee, vec!["ai.code.execution:25"]);
            }
            other => panic!("unexpected query command {other:?}"),
        }

        let error = QueryCommand::try_parse_from(["query", "pending-tasks", "--offset", "50"])
            .expect_err("pending tasks must reject offset pagination");
        assert!(error.to_string().contains("--offset"), "{error}");

        let mut command = QueryCommand::command();
        let help = command
            .find_subcommand_mut("pending-tasks")
            .expect("missing pending-tasks subcommand")
            .render_long_help()
            .to_string();
        assert!(help.contains("--limit"), "{help}");
        assert!(help.contains("--cursor"), "{help}");
        assert!(help.contains("--discover-capability"), "{help}");
        assert!(help.contains("--discover-min-fee"), "{help}");
        assert!(help.contains("--discover-fee"), "{help}");
        assert!(!help.contains("--offset"), "{help}");
        assert!(!help.contains("--secret-key"), "{help}");
    }
}
