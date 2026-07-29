#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SurfaceCategory {
    Public,
    Participant,
    Provider,
    Omitted,
}

#[derive(Clone, Copy, Debug)]
pub struct SurfaceEntry {
    pub command: &'static str,
    pub category: SurfaceCategory,
    pub rationale: &'static str,
}

pub const TX_SURFACE: &[SurfaceEntry] = &[
    SurfaceEntry { command: "transfer", category: SurfaceCategory::Public, rationale: "ordinary value transfer" },
    SurfaceEntry { command: "entity-link", category: SurfaceCategory::Public, rationale: "public identity graph transaction" },
    SurfaceEntry { command: "agent-*", category: SurfaceCategory::Public, rationale: "public agent lifecycle" },
    SurfaceEntry { command: "capability-*", category: SurfaceCategory::Public, rationale: "public capability catalog proposal and curator lifecycle" },
    SurfaceEntry { command: "task-*", category: SurfaceCategory::Public, rationale: "public requester/agent task lifecycle" },
    SurfaceEntry { command: "tool-*", category: SurfaceCategory::Public, rationale: "public tool lifecycle, invocation, results, usage, subscriptions" },
    SurfaceEntry { command: "agreement-*", category: SurfaceCategory::Public, rationale: "public agreement lifecycle" },
    SurfaceEntry { command: "arbitrator-*", category: SurfaceCategory::Public, rationale: "public dispute-arbitrator lifecycle" },
    SurfaceEntry { command: "validator-register/update/exit stake/unstake", category: SurfaceCategory::Public, rationale: "public validator and stake transactions accepted by submit API" },
    SurfaceEntry { command: "contract-*", category: SurfaceCategory::Public, rationale: "public contract deployment, calls, routes, verification, ABI" },
    SurfaceEntry { command: "token-*", category: SurfaceCategory::Public, rationale: "ZIP-20 token lifecycle" },
    SurfaceEntry { command: "submit-protected submit-bundle", category: SurfaceCategory::Provider, rationale: "provider-gated orderflow utilities that require bearer auth" },
    SurfaceEntry { command: "validator-vrf-* protocol-params-update finality-* node-* operator-*", category: SurfaceCategory::Omitted, rationale: "consensus, operator, node management, and internal maintenance are outside the public SDK boundary" },
];

#[derive(Clone, Copy, Debug)]
pub struct QueryEndpoint {
    pub command: &'static str,
    pub method: &'static str,
    pub path_template: &'static str,
    pub category: SurfaceCategory,
}

pub const TYPED_QUERY_ENDPOINTS: &[QueryEndpoint] = &[
    QueryEndpoint {
        command: "chain",
        method: "GET",
        path_template: "/v1/chain/info",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "block",
        method: "GET",
        path_template: "/v1/blocks/{height_or_hash}",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "blocks",
        method: "GET",
        path_template: "/v1/blocks",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "account",
        method: "GET",
        path_template: "/v1/accounts/{address}",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "account-nonce",
        method: "GET",
        path_template: "/v1/accounts/{address}/nonce",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "account-transactions",
        method: "GET",
        path_template: "/v1/accounts/{address}/transactions",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "agent",
        method: "GET",
        path_template: "/v1/agents/{address}",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "agents",
        method: "GET",
        path_template: "/v1/agents",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "requester-reputation",
        method: "GET",
        path_template: "/v1/requesters/{address}",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "capabilities",
        method: "GET",
        path_template: "/v1/capabilities",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "capability",
        method: "GET",
        path_template: "/v1/capabilities/{slug}",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "capability-search",
        method: "GET",
        path_template: "/v1/capabilities/search",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "capability-categories",
        method: "GET",
        path_template: "/v1/capabilities/categories",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "task",
        method: "GET",
        path_template: "/v1/tasks/{task_id}",
        category: SurfaceCategory::Participant,
    },
    QueryEndpoint {
        command: "task-opportunity",
        method: "GET",
        path_template: "/v1/tasks/{task_id}/opportunity",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "pending-tasks",
        method: "GET",
        path_template: "/v1/tasks/pending",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "tool",
        method: "GET",
        path_template: "/v1/tools/{tool_id}",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "tools",
        method: "GET",
        path_template: "/v1/tools",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "subscription",
        method: "GET",
        path_template: "/v1/tool-subscriptions/{subscription_id}",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "agreement",
        method: "GET",
        path_template: "/v1/agreements/{agreement_id}",
        category: SurfaceCategory::Participant,
    },
    QueryEndpoint {
        command: "agreements-by-party",
        method: "GET",
        path_template: "/v1/agreements/party/{address}",
        category: SurfaceCategory::Participant,
    },
    QueryEndpoint {
        command: "agreements-by-arbitrator",
        method: "GET",
        path_template: "/v1/agreements/arbitrator/{address}",
        category: SurfaceCategory::Participant,
    },
    QueryEndpoint {
        command: "tool-job",
        method: "GET",
        path_template: "/v1/tool-jobs/{job_id}",
        category: SurfaceCategory::Participant,
    },
    QueryEndpoint {
        command: "tool-jobs-by-requester",
        method: "GET",
        path_template: "/v1/tool-jobs/requester/{address}",
        category: SurfaceCategory::Participant,
    },
    QueryEndpoint {
        command: "tool-jobs-by-provider",
        method: "GET",
        path_template: "/v1/tool-jobs/provider/{address}",
        category: SurfaceCategory::Participant,
    },
    QueryEndpoint {
        command: "tool-usage-session",
        method: "GET",
        path_template: "/v1/tool-usage-sessions/{session_id}",
        category: SurfaceCategory::Participant,
    },
    QueryEndpoint {
        command: "tool-usage-sessions-by-requester",
        method: "GET",
        path_template: "/v1/tool-usage-sessions/requester/{address}",
        category: SurfaceCategory::Participant,
    },
    QueryEndpoint {
        command: "tool-usage-sessions-by-provider",
        method: "GET",
        path_template: "/v1/tool-usage-sessions/provider/{address}",
        category: SurfaceCategory::Participant,
    },
    QueryEndpoint {
        command: "contract",
        method: "GET",
        path_template: "/v1/contracts/{address}",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "contracts",
        method: "GET",
        path_template: "/v1/contracts",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "contract-transactions",
        method: "GET",
        path_template: "/v1/contracts/{address}/transactions",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "route",
        method: "GET",
        path_template: "/v1/contracts/routes/{deployer}/{route_name}",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "token",
        method: "GET",
        path_template: "/v1/tokens/{token_id}",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "tokens",
        method: "GET",
        path_template: "/v1/tokens",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "token-transactions",
        method: "GET",
        path_template: "/v1/tokens/{token_id}/transactions",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "arbitrator",
        method: "GET",
        path_template: "/v1/arbitrators/{address}",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "arbitrators",
        method: "GET",
        path_template: "/v1/arbitrators",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "market-rates",
        method: "GET",
        path_template: "/v1/market-rates",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "events",
        method: "GET",
        path_template: "/v1/events",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "tx",
        method: "GET",
        path_template: "/v1/tx/{hash}",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "validators",
        method: "GET",
        path_template: "/v1/consensus/validators",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "participant",
        method: "GET",
        path_template: "<signed participant path>",
        category: SurfaceCategory::Participant,
    },
];

pub fn assert_public_surface() {
    assert!(
        !TX_SURFACE.is_empty(),
        "transaction surface matrix is empty"
    );
    assert!(
        TX_SURFACE
            .iter()
            .any(|entry| matches!(entry.category, SurfaceCategory::Provider)),
        "provider-gated orderflow surface must be documented"
    );
    assert!(
        TX_SURFACE
            .iter()
            .any(|entry| matches!(entry.category, SurfaceCategory::Omitted)),
        "omitted private/internal surface must be documented"
    );
    for entry in TX_SURFACE {
        assert!(!entry.command.trim().is_empty());
        assert!(!entry.rationale.trim().is_empty());
    }
    for endpoint in TYPED_QUERY_ENDPOINTS {
        assert_eq!(endpoint.method, "GET", "typed query endpoints are GET-only");
        assert!(
            !matches!(
                endpoint.category,
                SurfaceCategory::Provider | SurfaceCategory::Omitted
            ),
            "typed query {} maps to a non-public endpoint",
            endpoint.command
        );
        let path = endpoint.path_template;
        let allowed_public_consensus_path = path == "/v1/consensus/validators";
        assert_ne!(
            path, "/v1/tasks",
            "typed query {} maps to removed task list endpoint",
            endpoint.command
        );
        assert!(
            !path.contains("operator")
                && !path.contains("mempool")
                && !path.contains("pipeline")
                && (!path.contains("consensus") || allowed_public_consensus_path)
                && !path.contains("finality")
                && !path.contains("testing")
                && !path.contains("internal")
                && !path.contains("readiness")
                && !path.contains("orderflow"),
            "typed query {} maps to excluded endpoint {}",
            endpoint.command,
            path
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::QueryCommand;
    use clap::CommandFactory;
    use std::collections::BTreeSet;

    #[test]
    fn typed_queries_do_not_cross_public_boundary() {
        assert_public_surface();
    }

    #[test]
    fn typed_query_manifest_matches_clap_surface() {
        let clap_commands: BTreeSet<_> = QueryCommand::command()
            .get_subcommands()
            .map(|command| command.get_name().to_string())
            .filter(|name| name != "help")
            .collect();
        let manifest_commands: BTreeSet<_> = TYPED_QUERY_ENDPOINTS
            .iter()
            .map(|entry| entry.command.to_string())
            .collect();
        assert_eq!(clap_commands, manifest_commands);
    }
}
