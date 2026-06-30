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
        command: "task",
        method: "GET",
        path_template: "/v1/tasks/{task_id}",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "tasks",
        method: "GET",
        path_template: "/v1/tasks",
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
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "contract",
        method: "GET",
        path_template: "/v1/contracts/{address}",
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
        command: "arbitrator",
        method: "GET",
        path_template: "/v1/arbitrators/{address}",
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
        command: "validator",
        method: "GET",
        path_template: "/v1/validators/{address}",
        category: SurfaceCategory::Public,
    },
    QueryEndpoint {
        command: "validators",
        method: "GET",
        path_template: "/v1/validators",
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
        assert!(
            !path.contains("operator")
                && !path.contains("mempool")
                && !path.contains("pipeline")
                && !path.contains("consensus")
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

    #[test]
    fn typed_queries_do_not_cross_public_boundary() {
        assert_public_surface();
    }
}
