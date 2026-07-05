# Zincha Public CLI Surface

The public `zincha` CLI is an SDK client surface. It intentionally wires
wallet/key management, public transaction construction, public and
participant-authenticated reads, normal submit/batch submit, and explicit
provider-gated orderflow utilities. It does not expose node operation,
testing, worker runtime, mempool, consensus, or finality internals.

## Included Transaction Groups

| Group | CLI shape | Boundary reason |
| --- | --- | --- |
| Transfers | `zincha tx transfer` | Public value transfer accepted through `/v1/tx/submit`. |
| Entity links | `zincha tx entity-link` | Public identity graph transaction built by `AgentWallet`. |
| Agents | `register-agent`, `update-agent`, `deregister-agent` | Public agent lifecycle builders in `zincha-primitives`. |
| Requesters/tasks | `bond-requester-auto-match`, `submit-task`, task accept/dispute/resolve/finalize/cancel/decompose, reputation update | Public requester/agent workflow. |
| Tools | tool register/update/deregister, invoke, result, usage, subscription plan and subscription commands | Public tool provider/requester workflow. |
| Capability catalog | capability propose plus curator approve/reject/deprecate | Public catalog extension workflow; catalog entries are curated metadata, while agent/tool/task capability strings remain open. |
| Agreements/arbitrators | agreement create/accept/execute/dispute/resolve/cancel, arbitrator register/deregister | Public agreement and dispute workflow. |
| Validators/stake | validator register/update/exit, stake, unstake | Public transactions accepted by the normal submit API. |
| Contracts/routes | deploy, call, route call/update, source verification, ABI publish, deactivate | Public contract workflow. |
| ZIP-20 tokens | create, transfer, approve, mint, update mint authority, burn, destroy | Public token lifecycle. |
| Transport utilities | `submit-signed`, `submit-batch`, `wait` | Client transport helpers, not node-management commands. |
| Provider orderflow | `submit-protected`, `submit-bundle` | Provider-gated utilities requiring bearer auth. |

## Omitted Transaction Groups

| Omitted | Reason |
| --- | --- |
| Validator VRF commit/contribution | Consensus epoch-randomness internals. |
| Protocol parameter update | Governance/operator maintenance surface, not public SDK CLI v1. |
| Finality evidence/votes | Finality evidence types are not promoted as public CLI workflow. |
| Node/operator/system maintenance | Outside the SDK boundary. |
| Worker/agent runtime daemon behavior | Runtime service behavior, not client transaction construction. |

## Included Query Categories

Typed query commands are limited to public reads plus deliberate signed
participant reads. Generic `zincha query <path>` remains as an escape hatch.

| Category | Examples |
| --- | --- |
| Chain/blocks | `query chain`, `query block`, `query blocks` |
| Accounts/agents/requesters | `query account`, `query account-nonce`, `query account-transactions`, `query agent`, `query agents`, `query requester-reputation` |
| Capabilities | `query capabilities`, `query capability`, `query capability-search`, `query capability-categories` |
| Tasks/tools/subscriptions | `query pending-tasks`, `query task-opportunity`, `query task` with a signer, `query tool`, `query tools`, `query subscription`, `query tool-job`, `query tool-jobs-by-requester`, `query tool-jobs-by-provider`, `query tool-usage-session`, `query tool-usage-sessions-by-requester`, `query tool-usage-sessions-by-provider` |
| Agreements/contracts/routes/tokens/arbitrators | `query agreement`, `query agreements-by-party`, `query agreements-by-arbitrator`, `query contract`, `query contract-transactions`, `query route`, `query token`, `query token-transactions`, `query arbitrator` |
| Events/transactions/validators | `query events`, `query tx`, `query validator`, `query validators` |
| Participant reads | `query participant <path>` with a signer and local address-scope checks. |

Operator, provider-read, testing, readiness-internal, mempool, pipeline,
consensus, finality, orderflow-stats, and node-memory endpoints are not wired
as typed query commands.

Account, contract, token transaction-history queries and participant workflow
lists use cursor pagination with `--limit` and `--cursor`; they intentionally
do not expose `--offset`.

Capability catalog list queries also use cursor pagination with `--limit` and
`--cursor`. Agents can use `query capability-search` or `query capabilities`
to discover common curated capability names before building agent, tool, or
task transactions, but custom capability strings are protocol-valid even when
they are not catalog entries. Propose a catalog entry when a custom capability
should become shared curated metadata.

Transaction builders that need client-side neural embeddings accept
`--embed-url`; when omitted, the CLI falls back to `ZINCHA_EMBED_URL`. For
Vega, use `https://embed.vega.zincha.com` unless you are intentionally pointing
at a local embedding service.
