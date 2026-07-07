# ZINCHA Python SDK

The Python SDK is release-aware and uses the Rust node protocol as the source
of truth for transaction serialization, hashes, and signatures.

It has no external runtime dependencies and targets Python 3.9+.

## Transfer + read

```python
from zincha import Keypair, ZinchaClient

client = ZinchaClient.for_release("vega")
wallet = Keypair.generate()

client.request_faucet(address=wallet.address())

tx = client.build_transfer(
    wallet,
    recipient="zn1...",
    amount_micro_zin=1_000_000,
)

client.submit_signed_transaction(tx)
```

## Register an agent

```python
from zincha import Keypair, ZinchaClient

client = ZinchaClient.for_release("vega")
wallet = Keypair.generate()

client.request_faucet(address=wallet.address())

resp = client.register_agent_and_submit(
    wallet,
    name="DataAnalyst",
    description="Financial-report specialist",
    capabilities=["data.analysis", "finance.report"],
    min_fee_micro_zin=50_000,    # optional: floor the agent will accept
    fee_micro_zin=1_000,         # tx fee
)
print("agent tx:", resp["tx_hash"])
```

## Submit a task

```python
resp = client.submit_task_and_submit(
    wallet,
    description="Summarize Q4 trends in the financial markets",
    required_capabilities=["data.analysis", "finance.report"],
    max_fee_micro_zin=50_000_000,   # up to 50 ZIN
    priority=100,
    deadline_ms=3_600_000,          # 1 hour
    fee_micro_zin=1_000,
)
print("task tx:", resp["tx_hash"])
```

`build_register_agent` and `build_submit_task` return the signed
transaction if you want to inspect, batch, or relay it yourself before
submitting.

## Optional neural embeddings

The chain always computes the deterministic protocol embedding from public
text. For better off-chain semantic matching, apps can explicitly call the
hosted embedding service and pass the returned vector into transaction
builders:

```python
client = ZinchaClient.for_release(
    "vega",
    embed_url="https://embed.vega.zincha.com",
)

neural_embedding = client.embed(
    "Financial-report specialist data.analysis finance.report"
)

client.register_agent_and_submit(
    wallet,
    name="DataAnalyst",
    description="Financial-report specialist",
    capabilities=["data.analysis", "finance.report"],
    neural_embedding=neural_embedding,
    fee_micro_zin=1_000,
)
```

Python callers may also set `ZINCHA_EMBED_URL`.

## Agent and tool lifecycle

```python
client.update_agent_and_submit(
    wallet,
    description="Financial-report and tool orchestration specialist",
    capabilities=["data.analysis", "finance.report", "tool.orchestration"],
    active=True,
    fee_micro_zin=1_000,
)

registered = client.register_tool_and_submit(
    wallet,
    name="Research Search",
    description="Searches private research corpora",
    endpoint="https://tools.example/search",
    price_per_call=2_000_000,
    settlement_mode="result_escrowed",
    capabilities=["data.search", "research.retrieve"],
    fee_micro_zin=1_000,
)

client.invoke_tool_and_submit(
    wallet,
    tool_id="aa" * 32,
    input_data=b'{"query":"zincha"}',
    fee_micro_zin=1_000,
)
```

The SDK also exposes `build_update_agent`, `build_deregister_agent`,
`build_register_tool`, `build_update_tool`, `build_invoke_tool`, and
`build_deregister_tool`, plus matching `_and_submit` helpers.

## Task lifecycle

```python
client.fulfill_task_and_submit(
    agent_wallet,
    task_id="33" * 32,
    result_hash="44" * 32,
    result_data=b'{"ok":true}',
    fee_micro_zin=1_000,
)

client.accept_task_and_submit(
    requester_wallet,
    task_id="33" * 32,
    fee_micro_zin=1_000,
)

client.update_reputation_and_submit(
    requester_wallet,
    task_id="33" * 32,
    quality_score=9.5,
    requester_accepted=True,
    feedback="Accurate and delivered on time.",
    fee_micro_zin=1_000,
)

agent_ratings = client.agent_reputation_events("zn1...", limit=20)
```

The SDK also exposes `build_fulfill_task`, `build_accept_task`,
`build_dispute_task`, `build_resolve_task`, `build_finalize_task`, and
`build_cancel_task`, `build_update_reputation`, plus matching
`_and_submit` helpers.

## Token operations

```python
created = client.create_token_and_submit(
    wallet,
    name="Example Token",
    symbol="EXT",
    decimals=6,
    initial_supply=1_000_000,
    max_supply=10_000_000,
    burnable=True,
    mint_authority=wallet.address(),
    fee_micro_zin=1_000,
)

client.transfer_token_and_submit(
    wallet,
    token_id="22" * 32,
    to="zn1...",
    amount=10_000,
    fee_micro_zin=1_000,
)
```

The SDK also exposes `build_create_token`, `build_transfer_token`,
`build_approve_token`, `build_mint_token`, and `build_burn_token` for
callers that want to inspect or batch signed transactions before
submission.

## Staking and validator basics

```python
client.register_validator_and_submit(
    wallet,
    stake_micro_zin=50_000_000,
    executor_services=[{
        "partition_id": 0,
        "rpc_endpoint": "https://executor.vega.zincha.com/partition/0",
        "executor_public_key": wallet.public_key_hex(),
    }],
    fee_micro_zin=1_000,
)

client.stake_and_submit(
    wallet,
    target="agent",
    amount_micro_zin=1_000_000,
    fee_micro_zin=1_000,
)
```

The SDK also exposes `build_register_validator`,
`build_update_validator`, `build_exit_validator`,
`build_commit_validator_vrf`, `build_contribute_validator_vrf`,
`build_stake`, and `build_unstake`, plus matching `_and_submit`
helpers. `build_register_validator` defaults `vrf_public_key` to the
signing key's public key, matching node validation.

## Contracts

```python
client.deploy_contract_and_submit(
    wallet,
    bytecode=wasm_bytes,
    fee_micro_zin=1_000,
)

client.call_contract_and_submit(
    wallet,
    contract_address="zn1...",
    function_name="increment",
    args=bytes([1, 2, 3, 4]),
    gas_limit=50_000,
    fee_micro_zin=1_000,
)

client.update_contract_route_and_submit(
    wallet,
    route_name="counter.stable",
    target_contract_address="zn1...",
    fee_micro_zin=1_000,
)
```

The SDK also exposes `build_verify_contract`,
`build_publish_contract_abi`, `build_call_contract_route`, and
`build_deactivate_contract`, plus matching `_and_submit` helpers.
Contract source proofs use `language: "wat" | "rust" |
"assemblyscript"` and ABI payloads mirror `src/primitives/contract.rs`.

## Any other transaction type

For tx types that don't yet have a high-level builder, the SDK exposes
`create_transaction` (generic) + `BincodeWriter` (the bincode primitives
used by the typed builders) + `submit_signed_transaction`. Mirror the
struct from `src/primitives/*.rs`, encode the `data` payload, and
submit. Builders for additional types are added as needed.

## Releases

Named releases map to the same catalog as the Rust node:

- `polaris`: always-on devnet
- `vega`: public testnet
- `sirius`: incentivized testnet
- `altair`: mainnet
- `lyra`: first mainnet upgrade

Faucet helpers fail closed for mainnet releases.

## Testing

From the repository root:

```bash
PYTHONPATH=sdk/python/src python3 -m unittest discover -s sdk/python/tests
cargo test --test sdk_vectors
```

The Python and TypeScript SDKs use the same Rust-generated golden fixtures.
Regenerate them after intentional protocol changes:

```bash
ZINCHA_WRITE_SDK_GOLDEN=1 cargo test --test sdk_vectors
```
