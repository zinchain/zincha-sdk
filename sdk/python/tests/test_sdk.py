import json
import unittest
from pathlib import Path

from zincha import (
    AgreementMilestone,
    AgreementPayout,
    AgreementReputationEffect,
    BincodeWriter,
    Keypair,
    MatchPreferences,
    ZinchaApiError,
    ZinchaClient,
    TX_TYPE_WIRE_CODES,
    bytes_to_hex,
    create_transfer_transaction,
    encode_agreement_accept_data,
    encode_agreement_cancel_data,
    encode_agreement_create_data,
    encode_agreement_dispute_data,
    encode_agreement_execute_data,
    encode_agreement_resolve_data,
    encode_agent_deregister_data,
    encode_agent_register_data,
    encode_agent_update_data,
    encode_capability_approve_data,
    encode_capability_deprecate_data,
    encode_capability_propose_data,
    encode_capability_reject_data,
    encode_task_accept_data,
    encode_task_cancel_data,
    encode_task_dispute_data,
    encode_task_finalize_data,
    encode_task_fulfill_data,
    encode_reputation_update_data,
    encode_task_resolve_data,
    encode_task_submit_data,
    encode_tool_deregister_data,
    encode_tool_invoke_data,
    encode_tool_job_expire_data,
    encode_tool_register_data,
    encode_tool_result_accept_data,
    encode_tool_result_dispute_data,
    encode_tool_result_resolve_data,
    encode_tool_result_submit_data,
    encode_tool_subscription_cancel_data,
    encode_tool_subscription_plan_create_data,
    encode_tool_subscription_plan_update_data,
    encode_tool_subscription_renew_data,
    encode_tool_subscription_resume_data,
    encode_tool_subscription_start_data,
    encode_tool_subscription_top_up_data,
    encode_tool_update_data,
    encode_tool_usage_accept_data,
    encode_tool_usage_dispute_data,
    encode_tool_usage_expire_data,
    encode_tool_usage_report_data,
    encode_tool_usage_resolve_data,
    encode_contract_call_data,
    encode_contract_deactivate_data,
    encode_contract_deploy_data,
    encode_contract_publish_abi_data,
    encode_contract_route_call_data,
    encode_contract_route_update_data,
    encode_contract_verify_data,
    encode_token_approve_data,
    encode_token_burn_data,
    encode_token_create_data,
    encode_token_mint_data,
    encode_token_transfer_data,
    encode_stake_data,
    encode_unstake_data,
    encode_validator_exit_data,
    encode_validator_register_data,
    encode_validator_update_data,
    encode_validator_vrf_commit_data,
    encode_validator_vrf_contribution_data,
    release_spec,
    sign_transaction,
    signed_request_headers,
    signed_transaction_hex,
    with_validity_window,
)


GOLDEN = json.loads(
    (Path(__file__).resolve().parents[2] / "testdata" / "golden-transfer.json").read_text()
)


class PythonSdkTests(unittest.TestCase):
    def test_release_catalog_mirrors_rust_release_endpoints(self):
        self.assertEqual(release_spec("vega").chain_id, "zincha-vega-1")
        self.assertEqual(release_spec("vega").canonical_rpc_url, "https://vega.zincha.com")
        self.assertEqual(release_spec("vega").faucet_url, "https://faucet.vega.zincha.com")
        self.assertEqual(release_spec("vega").explorer_url, "https://vega.zinscan.com")
        self.assertEqual(release_spec("testnet").slug, "vega")
        self.assertEqual(release_spec("sirius").canonical_websocket_url, "wss://sirius.zincha.com")
        self.assertEqual(release_spec("mainnet").slug, "altair")

    def test_keypair_derives_rust_compatible_public_key_and_address(self):
        keypair = Keypair.from_secret_hex(GOLDEN["secret_hex"])
        self.assertEqual(keypair.public_key_hex(), GOLDEN["public_key_hex"])
        self.assertEqual(keypair.address(), GOLDEN["sender"])

    def test_transfer_serialization_hash_signature_and_signed_bytes_match_rust(self):
        keypair = Keypair.from_secret_hex(GOLDEN["secret_hex"])
        unsigned = GOLDEN["unsigned_transaction"]
        tx = create_transfer_transaction(
            keypair,
            recipient=GOLDEN["recipient"],
            amount_micro_zin=unsigned["amount"],
            fee_micro_zin=unsigned["fee"],
            nonce=unsigned["nonce"],
            chain_id=unsigned["chain_id"],
            timestamp_ms=unsigned["timestamp"],
            max_priority_fee_per_gas=unsigned["max_priority_fee_per_gas"],
        )
        tx = with_validity_window(
            tx,
            unsigned["reference_block_height"],
            unsigned["reference_block_hash"],
            100,
        )
        signed = sign_transaction(tx, keypair)
        self.assertEqual(signed.hash, GOLDEN["transaction_hash"])
        self.assertEqual(signed.signature, GOLDEN["signature_hex"])
        self.assertEqual(signed.public_key, GOLDEN["public_key_hex"])
        self.assertEqual(signed_transaction_hex(signed), GOLDEN["signed_tx_hex"])

    def test_signed_request_headers_match_rust_request_auth_shape(self):
        keypair = Keypair.from_secret_hex(GOLDEN["secret_hex"])
        body = json.dumps({"hello": "zincha"}, separators=(",", ":"))
        headers = signed_request_headers(
            keypair,
            "POST",
            "/v1/tasks/estimate-fee?x=1",
            body=body,
            nonce="nonce-1",
            timestamp_ms=1_700_000_000_000,
        )
        self.assertEqual(headers["x-zincha-address"], GOLDEN["sender"])
        self.assertEqual(headers["x-zincha-public-key"], GOLDEN["public_key_hex"])
        self.assertEqual(headers["x-zincha-timestamp-ms"], "1700000000000")
        self.assertEqual(headers["x-zincha-nonce"], "nonce-1")
        self.assertRegex(headers["x-zincha-body-sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(headers["x-zincha-signature"], r"^[0-9a-f]{128}$")
        self.assertEqual(len(bytes_to_hex(keypair.sign(b"hello"))), 128)

    def test_client_unwraps_api_responses_and_surfaces_api_errors(self):
        calls = []

        def transport(method, url, headers, body, timeout):
            calls.append((method, url, headers, body, timeout))
            if url.endswith("/v1/chain/info"):
                return 200, json.dumps(
                    {
                        "success": True,
                        "data": {
                            "chain_id": "zincha-vega-1",
                            "version": "0.1.0",
                            "block_height": 1,
                            "latest_block_hash": "00" * 32,
                            "target_block_time_ms": 1000,
                            "transaction_ttl_blocks": 100,
                            "transaction_reference_block_height": 1,
                            "transaction_reference_block_hash": "00" * 32,
                            "base_fee_per_gas": 1,
                            "next_base_fee": 1,
                            "contract_platform_profile_version": 1,
                            "contract_platform_profile_id": "11" * 32,
                        },
                        "error": None,
                    }
                )
            return 429, json.dumps(
                {
                    "success": False,
                    "data": {"retry_after_secs": 10},
                    "error": "rate limited",
                }
            )

        client = ZinchaClient(base_url="http://node.test/", transport=transport)
        info = client.chain_info()
        self.assertEqual(info["chain_id"], "zincha-vega-1")
        self.assertEqual(calls[0][1], "http://node.test/v1/chain/info")

        with self.assertRaises(ZinchaApiError) as caught:
            client.request_faucet(address=GOLDEN["sender"])
        self.assertEqual(caught.exception.status, 429)
        self.assertEqual(caught.exception.data, {"retry_after_secs": 10})

    def test_embed_helper_uses_configured_embed_service_and_validates_vector(self):
        calls = []

        def transport(method, url, headers, body, timeout):
            calls.append((method, url, headers, body, timeout))
            return 200, json.dumps({"embedding": [0.125, -0.5, 1]})

        client = ZinchaClient(
            base_url="http://node.test/",
            embed_url="https://embed.vega.zincha.com/",
            transport=transport,
        )
        embedding = client.embed("AI research agent ai.web.search")

        self.assertEqual(embedding, [0.125, -0.5, 1.0])
        self.assertEqual(calls[0][0], "POST")
        self.assertEqual(calls[0][1], "https://embed.vega.zincha.com/embed")
        self.assertEqual(calls[0][2]["content-type"], "application/json")
        self.assertEqual(
            json.loads(calls[0][3].decode("utf-8")),
            {"text": "AI research agent ai.web.search"},
        )

    def test_embed_helper_supports_per_call_url_override_and_fails_closed(self):
        calls = []

        def transport(method, url, headers, body, timeout):
            calls.append((method, url, headers, body, timeout))
            return 200, json.dumps({"embedding": [False]})

        missing_url = ZinchaClient(
            base_url="http://node.test/",
            transport=lambda *_args: (200, json.dumps({"embedding": [1]})),
        )
        with self.assertRaisesRegex(ValueError, "embed service URL required"):
            missing_url.embed("missing url")

        client = ZinchaClient(
            base_url="http://node.test/",
            embed_url="https://ignored.embed/",
            transport=transport,
        )
        with self.assertRaises(ZinchaApiError) as caught:
            client.embed("bad vector", embed_url="https://custom.embed/")
        self.assertEqual(caught.exception.status, 200)
        self.assertRegex(str(caught.exception), "non-finite embedding value")
        self.assertEqual(calls[0][1], "https://custom.embed/embed")

    def test_transaction_history_helpers_use_cursor_pagination(self):
        calls = []

        def transport(method, url, headers, body, timeout):
            calls.append((method, url, headers, body, timeout))
            return 200, json.dumps(
                {
                    "success": True,
                    "data": {
                        "items": [],
                        "pagination": {
                            "total": 0,
                            "limit": 5,
                            "has_more": False,
                            "next_cursor": None,
                            "cursor": "abcdef",
                        },
                    },
                    "error": None,
                }
            )

        client = ZinchaClient(base_url="http://node.test/", transport=transport)
        client.account_transactions(GOLDEN["sender"], limit=5, cursor="abcdef")
        client.contract_transactions(GOLDEN["recipient"], limit=2, cursor="c0ffee")
        client.token_transactions("11" * 32, limit=3, cursor="1234")

        self.assertEqual(
            calls[0][1],
            "http://node.test/v1/accounts/%s/transactions?limit=5&cursor=abcdef"
            % GOLDEN["sender"],
        )
        self.assertEqual(
            calls[1][1],
            "http://node.test/v1/contracts/%s/transactions?limit=2&cursor=c0ffee"
            % GOLDEN["recipient"],
        )
        self.assertEqual(
            calls[2][1],
            "http://node.test/v1/tokens/%s/transactions?limit=3&cursor=1234" % ("11" * 32),
        )
        for method, url, _headers, _body, _timeout in calls:
            self.assertEqual(method, "GET")
            self.assertNotIn("offset", url)

        with self.assertRaises(TypeError):
            client.account_transactions(GOLDEN["sender"], offset=0)

    def test_high_cardinality_list_helpers_use_cursor_pagination(self):
        calls = []

        def transport(method, url, headers, body, timeout):
            calls.append(url)
            return 200, json.dumps(
                {
                    "success": True,
                    "data": {"items": [], "pagination": {"has_more": False}},
                    "error": None,
                }
            )

        client = ZinchaClient(base_url="http://node.test", transport=transport)
        client.agents(cursor="a1", limit=2)
        client.pending_tasks(
            cursor="a2",
            limit=3,
            discover_capability="reasoning",
            discover_min_fee=7,
            discover_fee="42",
        )
        client.tools(cursor="a3", limit=4)
        client.contracts(cursor="a4", limit=5)
        client.tokens(cursor="a5", limit=6)
        client.arbitrators(cursor="a6", limit=7)
        client.market_rates(cursor="a7", limit=8)
        client.capability_search("reasoning", cursor="a8", limit=9, status="all")

        self.assertEqual(
            calls,
            [
                "http://node.test/v1/agents?cursor=a1&limit=2",
                "http://node.test/v1/tasks/pending?cursor=a2&limit=3"
                "&discover_capability=reasoning&discover_min_fee=7&discover_fee=42",
                "http://node.test/v1/tools?cursor=a3&limit=4",
                "http://node.test/v1/contracts?cursor=a4&limit=5",
                "http://node.test/v1/tokens?cursor=a5&limit=6",
                "http://node.test/v1/arbitrators?cursor=a6&limit=7",
                "http://node.test/v1/market-rates?cursor=a7&limit=8",
                "http://node.test/v1/capabilities/search?q=reasoning&cursor=a8&limit=9&status=all",
            ],
        )
        self.assertTrue(all("offset=" not in url for url in calls))

    def test_capability_catalog_helpers_use_public_urls_and_drop_unsupported_keys(self):
        calls = []

        def transport(method, url, headers, body, timeout):
            calls.append((method, url, headers, body, timeout))
            return 200, json.dumps({"success": True, "data": {}, "error": None})

        client = ZinchaClient(base_url="http://node.test/", transport=transport)
        client.capabilities(
            limit=25,
            cursor="ai.reasoning",
            status="all",
            category="ai",
            parent="ai.reasoning",
        )
        client.capability_search(
            "smart contract",
            cursor="search-cursor",
            limit=10,
            status="active",
            category="blockchain",
        )
        client.capability("AI.Reasoning")
        client.capability_categories()

        self.assertEqual(
            calls[0][1],
            "http://node.test/v1/capabilities?limit=25&cursor=ai.reasoning&status=all&category=ai&parent=ai.reasoning",
        )
        self.assertEqual(
            calls[1][1],
            "http://node.test/v1/capabilities/search?q=smart+contract&cursor=search-cursor&limit=10&status=active&category=blockchain",
        )
        self.assertEqual(calls[2][1], "http://node.test/v1/capabilities/ai.reasoning")
        self.assertEqual(calls[3][1], "http://node.test/v1/capabilities/categories")
        for method, url, headers, _body, _timeout in calls:
            self.assertEqual(method, "GET")
            self.assertNotIn("offset", url)
            self.assertNotIn("x-zincha-address", headers)
            self.assertNotIn("x-zincha-signature", headers)

    def test_task_opportunity_helper_fetches_public_open_task_view_unsigned(self):
        calls = []
        task_id = "aa" * 32

        def transport(method, url, headers, body, timeout):
            calls.append((method, url, headers, body, timeout))
            return 200, json.dumps(
                {
                    "success": True,
                    "data": {"task_id": task_id, "description": "public brief"},
                    "error": None,
                }
            )

        client = ZinchaClient(base_url="http://node.test/", transport=transport)
        response = client.task_opportunity("0x" + task_id)

        self.assertEqual(response, {"task_id": task_id, "description": "public brief"})
        self.assertEqual(calls[0][0], "GET")
        self.assertEqual(calls[0][1], "http://node.test/v1/tasks/%s/opportunity" % task_id)
        headers = calls[0][2]
        self.assertNotIn("x-zincha-address", headers)
        self.assertNotIn("x-zincha-signature", headers)

    def test_task_helper_fetches_task_detail_with_signed_participant_auth(self):
        calls = []
        keypair = Keypair.from_secret_hex(GOLDEN["secret_hex"])
        task_id = "aa" * 32

        def transport(method, url, headers, body, timeout):
            calls.append((method, url, headers, body, timeout))
            return 200, json.dumps(
                {
                    "success": True,
                    "data": {"task_id": task_id},
                    "error": None,
                }
            )

        client = ZinchaClient(
            base_url="http://node.test/",
            signer=keypair,
            transport=transport,
        )
        response = client.task("0x" + task_id)

        self.assertEqual(response, {"task_id": task_id})
        self.assertEqual(calls[0][0], "GET")
        self.assertEqual(calls[0][1], "http://node.test/v1/tasks/%s" % task_id)
        headers = calls[0][2]
        self.assertEqual(headers["x-zincha-address"], GOLDEN["sender"])
        self.assertEqual(headers["x-zincha-public-key"], GOLDEN["public_key_hex"])
        self.assertRegex(headers["x-zincha-body-sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(headers["x-zincha-signature"], r"^[0-9a-f]{128}$")

    def test_reputation_read_helpers_map_public_audit_urls_unsigned(self):
        calls = []
        task_id = "dd" * 32

        def transport(method, url, headers, body, timeout):
            calls.append((method, url, headers, body, timeout))
            return 200, json.dumps({"success": True, "data": {}, "error": None})

        client = ZinchaClient(base_url="http://node.test/", transport=transport)
        client.agent_lifecycle_events(GOLDEN["sender"], limit=5, cursor="a1")
        client.agent_reputation_events(GOLDEN["sender"], limit=6, cursor="b2")
        client.agent_reputation_history(GOLDEN["sender"], limit=7, cursor="c3")
        client.requester_reputation(GOLDEN["sender"])
        client.requester_reputation_events(GOLDEN["sender"], limit=8, cursor="d4")
        client.requester_reputation_history(GOLDEN["sender"], limit=9, cursor="e5")
        client.task_reputation_events("0x" + task_id, limit=10, cursor="f6")

        self.assertEqual(
            [call[1] for call in calls],
            [
                "http://node.test/v1/agents/%s/lifecycle-events?limit=5&cursor=a1"
                % GOLDEN["sender"],
                "http://node.test/v1/agents/%s/reputation-events?limit=6&cursor=b2"
                % GOLDEN["sender"],
                "http://node.test/v1/agents/%s/reputation-history?limit=7&cursor=c3"
                % GOLDEN["sender"],
                "http://node.test/v1/requesters/%s" % GOLDEN["sender"],
                "http://node.test/v1/requesters/%s/reputation-events?limit=8&cursor=d4"
                % GOLDEN["sender"],
                "http://node.test/v1/requesters/%s/reputation-history?limit=9&cursor=e5"
                % GOLDEN["sender"],
                "http://node.test/v1/tasks/%s/reputation-events?limit=10&cursor=f6" % task_id,
            ],
        )
        for method, _url, headers, _body, _timeout in calls:
            self.assertEqual(method, "GET")
            self.assertNotIn("x-zincha-address", headers)
            self.assertNotIn("x-zincha-signature", headers)

    def test_participant_workflow_helpers_use_signed_cursor_routes(self):
        calls = []
        keypair = Keypair.from_secret_hex(GOLDEN["secret_hex"])
        agreement_id = "11" * 32
        job_id = "22" * 32
        session_id = "33" * 32

        def transport(method, url, headers, body, timeout):
            calls.append((method, url, headers, body, timeout))
            return 200, json.dumps({"success": True, "data": {}, "error": None})

        client = ZinchaClient(
            base_url="http://node.test/",
            signer=keypair,
            transport=transport,
        )
        client.agreement("0x" + agreement_id)
        client.tool_job("0x" + job_id)
        client.tool_usage_session("0x" + session_id)
        client.agreements_by_party(GOLDEN["sender"], limit=7, cursor="cafe")
        client.agreements_by_arbitrator(GOLDEN["sender"], limit=7, cursor="cafe")
        client.tool_jobs_by_requester(GOLDEN["sender"], limit=7, cursor="cafe")
        client.tool_jobs_by_provider(GOLDEN["sender"], limit=7, cursor="cafe")
        client.tool_usage_sessions_by_requester(GOLDEN["sender"], limit=7, cursor="cafe")
        client.tool_usage_sessions_by_provider(GOLDEN["sender"], limit=7, cursor="cafe")

        self.assertEqual(
            [call[1] for call in calls],
            [
                "http://node.test/v1/agreements/%s" % agreement_id,
                "http://node.test/v1/tool-jobs/%s" % job_id,
                "http://node.test/v1/tool-usage-sessions/%s" % session_id,
                "http://node.test/v1/agreements/party/%s?limit=7&cursor=cafe"
                % GOLDEN["sender"],
                "http://node.test/v1/agreements/arbitrator/%s?limit=7&cursor=cafe"
                % GOLDEN["sender"],
                "http://node.test/v1/tool-jobs/requester/%s?limit=7&cursor=cafe"
                % GOLDEN["sender"],
                "http://node.test/v1/tool-jobs/provider/%s?limit=7&cursor=cafe"
                % GOLDEN["sender"],
                "http://node.test/v1/tool-usage-sessions/requester/%s?limit=7&cursor=cafe"
                % GOLDEN["sender"],
                "http://node.test/v1/tool-usage-sessions/provider/%s?limit=7&cursor=cafe"
                % GOLDEN["sender"],
            ],
        )
        for method, url, headers, _body, _timeout in calls:
            self.assertEqual(method, "GET")
            self.assertNotIn("offset", url)
            self.assertEqual(headers["x-zincha-address"], GOLDEN["sender"])
            self.assertRegex(headers["x-zincha-signature"], r"^[0-9a-f]{128}$")

        with self.assertRaises(TypeError):
            client.tool_jobs_by_provider(GOLDEN["sender"], offset=0)

    def test_release_faucet_helper_uses_release_faucet_api_while_normal_calls_use_canonical_rpc(self):
        calls = []

        def transport(method, url, headers, body, timeout):
            calls.append((method, url, body))
            if url.endswith("/v1/chain/info"):
                return 200, json.dumps(
                    {
                        "success": True,
                        "data": {
                            "chain_id": "zincha-vega-1",
                            "version": "0.1.0",
                            "block_height": 1,
                            "latest_block_hash": "00" * 32,
                            "target_block_time_ms": 1000,
                            "transaction_ttl_blocks": 100,
                            "transaction_reference_block_height": 1,
                            "transaction_reference_block_hash": "00" * 32,
                            "base_fee_per_gas": 1,
                            "next_base_fee": 1,
                            "contract_platform_profile_version": 1,
                            "contract_platform_profile_id": "11" * 32,
                        },
                        "error": None,
                    }
                )
            return 200, json.dumps(
                {
                    "success": True,
                    "data": {
                        "hash": "22" * 32,
                        "accepted": True,
                        "amount_micro_zin": "10000000",
                        "faucet_address": GOLDEN["recipient"],
                    },
                    "error": None,
                }
            )

        client = ZinchaClient.for_release("vega", transport=transport)
        client.chain_info()
        client.request_faucet(address=GOLDEN["sender"])

        self.assertEqual(calls[0][1], "https://vega.zincha.com/v1/chain/info")
        self.assertEqual(calls[1][1], "https://faucet.vega.zincha.com/v1/faucet")

    def test_build_transfer_uses_chain_info_nonce_fee_and_validity(self):
        keypair = Keypair.from_secret_hex(GOLDEN["secret_hex"])

        def transport(method, url, headers, body, timeout):
            if url.endswith("/v1/chain/info"):
                return 200, json.dumps(
                    {
                        "success": True,
                        "data": {
                            "chain_id": "zincha-vega-1",
                            "version": "0.1.0",
                            "block_height": 42,
                            "latest_block_hash": "22" * 32,
                            "target_block_time_ms": 1000,
                            "transaction_ttl_blocks": 100,
                            "transaction_reference_block_height": 42,
                            "transaction_reference_block_hash": "11" * 32,
                            "base_fee_per_gas": 10,
                            "next_base_fee": 10,
                            "contract_platform_profile_version": 1,
                            "contract_platform_profile_id": "33" * 32,
                        },
                        "error": None,
                    }
                )
            if url.endswith("/nonce"):
                return 200, json.dumps(
                    {
                        "success": True,
                        "data": {
                            "address": keypair.address(),
                            "nonce": 2,
                            "next_nonce": 3,
                        },
                        "error": None,
                    }
                )
            raise AssertionError("unexpected URL %s" % url)

        client = ZinchaClient(base_url="http://node.test/", transport=transport)
        signed = client.build_transfer(
            keypair,
            recipient=GOLDEN["recipient"],
            amount_micro_zin=1_000,
            timestamp_ms=1_700_000_000_123,
        )
        self.assertEqual(signed.transaction.chain_id, "zincha-vega-1")
        self.assertEqual(signed.transaction.nonce, 3)
        self.assertEqual(signed.transaction.fee, 100)
        self.assertEqual(signed.transaction.reference_block_height, 42)
        self.assertEqual(signed.transaction.max_valid_block_height, 142)

    def test_faucet_helper_fails_closed_on_mainnet_releases(self):
        client = ZinchaClient.for_release(
            "altair",
            transport=lambda method, url, headers, body, timeout: (
                200,
                json.dumps({"success": True, "data": {}, "error": None}),
            ),
        )
        with self.assertRaisesRegex(ValueError, "faucet is unavailable for mainnet releases"):
            client.request_faucet(address=GOLDEN["sender"])

    def test_typed_builders_pin_validity_window_even_when_chain_id_is_provided(self):
        keypair = Keypair.from_secret_hex(GOLDEN["secret_hex"])
        calls = []

        def transport(method, url, headers, body, timeout):
            calls.append(url)
            if url.endswith("/v1/chain/info"):
                return 200, json.dumps(
                    {
                        "success": True,
                        "data": {
                            "chain_id": "zincha-vega-1",
                            "version": "0.1.0",
                            "block_height": 42,
                            "latest_block_hash": "22" * 32,
                            "target_block_time_ms": 1000,
                            "transaction_ttl_blocks": 100,
                            "transaction_reference_block_height": 42,
                            "transaction_reference_block_hash": "11" * 32,
                            "base_fee_per_gas": 1,
                            "next_base_fee": 1,
                            "contract_platform_profile_version": 1,
                            "contract_platform_profile_id": "33" * 32,
                        },
                        "error": None,
                    }
                )
            if url.endswith("/nonce"):
                return 200, json.dumps(
                    {
                        "success": True,
                        "data": {
                            "address": keypair.address(),
                            "nonce": 3,
                            "next_nonce": 4,
                        },
                        "error": None,
                    }
                )
            raise AssertionError("unexpected URL %s" % url)

        client = ZinchaClient(base_url="http://node.test/", transport=transport)
        signed = client.build_register_agent(
            keypair,
            name="DataAnalyst",
            description="High-performance financial analysis agent",
            capabilities=["data.analysis"],
            chain_id="zincha-vega-1",
            fee_micro_zin=1_000,
            timestamp_ms=1_700_000_000_456,
        )

        self.assertTrue(any(url.endswith("/v1/chain/info") for url in calls))
        self.assertEqual(signed.transaction.reference_block_height, 42)
        self.assertEqual(signed.transaction.reference_block_hash, "11" * 32)
        self.assertEqual(signed.transaction.max_valid_block_height, 142)

    def test_typed_builders_reject_partial_validity_windows(self):
        keypair = Keypair.from_secret_hex(GOLDEN["secret_hex"])

        def transport(method, url, headers, body, timeout):
            raise AssertionError("network should not be used for partial validity input")

        client = ZinchaClient(base_url="http://node.test/", transport=transport)
        with self.assertRaisesRegex(
            ValueError,
            "reference_block_height, reference_block_hash, and max_valid_block_height must be provided together",
        ):
            client.build_submit_task(
                keypair,
                description="Summarize Q4 trends in financial markets",
                required_capabilities=["data.analysis"],
                max_fee_micro_zin=50_000_000,
                chain_id="zincha-vega-1",
                nonce=5,
                reference_block_height=42,
            )

    def test_capability_transaction_builders_use_catalog_wire_codes(self):
        keypair = Keypair.from_secret_hex(GOLDEN["secret_hex"])

        def transport(method, url, headers, body, timeout):
            raise AssertionError("network should not be used when signing inputs are explicit")

        client = ZinchaClient(base_url="http://node.test/", transport=transport)
        common = {
            "chain_id": "zincha-vega-1",
            "nonce": 7,
            "timestamp_ms": 1_700_000_000_789,
            "reference_block_height": 42,
            "reference_block_hash": "11" * 32,
            "max_valid_block_height": 142,
        }

        proposed = client.build_propose_capability(
            keypair,
            **common,
            slug="AI.Custom.Research",
            display_name="Custom Research",
            description="Research capability",
            category="Research",
            aliases=["research.custom"],
            keywords=["research"],
            examples=["Find market references"],
            related=["ai.web.research"],
        )
        self.assertEqual(proposed.transaction.tx_type, "capability_propose")
        self.assertEqual(TX_TYPE_WIRE_CODES["capability_propose"], 67)

        approved = client.build_approve_capability(
            keypair,
            **{**common, "nonce": 8},
            slug="ai.custom.research",
            display_name="Custom Research",
            category="research",
            parent=None,
            aliases=["research.custom"],
        )
        self.assertEqual(approved.transaction.tx_type, "capability_approve")
        self.assertEqual(TX_TYPE_WIRE_CODES["capability_approve"], 68)

        rejected = client.build_reject_capability(
            keypair,
            **{**common, "nonce": 9},
            slug="ai.custom.research",
            reason="duplicate",
        )
        self.assertEqual(rejected.transaction.tx_type, "capability_reject")
        self.assertEqual(TX_TYPE_WIRE_CODES["capability_reject"], 69)

        deprecated = client.build_deprecate_capability(
            keypair,
            **{**common, "nonce": 10},
            slug="ai.custom.research",
            replacement="research.web",
            reason="merged",
        )
        self.assertEqual(deprecated.transaction.tx_type, "capability_deprecate")
        self.assertEqual(TX_TYPE_WIRE_CODES["capability_deprecate"], 70)

    def test_capability_payload_encoders_validate_slugs(self):
        self.assertGreater(
            len(
                encode_capability_propose_data(
                    slug="AI.Custom.Search",
                    display_name="Custom Search",
                    description="Search",
                    category="AI",
                    aliases=["search.custom"],
                )
            ),
            0,
        )
        self.assertGreater(len(encode_capability_approve_data(slug="ai.custom.search")), 0)
        self.assertGreater(len(encode_capability_reject_data(slug="ai.custom.search")), 0)
        self.assertGreater(
            len(
                encode_capability_deprecate_data(
                    slug="ai.custom.search",
                    replacement="ai.web.search",
                )
            ),
            0,
        )
        with self.assertRaisesRegex(ValueError, "invalid capability slug"):
            encode_capability_propose_data(
                slug="not valid",
                display_name="Invalid",
                description="Invalid",
                category="AI",
            )


# ─── Bincode primitives ─────────────────────────────────────────────


class BincodePrimitiveTests(unittest.TestCase):
    def test_writer_emits_little_endian_primitives(self):
        w = BincodeWriter()
        w.write_u8(1)
        w.write_u16(0x2345)
        w.write_u32(0x12345678)
        w.write_u64(0x0102030405060708)
        self.assertEqual(
            w.finish().hex(),
            "01" + "4523" + "78563412" + "0807060504030201",
        )

    def test_writer_option_none_is_zero_byte(self):
        w = BincodeWriter()
        w.write_option(None, lambda writer, value: writer.write_u32(value))
        self.assertEqual(w.finish().hex(), "00")

    def test_writer_option_some_is_tag_plus_payload(self):
        w = BincodeWriter()
        w.write_option(42, lambda writer, value: writer.write_u32(value))
        self.assertEqual(w.finish().hex(), "01" + "2a000000")

    def test_writer_vec_is_u64_length_plus_elements(self):
        w = BincodeWriter()
        w.write_vec(["a", "bc"], lambda writer, value: writer.write_string(value))
        self.assertEqual(
            w.finish().hex(),
            "0200000000000000" + "0100000000000000" + "61" + "0200000000000000" + "6263",
        )

    def test_writer_f32_f64_are_little_endian_ieee(self):
        w32 = BincodeWriter()
        w32.write_f32(1.0)
        self.assertEqual(w32.finish().hex(), "0000803f")

        w64 = BincodeWriter()
        w64.write_f64(2.5)
        self.assertEqual(w64.finish().hex(), "0000000000000440")


# ─── encode_agent_register_data ─────────────────────────────────────


class AgentRegisterEncoderTests(unittest.TestCase):
    def test_zero_filled_inputs_produce_rust_hash_string_layout(self):
        bytes_out = encode_agent_register_data(
            name="",
            description="",
            capabilities=[],
        )
        expected = (
            "0000000000000000"                    # name ""
            + "0000000000000000"                  # description ""
            + "00"                                # neural_embedding None
            + "4000000000000000"                  # model_hash string length 64
            + ("30" * 64)                         # model_hash zero hex string
            + "0000000000000000"                  # capabilities
            + "0000000000000000"                  # metadata
            + "0000000000000000"                  # min_fee
            + "0000000000000000"                  # fee_schedule
        )
        self.assertEqual(len(bytes_out), 121)
        self.assertEqual(bytes_out.hex(), expected)

    def test_small_inputs_emit_expected_wire_layout(self):
        bytes_out = encode_agent_register_data(
            name="ab",
            description="",
            capabilities=["x"],
        )
        expected = (
            "0200000000000000" + "6162"           # name "ab"
            + "0000000000000000"                    # description ""
            + "00"                                  # neural_embedding None
            + "4000000000000000"                   # model_hash string length 64
            + ("30" * 64)                          # model_hash zero hex string
            + "0100000000000000"                   # capabilities Vec len 1
            + "0100000000000000" + "78"          # Capability("x")
            + "0000000000000000"                   # metadata Vec len 0
            + "0000000000000000"                   # min_fee 0
            + "0000000000000000"                   # fee_schedule Vec len 0
        )
        self.assertEqual(bytes_out.hex(), expected)

    def test_some_neural_embedding_encodes_vec_of_f32(self):
        bytes_out = encode_agent_register_data(
            name="",
            description="",
            capabilities=[],
            neural_embedding=[1.0, 2.0],
        )
        expected = (
            "0000000000000000"                  # name ""
            + "0000000000000000"                  # description ""
            + "01"                                # neural_embedding Some tag
            + "0200000000000000"                  # Vec<f32> len 2
            + "0000803f" + "00000040"           # f32 1.0, f32 2.0
            + "4000000000000000"                  # model_hash string length 64
            + ("30" * 64)                         # model_hash zero hex string
            + "0000000000000000"                  # capabilities
            + "0000000000000000"                  # metadata
            + "0000000000000000"                  # min_fee
            + "0000000000000000"                  # fee_schedule
        )
        self.assertEqual(bytes_out.hex(), expected)


# ─── encode_task_submit_data ────────────────────────────────────────


class TaskSubmitEncoderTests(unittest.TestCase):
    def test_defaults_match_match_preferences_default(self):
        bytes_out = encode_task_submit_data(
            description="x",
            required_capabilities=[],
            max_fee_micro_zin=0,
        )
        # 9 (desc "x") + 1 (None) + 8 (caps []) + 8 (max_fee) + 1 (priority) +
        # 8 (deadline) + 8 (parameters) + 5*1 (weights) + 8 (min_rep) +
        # 8 (max_price) + 4 (discovery_threshold) + 1 (discovery_boost) = 69
        self.assertEqual(len(bytes_out), 69)

        expected = (
            "0100000000000000" + "78"           # description "x"
            + "00"                                # neural_embedding None
            + "0000000000000000"                  # required_capabilities Vec len 0
            + "0000000000000000"                  # max_fee 0
            + "00"                                # priority 0
            + "0000000000000000"                  # deadline 0
            + "0000000000000000"                  # parameters Vec len 0
            + "1e" + "1e" + "14" + "0a" + "0a"  # weights 30,30,20,10,10
            + "0000000000000000"                  # min_reputation 0.0
            + "0000000000000000"                  # max_price 0
            + "0a000000"                          # discovery_threshold 10
            + "0f"                                # discovery_boost 15
        )
        self.assertEqual(bytes_out.hex(), expected)


# ─── Golden vector tests ────────────────────────────────────────────
# Generated by `ZINCHA_WRITE_SDK_GOLDEN=1 cargo test --test sdk_vectors`.
# They are checked in and must be present.


def _python_fixture_path(name: str) -> Path:
    return Path(__file__).resolve().parents[2] / "testdata" / name


class GoldenVectorTests(unittest.TestCase):
    def test_encode_agent_register_data_matches_rust_golden(self):
        path = _python_fixture_path("golden-agent-register.json")
        golden = json.loads(path.read_text())
        inp = golden["input"]
        data = encode_agent_register_data(
            name=inp["name"],
            description=inp["description"],
            capabilities=inp["capabilities"],
            min_fee_micro_zin=inp["min_fee_micro_zin"],
            fee_schedule=[(name, fee) for name, fee in inp["fee_schedule"]],
        )
        self.assertEqual(data.hex(), golden["data_hex"])

    def test_encode_task_submit_data_matches_rust_golden(self):
        path = _python_fixture_path("golden-task-submit.json")
        golden = json.loads(path.read_text())
        inp = golden["input"]
        prefs_in = inp["match_preferences"]
        data = encode_task_submit_data(
            description=inp["description"],
            required_capabilities=inp["required_capabilities"],
            max_fee_micro_zin=inp["max_fee_micro_zin"],
            priority=inp["priority"],
            deadline_ms=inp["deadline_ms"],
            match_preferences=MatchPreferences(
                w_semantic=prefs_in["w_semantic"],
                w_reputation=prefs_in["w_reputation"],
                w_price=prefs_in["w_price"],
                w_freshness=prefs_in["w_freshness"],
                w_stake=prefs_in["w_stake"],
                min_reputation=prefs_in["min_reputation"],
                max_price=prefs_in["max_price"],
                discovery_threshold=prefs_in["discovery_threshold"],
                discovery_boost=prefs_in["discovery_boost"],
            ),
        )
        self.assertEqual(data.hex(), golden["data_hex"])

    def test_task_lifecycle_encoders_match_rust_golden(self):
        path = _python_fixture_path("golden-task-lifecycle.json")
        golden = json.loads(path.read_text())

        fulfill = encode_task_fulfill_data(
            task_id=golden["fulfill"]["input"]["task_id"],
            result_hash=golden["fulfill"]["input"]["result_hash"],
            result_data=bytes.fromhex(golden["fulfill"]["input"]["result_data_hex"]),
            tools_used=golden["fulfill"]["input"]["tools_used"],
            input_refs=golden["fulfill"]["input"]["input_refs"],
            receipt_proofs=[
                {
                    "receipt": {
                        "token_id": proof["receipt"]["token_id"],
                        "tool_id": proof["receipt"]["tool_id"],
                        "invoker": proof["receipt"]["invoker"],
                        "amount_paid": proof["receipt"]["amount_paid"],
                        "issued_at": proof["receipt"]["issued_at"],
                        "block_number": proof["receipt"]["block_number"],
                        "nonce": proof["receipt"]["nonce"],
                    },
                    "proof_siblings": proof["proof_siblings"],
                    "receipt_root": proof["receipt_root"],
                }
                for proof in golden["fulfill"]["input"]["receipt_proofs"]
            ],
        )
        self.assertEqual(fulfill.hex(), golden["fulfill"]["data_hex"])

        accept = encode_task_accept_data(task_id=golden["accept"]["input"]["task_id"])
        self.assertEqual(accept.hex(), golden["accept"]["data_hex"])

        dispute = encode_task_dispute_data(
            task_id=golden["dispute"]["input"]["task_id"],
            reason=golden["dispute"]["input"]["reason"],
        )
        self.assertEqual(dispute.hex(), golden["dispute"]["data_hex"])

        resolve = encode_task_resolve_data(
            task_id=golden["resolve"]["input"]["task_id"],
            agent_wins=golden["resolve"]["input"]["agent_wins"],
            reason=golden["resolve"]["input"]["reason"],
        )
        self.assertEqual(resolve.hex(), golden["resolve"]["data_hex"])

        finalize = encode_task_finalize_data(task_id=golden["finalize"]["input"]["task_id"])
        self.assertEqual(finalize.hex(), golden["finalize"]["data_hex"])

        cancel = encode_task_cancel_data(task_id=golden["cancel"]["input"]["task_id"])
        self.assertEqual(cancel.hex(), golden["cancel"]["data_hex"])

    def test_agreement_lifecycle_encoders_match_rust_golden(self):
        golden = json.loads(_python_fixture_path("golden-agreement-lifecycle.json").read_text())
        create = golden["create"]["input"]
        encoded_create = encode_agreement_create_data(
            parties=create["parties"],
            terms=bytes.fromhex(create["terms_hex"]),
            escrow_amount=create["escrow_amount"],
            expires_at=create["expires_at"],
            arbitrator=create["arbitrator"],
            milestones=[AgreementMilestone(**item) for item in create["milestones"]],
            service_provider=create["service_provider"],
            settlement_allocations=[
                AgreementPayout(**item) for item in create["settlement_allocations"]
            ],
            settlement_approver=create["settlement_approver"],
        )
        self.assertEqual(encoded_create.hex(), golden["create"]["data_hex"])
        self.assertEqual(
            encode_agreement_accept_data(**golden["accept"]["input"]).hex(),
            golden["accept"]["data_hex"],
        )
        self.assertEqual(
            encode_agreement_execute_data(**golden["execute"]["input"]).hex(),
            golden["execute"]["data_hex"],
        )
        self.assertEqual(
            encode_agreement_dispute_data(**golden["dispute"]["input"]).hex(),
            golden["dispute"]["data_hex"],
        )
        resolve = golden["resolve"]["input"]
        self.assertEqual(
            encode_agreement_resolve_data(
                agreement_id=resolve["agreement_id"],
                payouts=[AgreementPayout(**item) for item in resolve["payouts"]],
                reputation_effects=[
                    AgreementReputationEffect(**item)
                    for item in resolve["reputation_effects"]
                ],
                reason=resolve["reason"],
                milestone_index=resolve["milestone_index"],
            ).hex(),
            golden["resolve"]["data_hex"],
        )
        self.assertEqual(
            encode_agreement_cancel_data(**golden["cancel"]["input"]).hex(),
            golden["cancel"]["data_hex"],
        )

    def test_agreement_encoders_reject_invalid_settlement_and_milestones(self):
        proposer = "zn1" + "11" * 20
        provider = "zn1" + "22" * 20
        with self.assertRaisesRegex(ValueError, "sum to escrow_amount"):
            encode_agreement_create_data(
                parties=[proposer, provider],
                terms=b"",
                escrow_amount=100,
                expires_at=0,
                service_provider=provider,
                milestones=[AgreementMilestone("bad", 99)],
            )
        with self.assertRaisesRegex(ValueError, "sum to 10,000"):
            encode_agreement_resolve_data(
                agreement_id="aa" * 32,
                payouts=[AgreementPayout(provider, 9_999)],
                reason="reason",
            )
        with self.assertRaisesRegex(ValueError, "4,096 UTF-8 bytes"):
            encode_agreement_dispute_data(
                agreement_id="aa" * 32,
                reason="x" * 4_097,
            )

    def test_agreement_client_builders_sign_lifecycle_and_fund_create_escrow(self):
        keypair = Keypair.from_secret_hex(GOLDEN["secret_hex"])
        provider = "zn1" + "22" * 20

        def transport(*_args):
            raise AssertionError("network should not be used")

        client = ZinchaClient(base_url="http://node.test/", transport=transport)
        common = {
            "nonce": 10,
            "chain_id": "zincha-vega-1",
            "timestamp_ms": 1_700_000_000_000,
            "reference_block_height": 42,
            "reference_block_hash": "11" * 32,
            "max_valid_block_height": 142,
        }
        created = client.build_create_agreement(
            keypair,
            **common,
            parties=[keypair.address(), provider],
            terms=b"deliver",
            escrow_amount=1_000,
            expires_at=1_900_000_000_000,
            service_provider=provider,
        )
        self.assertEqual(created.transaction.tx_type, "agreement_create")
        self.assertEqual(created.transaction.amount, 1_000)
        with self.assertRaisesRegex(ValueError, "non-proposer payout recipient"):
            client.build_create_agreement(
                keypair,
                **common,
                parties=[keypair.address(), provider],
                terms=b"",
                escrow_amount=1_000,
                expires_at=0,
                service_provider=provider,
                settlement_approver=provider,
            )

        agreement_id = "aa" * 32
        accept = client.build_accept_agreement(keypair, **common, agreement_id=agreement_id)
        execute = client.build_execute_agreement(
            keypair,
            **common,
            agreement_id=agreement_id,
            result_hash="bb" * 32,
            milestone_index=0,
        )
        dispute = client.build_dispute_agreement(
            keypair,
            **common,
            agreement_id=agreement_id,
            reason="failed",
            milestone_index=0,
        )
        resolve = client.build_resolve_agreement(
            keypair,
            **common,
            agreement_id=agreement_id,
            payouts=[AgreementPayout(provider, 10_000)],
            reason="resolved",
            milestone_index=0,
        )
        cancel = client.build_cancel_agreement(keypair, **common, agreement_id=agreement_id)
        self.assertEqual(
            [tx.transaction.tx_type for tx in (accept, execute, dispute, resolve, cancel)],
            [
                "agreement_accept",
                "agreement_execute",
                "agreement_dispute",
                "agreement_resolve",
                "agreement_cancel",
            ],
        )
        for signed in (accept, execute, dispute, resolve, cancel):
            self.assertEqual(signed.transaction.amount, 0)
            self.assertRegex(signed.hash, r"^[0-9a-f]{64}$")

    def test_reputation_update_encoder_matches_rust_wire_layout(self):
        task_id = "12" * 32
        encoded = encode_reputation_update_data(
            task_id=task_id,
            quality_score=9.25,
            requester_accepted=True,
            feedback="great",
        )
        self.assertEqual(
            encoded.hex(),
            "4000000000000000"
            + "3132" * 32
            + "0000000000802240"
            + "01"
            + "0500000000000000"
            + "6772656174",
        )

        with self.assertRaisesRegex(ValueError, "finite"):
            encode_reputation_update_data(
                task_id=task_id,
                quality_score=float("nan"),
                requester_accepted=True,
            )
        with self.assertRaisesRegex(ValueError, "between 0 and 10"):
            encode_reputation_update_data(
                task_id=task_id,
                quality_score=10.1,
                requester_accepted=True,
            )

    def test_reputation_update_builder_signs_typed_transaction_and_caps_feedback(self):
        keypair = Keypair.from_secret_hex(GOLDEN["secret_hex"])

        def transport(method, url, headers, body, timeout):
            raise AssertionError("network should not be used when signing inputs are explicit")

        client = ZinchaClient(base_url="http://node.test/", transport=transport)
        task_id = "34" * 32
        signed = client.build_update_reputation(
            keypair,
            task_id=task_id,
            quality_score=8.5,
            requester_accepted=False,
            feedback="x" * 501,
            fee_micro_zin=100,
            nonce=12,
            chain_id="zincha-vega-1",
            timestamp_ms=1_700_000_000_789,
            reference_block_height=42,
            reference_block_hash="11" * 32,
            max_valid_block_height=142,
        )

        self.assertEqual(signed.transaction.tx_type, "reputation_update")
        self.assertEqual(TX_TYPE_WIRE_CODES["reputation_update"], 7)
        self.assertEqual(
            signed.transaction.data.hex(),
            encode_reputation_update_data(
                task_id=task_id,
                quality_score=8.5,
                requester_accepted=False,
                feedback="x" * 500,
            ).hex(),
        )

    def test_task_lifecycle_builders_produce_rust_compatible_signed_transactions(self):
        path = _python_fixture_path("golden-task-lifecycle.json")
        golden = json.loads(path.read_text())
        keypair = Keypair.from_secret_hex(golden["secret_hex"])

        def transport(method, url, headers, body, timeout):
            raise AssertionError("network should not be used when chain, nonce, and validity are explicit")

        client = ZinchaClient(base_url="http://node.test/", transport=transport)

        def common(transaction):
            return {
                "fee_micro_zin": transaction["fee_micro_zin"],
                "nonce": transaction["nonce"],
                "chain_id": transaction["chain_id"],
                "timestamp_ms": transaction["timestamp"],
                "reference_block_height": transaction["reference_block_height"],
                "reference_block_hash": transaction["reference_block_hash"],
                "max_valid_block_height": transaction["max_valid_block_height"],
            }

        fulfill = client.build_fulfill_task(
            keypair,
            **common(golden["fulfill"]["transaction"]),
            task_id=golden["fulfill"]["input"]["task_id"],
            result_hash=golden["fulfill"]["input"]["result_hash"],
            result_data=bytes.fromhex(golden["fulfill"]["input"]["result_data_hex"]),
            tools_used=golden["fulfill"]["input"]["tools_used"],
            input_refs=golden["fulfill"]["input"]["input_refs"],
            receipt_proofs=golden["fulfill"]["input"]["receipt_proofs"],
        )
        self.assertEqual(signed_transaction_hex(fulfill), golden["fulfill"]["transaction"]["signed_tx_hex"])

        accept = client.build_accept_task(
            keypair,
            **common(golden["accept"]["transaction"]),
            task_id=golden["accept"]["input"]["task_id"],
        )
        self.assertEqual(signed_transaction_hex(accept), golden["accept"]["transaction"]["signed_tx_hex"])

        dispute = client.build_dispute_task(
            keypair,
            **common(golden["dispute"]["transaction"]),
            task_id=golden["dispute"]["input"]["task_id"],
            reason=golden["dispute"]["input"]["reason"],
        )
        self.assertEqual(signed_transaction_hex(dispute), golden["dispute"]["transaction"]["signed_tx_hex"])

        resolve = client.build_resolve_task(
            keypair,
            **common(golden["resolve"]["transaction"]),
            task_id=golden["resolve"]["input"]["task_id"],
            agent_wins=golden["resolve"]["input"]["agent_wins"],
            reason=golden["resolve"]["input"]["reason"],
        )
        self.assertEqual(signed_transaction_hex(resolve), golden["resolve"]["transaction"]["signed_tx_hex"])

        finalize = client.build_finalize_task(
            keypair,
            **common(golden["finalize"]["transaction"]),
            task_id=golden["finalize"]["input"]["task_id"],
        )
        self.assertEqual(signed_transaction_hex(finalize), golden["finalize"]["transaction"]["signed_tx_hex"])

        cancel = client.build_cancel_task(
            keypair,
            **common(golden["cancel"]["transaction"]),
            task_id=golden["cancel"]["input"]["task_id"],
        )
        self.assertEqual(signed_transaction_hex(cancel), golden["cancel"]["transaction"]["signed_tx_hex"])

    def test_agent_tool_lifecycle_encoders_match_rust_golden(self):
        path = _python_fixture_path("golden-agent-tool-lifecycle.json")
        golden = json.loads(path.read_text())

        agent_update = encode_agent_update_data(
            name=golden["agent_update"]["input"]["name"],
            description=golden["agent_update"]["input"]["description"],
            neural_embedding=golden["agent_update"]["input"]["neural_embedding"],
            model_hash=golden["agent_update"]["input"]["model_hash"],
            capabilities=golden["agent_update"]["input"]["capabilities"],
            metadata=bytes.fromhex(golden["agent_update"]["input"]["metadata_hex"]),
            active=golden["agent_update"]["input"]["active"],
            min_fee_micro_zin=golden["agent_update"]["input"]["min_fee_micro_zin"],
            fee_schedule=[tuple(entry) for entry in golden["agent_update"]["input"]["fee_schedule"]],
        )
        self.assertEqual(agent_update.hex(), golden["agent_update"]["data_hex"])

        agent_deregister = encode_agent_deregister_data()
        self.assertEqual(agent_deregister.hex(), golden["agent_deregister"]["data_hex"])

        tool_register = encode_tool_register_data(
            name=golden["tool_register"]["input"]["name"],
            description=golden["tool_register"]["input"]["description"],
            endpoint=golden["tool_register"]["input"]["endpoint"],
            price_per_call=golden["tool_register"]["input"]["price_per_call"],
            capabilities=golden["tool_register"]["input"]["capabilities"],
            settlement_mode=golden["tool_register"]["input"]["settlement_mode"],
            sla_ms=golden["tool_register"]["input"]["sla_ms"],
            challenge_window_ms=golden["tool_register"]["input"]["challenge_window_ms"],
            max_result_metadata_bytes=golden["tool_register"]["input"]["max_result_metadata_bytes"],
            arbitration_policy=golden["tool_register"]["input"]["arbitration_policy"],
            match_enabled=golden["tool_register"]["input"]["match_enabled"],
            neural_embedding=golden["tool_register"]["input"]["neural_embedding"],
            version=golden["tool_register"]["input"]["version"],
        )
        self.assertEqual(tool_register.hex(), golden["tool_register"]["data_hex"])

        tool_invoke = encode_tool_invoke_data(
            tool_id=golden["tool_invoke"]["input"]["tool_id"],
            input_data=bytes.fromhex(golden["tool_invoke"]["input"]["input_data_hex"]),
            max_metered_units=golden["tool_invoke"]["input"]["max_metered_units"],
            gas_limit=golden["tool_invoke"]["input"]["gas_limit"],
            milestones=golden["tool_invoke"]["input"]["milestones"],
        )
        self.assertEqual(tool_invoke.hex(), golden["tool_invoke"]["data_hex"])

        tool_update = encode_tool_update_data(
            tool_id=golden["tool_update"]["input"]["tool_id"],
            description=golden["tool_update"]["input"]["description"],
            endpoint=golden["tool_update"]["input"]["endpoint"],
            price_per_call=golden["tool_update"]["input"]["price_per_call"],
            settlement_mode=golden["tool_update"]["input"]["settlement_mode"],
            sla_ms=golden["tool_update"]["input"]["sla_ms"],
            challenge_window_ms=golden["tool_update"]["input"]["challenge_window_ms"],
            max_result_metadata_bytes=golden["tool_update"]["input"]["max_result_metadata_bytes"],
            arbitration_policy=golden["tool_update"]["input"]["arbitration_policy"],
            capabilities=golden["tool_update"]["input"]["capabilities"],
            match_enabled=golden["tool_update"]["input"]["match_enabled"],
            neural_embedding=golden["tool_update"]["input"]["neural_embedding"],
            version=golden["tool_update"]["input"]["version"],
            active=golden["tool_update"]["input"]["active"],
        )
        self.assertEqual(tool_update.hex(), golden["tool_update"]["data_hex"])

        tool_deregister = encode_tool_deregister_data(
            tool_id=golden["tool_deregister"]["input"]["tool_id"]
        )
        self.assertEqual(tool_deregister.hex(), golden["tool_deregister"]["data_hex"])

        self.assertEqual(
            encode_tool_result_submit_data(
                job_id=golden["tool_result_submit"]["input"]["job_id"],
                result_hash=golden["tool_result_submit"]["input"]["result_hash"],
                result_metadata=bytes.fromhex(golden["tool_result_submit"]["input"]["result_metadata_hex"]),
                milestone_index=golden["tool_result_submit"]["input"]["milestone_index"],
            ).hex(),
            golden["tool_result_submit"]["data_hex"],
        )
        self.assertEqual(
            encode_tool_result_accept_data(
                job_id=golden["tool_result_accept"]["input"]["job_id"],
                milestone_index=golden["tool_result_accept"]["input"]["milestone_index"],
            ).hex(),
            golden["tool_result_accept"]["data_hex"],
        )
        self.assertEqual(
            encode_tool_result_dispute_data(
                job_id=golden["tool_result_dispute"]["input"]["job_id"],
                reason=golden["tool_result_dispute"]["input"]["reason"],
                milestone_index=golden["tool_result_dispute"]["input"]["milestone_index"],
            ).hex(),
            golden["tool_result_dispute"]["data_hex"],
        )
        self.assertEqual(
            encode_tool_result_resolve_data(
                job_id=golden["tool_result_resolve"]["input"]["job_id"],
                provider_wins=golden["tool_result_resolve"]["input"]["provider_wins"],
                reason=golden["tool_result_resolve"]["input"]["reason"],
                milestone_index=golden["tool_result_resolve"]["input"]["milestone_index"],
            ).hex(),
            golden["tool_result_resolve"]["data_hex"],
        )
        self.assertEqual(
            encode_tool_job_expire_data(
                job_id=golden["tool_job_expire"]["input"]["job_id"],
            ).hex(),
            golden["tool_job_expire"]["data_hex"],
        )
        self.assertEqual(
            encode_tool_usage_report_data(
                session_id=golden["tool_usage_report"]["input"]["session_id"],
                units_used=golden["tool_usage_report"]["input"]["units_used"],
                result_hash=golden["tool_usage_report"]["input"]["result_hash"],
                result_metadata=bytes.fromhex(golden["tool_usage_report"]["input"]["result_metadata_hex"]),
            ).hex(),
            golden["tool_usage_report"]["data_hex"],
        )
        self.assertEqual(
            encode_tool_usage_accept_data(
                session_id=golden["tool_usage_accept"]["input"]["session_id"],
            ).hex(),
            golden["tool_usage_accept"]["data_hex"],
        )
        self.assertEqual(
            encode_tool_usage_dispute_data(
                session_id=golden["tool_usage_dispute"]["input"]["session_id"],
                reason=golden["tool_usage_dispute"]["input"]["reason"],
            ).hex(),
            golden["tool_usage_dispute"]["data_hex"],
        )
        self.assertEqual(
            encode_tool_usage_resolve_data(
                session_id=golden["tool_usage_resolve"]["input"]["session_id"],
                provider_wins=golden["tool_usage_resolve"]["input"]["provider_wins"],
                reason=golden["tool_usage_resolve"]["input"]["reason"],
            ).hex(),
            golden["tool_usage_resolve"]["data_hex"],
        )
        self.assertEqual(
            encode_tool_usage_expire_data(
                session_id=golden["tool_usage_expire"]["input"]["session_id"],
            ).hex(),
            golden["tool_usage_expire"]["data_hex"],
        )
        self.assertEqual(
            encode_tool_subscription_plan_create_data(
                tool_id=golden["tool_subscription_plan_create"]["input"]["tool_id"],
                name=golden["tool_subscription_plan_create"]["input"]["name"],
                price_per_period=golden["tool_subscription_plan_create"]["input"]["price_per_period"],
                period_ms=golden["tool_subscription_plan_create"]["input"]["period_ms"],
                included_calls=golden["tool_subscription_plan_create"]["input"]["included_calls"],
                included_credits=golden["tool_subscription_plan_create"]["input"]["included_credits"],
                overage_policy=golden["tool_subscription_plan_create"]["input"]["overage_policy"],
            ).hex(),
            golden["tool_subscription_plan_create"]["data_hex"],
        )
        self.assertEqual(
            encode_tool_subscription_plan_update_data(
                plan_id=golden["tool_subscription_plan_update"]["input"]["plan_id"],
                name=golden["tool_subscription_plan_update"]["input"]["name"],
                price_per_period=golden["tool_subscription_plan_update"]["input"]["price_per_period"],
                period_ms=golden["tool_subscription_plan_update"]["input"]["period_ms"],
                included_calls=golden["tool_subscription_plan_update"]["input"]["included_calls"],
                included_credits=golden["tool_subscription_plan_update"]["input"]["included_credits"],
                overage_policy=golden["tool_subscription_plan_update"]["input"]["overage_policy"],
                active=golden["tool_subscription_plan_update"]["input"]["active"],
            ).hex(),
            golden["tool_subscription_plan_update"]["data_hex"],
        )
        self.assertEqual(
            encode_tool_subscription_start_data(
                plan_id=golden["tool_subscription_start"]["input"]["plan_id"],
                reserve_amount=golden["tool_subscription_start"]["input"]["reserve_amount"],
                auto_renew=golden["tool_subscription_start"]["input"]["auto_renew"],
            ).hex(),
            golden["tool_subscription_start"]["data_hex"],
        )
        self.assertEqual(
            encode_tool_subscription_top_up_data(
                subscription_id=golden["tool_subscription_top_up"]["input"]["subscription_id"],
                amount=golden["tool_subscription_top_up"]["input"]["amount"],
            ).hex(),
            golden["tool_subscription_top_up"]["data_hex"],
        )
        self.assertEqual(
            encode_tool_subscription_cancel_data(
                subscription_id=golden["tool_subscription_cancel"]["input"]["subscription_id"],
            ).hex(),
            golden["tool_subscription_cancel"]["data_hex"],
        )
        self.assertEqual(
            encode_tool_subscription_resume_data(
                subscription_id=golden["tool_subscription_resume"]["input"]["subscription_id"],
                reserve_amount=golden["tool_subscription_resume"]["input"]["reserve_amount"],
            ).hex(),
            golden["tool_subscription_resume"]["data_hex"],
        )
        self.assertEqual(
            encode_tool_subscription_renew_data(
                subscription_id=golden["tool_subscription_renew"]["input"]["subscription_id"],
            ).hex(),
            golden["tool_subscription_renew"]["data_hex"],
        )

    def test_agent_tool_lifecycle_builders_produce_rust_compatible_signed_transactions(self):
        path = _python_fixture_path("golden-agent-tool-lifecycle.json")
        golden = json.loads(path.read_text())
        keypair = Keypair.from_secret_hex(golden["secret_hex"])

        def transport(method, url, headers, body, timeout):
            raise AssertionError("network should not be used when chain, nonce, and validity are explicit")

        client = ZinchaClient(base_url="http://node.test/", transport=transport)

        def common(transaction):
            return {
                "fee_micro_zin": transaction["fee_micro_zin"],
                "nonce": transaction["nonce"],
                "chain_id": transaction["chain_id"],
                "timestamp_ms": transaction["timestamp"],
                "reference_block_height": transaction["reference_block_height"],
                "reference_block_hash": transaction["reference_block_hash"],
                "max_valid_block_height": transaction["max_valid_block_height"],
            }

        agent_update = client.build_update_agent(
            keypair,
            **common(golden["agent_update"]["transaction"]),
            name=golden["agent_update"]["input"]["name"],
            description=golden["agent_update"]["input"]["description"],
            neural_embedding=golden["agent_update"]["input"]["neural_embedding"],
            model_hash=golden["agent_update"]["input"]["model_hash"],
            capabilities=golden["agent_update"]["input"]["capabilities"],
            metadata=bytes.fromhex(golden["agent_update"]["input"]["metadata_hex"]),
            active=golden["agent_update"]["input"]["active"],
            min_fee_micro_zin=golden["agent_update"]["input"]["min_fee_micro_zin"],
            fee_schedule=[tuple(entry) for entry in golden["agent_update"]["input"]["fee_schedule"]],
        )
        self.assertEqual(
            signed_transaction_hex(agent_update),
            golden["agent_update"]["transaction"]["signed_tx_hex"],
        )

        agent_deregister = client.build_deregister_agent(
            keypair,
            **common(golden["agent_deregister"]["transaction"]),
        )
        self.assertEqual(
            signed_transaction_hex(agent_deregister),
            golden["agent_deregister"]["transaction"]["signed_tx_hex"],
        )

        tool_register = client.build_register_tool(
            keypair,
            **common(golden["tool_register"]["transaction"]),
            name=golden["tool_register"]["input"]["name"],
            description=golden["tool_register"]["input"]["description"],
            endpoint=golden["tool_register"]["input"]["endpoint"],
            price_per_call=golden["tool_register"]["input"]["price_per_call"],
            capabilities=golden["tool_register"]["input"]["capabilities"],
            settlement_mode=golden["tool_register"]["input"]["settlement_mode"],
            sla_ms=golden["tool_register"]["input"]["sla_ms"],
            challenge_window_ms=golden["tool_register"]["input"]["challenge_window_ms"],
            max_result_metadata_bytes=golden["tool_register"]["input"]["max_result_metadata_bytes"],
            arbitration_policy=golden["tool_register"]["input"]["arbitration_policy"],
            match_enabled=golden["tool_register"]["input"]["match_enabled"],
            neural_embedding=golden["tool_register"]["input"]["neural_embedding"],
            version=golden["tool_register"]["input"]["version"],
        )
        self.assertEqual(
            signed_transaction_hex(tool_register),
            golden["tool_register"]["transaction"]["signed_tx_hex"],
        )

        tool_invoke = client.build_invoke_tool(
            keypair,
            **common(golden["tool_invoke"]["transaction"]),
            tool_id=golden["tool_invoke"]["input"]["tool_id"],
            input_data=bytes.fromhex(golden["tool_invoke"]["input"]["input_data_hex"]),
            max_metered_units=golden["tool_invoke"]["input"]["max_metered_units"],
            gas_limit=golden["tool_invoke"]["input"]["gas_limit"],
            milestones=golden["tool_invoke"]["input"]["milestones"],
        )
        self.assertEqual(
            signed_transaction_hex(tool_invoke),
            golden["tool_invoke"]["transaction"]["signed_tx_hex"],
        )

        tool_update = client.build_update_tool(
            keypair,
            **common(golden["tool_update"]["transaction"]),
            tool_id=golden["tool_update"]["input"]["tool_id"],
            description=golden["tool_update"]["input"]["description"],
            endpoint=golden["tool_update"]["input"]["endpoint"],
            price_per_call=golden["tool_update"]["input"]["price_per_call"],
            settlement_mode=golden["tool_update"]["input"]["settlement_mode"],
            sla_ms=golden["tool_update"]["input"]["sla_ms"],
            challenge_window_ms=golden["tool_update"]["input"]["challenge_window_ms"],
            max_result_metadata_bytes=golden["tool_update"]["input"]["max_result_metadata_bytes"],
            arbitration_policy=golden["tool_update"]["input"]["arbitration_policy"],
            capabilities=golden["tool_update"]["input"]["capabilities"],
            match_enabled=golden["tool_update"]["input"]["match_enabled"],
            neural_embedding=golden["tool_update"]["input"]["neural_embedding"],
            version=golden["tool_update"]["input"]["version"],
            active=golden["tool_update"]["input"]["active"],
        )
        self.assertEqual(
            signed_transaction_hex(tool_update),
            golden["tool_update"]["transaction"]["signed_tx_hex"],
        )

        tool_deregister = client.build_deregister_tool(
            keypair,
            **common(golden["tool_deregister"]["transaction"]),
            tool_id=golden["tool_deregister"]["input"]["tool_id"],
        )
        self.assertEqual(
            signed_transaction_hex(tool_deregister),
            golden["tool_deregister"]["transaction"]["signed_tx_hex"],
        )

        result_submit = client.build_submit_tool_result(
            keypair,
            **common(golden["tool_result_submit"]["transaction"]),
            job_id=golden["tool_result_submit"]["input"]["job_id"],
            result_hash=golden["tool_result_submit"]["input"]["result_hash"],
            result_metadata=bytes.fromhex(golden["tool_result_submit"]["input"]["result_metadata_hex"]),
            milestone_index=golden["tool_result_submit"]["input"]["milestone_index"],
        )
        self.assertEqual(signed_transaction_hex(result_submit), golden["tool_result_submit"]["transaction"]["signed_tx_hex"])

        result_accept = client.build_accept_tool_result(
            keypair,
            **common(golden["tool_result_accept"]["transaction"]),
            job_id=golden["tool_result_accept"]["input"]["job_id"],
            milestone_index=golden["tool_result_accept"]["input"]["milestone_index"],
        )
        self.assertEqual(signed_transaction_hex(result_accept), golden["tool_result_accept"]["transaction"]["signed_tx_hex"])

        result_dispute = client.build_dispute_tool_result(
            keypair,
            **common(golden["tool_result_dispute"]["transaction"]),
            job_id=golden["tool_result_dispute"]["input"]["job_id"],
            reason=golden["tool_result_dispute"]["input"]["reason"],
            milestone_index=golden["tool_result_dispute"]["input"]["milestone_index"],
        )
        self.assertEqual(signed_transaction_hex(result_dispute), golden["tool_result_dispute"]["transaction"]["signed_tx_hex"])

        result_resolve = client.build_resolve_tool_result(
            keypair,
            **common(golden["tool_result_resolve"]["transaction"]),
            job_id=golden["tool_result_resolve"]["input"]["job_id"],
            provider_wins=golden["tool_result_resolve"]["input"]["provider_wins"],
            reason=golden["tool_result_resolve"]["input"]["reason"],
            milestone_index=golden["tool_result_resolve"]["input"]["milestone_index"],
        )
        self.assertEqual(signed_transaction_hex(result_resolve), golden["tool_result_resolve"]["transaction"]["signed_tx_hex"])

        job_expire = client.build_expire_tool_job(
            keypair,
            **common(golden["tool_job_expire"]["transaction"]),
            job_id=golden["tool_job_expire"]["input"]["job_id"],
        )
        self.assertEqual(signed_transaction_hex(job_expire), golden["tool_job_expire"]["transaction"]["signed_tx_hex"])

        usage_report = client.build_report_tool_usage(
            keypair,
            **common(golden["tool_usage_report"]["transaction"]),
            session_id=golden["tool_usage_report"]["input"]["session_id"],
            units_used=golden["tool_usage_report"]["input"]["units_used"],
            result_hash=golden["tool_usage_report"]["input"]["result_hash"],
            result_metadata=bytes.fromhex(golden["tool_usage_report"]["input"]["result_metadata_hex"]),
        )
        self.assertEqual(signed_transaction_hex(usage_report), golden["tool_usage_report"]["transaction"]["signed_tx_hex"])

        usage_accept = client.build_accept_tool_usage(
            keypair,
            **common(golden["tool_usage_accept"]["transaction"]),
            session_id=golden["tool_usage_accept"]["input"]["session_id"],
        )
        self.assertEqual(signed_transaction_hex(usage_accept), golden["tool_usage_accept"]["transaction"]["signed_tx_hex"])
        with self.assertRaises(TypeError):
            client.build_accept_tool_usage(
                keypair,
                session_id=golden["tool_usage_accept"]["input"]["session_id"],
                unknown_tx_option=True,
            )

        usage_dispute = client.build_dispute_tool_usage(
            keypair,
            **common(golden["tool_usage_dispute"]["transaction"]),
            session_id=golden["tool_usage_dispute"]["input"]["session_id"],
            reason=golden["tool_usage_dispute"]["input"]["reason"],
        )
        self.assertEqual(signed_transaction_hex(usage_dispute), golden["tool_usage_dispute"]["transaction"]["signed_tx_hex"])

        usage_resolve = client.build_resolve_tool_usage(
            keypair,
            **common(golden["tool_usage_resolve"]["transaction"]),
            session_id=golden["tool_usage_resolve"]["input"]["session_id"],
            provider_wins=golden["tool_usage_resolve"]["input"]["provider_wins"],
            reason=golden["tool_usage_resolve"]["input"]["reason"],
        )
        self.assertEqual(signed_transaction_hex(usage_resolve), golden["tool_usage_resolve"]["transaction"]["signed_tx_hex"])

        usage_expire = client.build_expire_tool_usage(
            keypair,
            **common(golden["tool_usage_expire"]["transaction"]),
            session_id=golden["tool_usage_expire"]["input"]["session_id"],
        )
        self.assertEqual(signed_transaction_hex(usage_expire), golden["tool_usage_expire"]["transaction"]["signed_tx_hex"])

        plan_create = client.build_create_tool_subscription_plan(
            keypair,
            **common(golden["tool_subscription_plan_create"]["transaction"]),
            tool_id=golden["tool_subscription_plan_create"]["input"]["tool_id"],
            name=golden["tool_subscription_plan_create"]["input"]["name"],
            price_per_period=golden["tool_subscription_plan_create"]["input"]["price_per_period"],
            period_ms=golden["tool_subscription_plan_create"]["input"]["period_ms"],
            included_calls=golden["tool_subscription_plan_create"]["input"]["included_calls"],
            included_credits=golden["tool_subscription_plan_create"]["input"]["included_credits"],
            overage_policy=golden["tool_subscription_plan_create"]["input"]["overage_policy"],
        )
        self.assertEqual(signed_transaction_hex(plan_create), golden["tool_subscription_plan_create"]["transaction"]["signed_tx_hex"])

        plan_update = client.build_update_tool_subscription_plan(
            keypair,
            **common(golden["tool_subscription_plan_update"]["transaction"]),
            plan_id=golden["tool_subscription_plan_update"]["input"]["plan_id"],
            name=golden["tool_subscription_plan_update"]["input"]["name"],
            price_per_period=golden["tool_subscription_plan_update"]["input"]["price_per_period"],
            period_ms=golden["tool_subscription_plan_update"]["input"]["period_ms"],
            included_calls=golden["tool_subscription_plan_update"]["input"]["included_calls"],
            included_credits=golden["tool_subscription_plan_update"]["input"]["included_credits"],
            overage_policy=golden["tool_subscription_plan_update"]["input"]["overage_policy"],
            active=golden["tool_subscription_plan_update"]["input"]["active"],
        )
        self.assertEqual(signed_transaction_hex(plan_update), golden["tool_subscription_plan_update"]["transaction"]["signed_tx_hex"])

        subscription_start = client.build_start_tool_subscription(
            keypair,
            **common(golden["tool_subscription_start"]["transaction"]),
            plan_id=golden["tool_subscription_start"]["input"]["plan_id"],
            reserve_amount=golden["tool_subscription_start"]["input"]["reserve_amount"],
            auto_renew=golden["tool_subscription_start"]["input"]["auto_renew"],
        )
        self.assertEqual(signed_transaction_hex(subscription_start), golden["tool_subscription_start"]["transaction"]["signed_tx_hex"])

        subscription_top_up = client.build_top_up_tool_subscription(
            keypair,
            **common(golden["tool_subscription_top_up"]["transaction"]),
            subscription_id=golden["tool_subscription_top_up"]["input"]["subscription_id"],
            amount=golden["tool_subscription_top_up"]["input"]["amount"],
        )
        self.assertEqual(signed_transaction_hex(subscription_top_up), golden["tool_subscription_top_up"]["transaction"]["signed_tx_hex"])

        subscription_cancel = client.build_cancel_tool_subscription(
            keypair,
            **common(golden["tool_subscription_cancel"]["transaction"]),
            subscription_id=golden["tool_subscription_cancel"]["input"]["subscription_id"],
        )
        self.assertEqual(signed_transaction_hex(subscription_cancel), golden["tool_subscription_cancel"]["transaction"]["signed_tx_hex"])

        subscription_resume = client.build_resume_tool_subscription(
            keypair,
            **common(golden["tool_subscription_resume"]["transaction"]),
            subscription_id=golden["tool_subscription_resume"]["input"]["subscription_id"],
            reserve_amount=golden["tool_subscription_resume"]["input"]["reserve_amount"],
        )
        self.assertEqual(signed_transaction_hex(subscription_resume), golden["tool_subscription_resume"]["transaction"]["signed_tx_hex"])

        subscription_renew = client.build_renew_tool_subscription(
            keypair,
            **common(golden["tool_subscription_renew"]["transaction"]),
            subscription_id=golden["tool_subscription_renew"]["input"]["subscription_id"],
        )
        self.assertEqual(signed_transaction_hex(subscription_renew), golden["tool_subscription_renew"]["transaction"]["signed_tx_hex"])

    def test_token_operation_encoders_match_rust_golden(self):
        path = _python_fixture_path("golden-token-operations.json")
        golden = json.loads(path.read_text())

        create = encode_token_create_data(
            name=golden["create"]["input"]["name"],
            symbol=golden["create"]["input"]["symbol"],
            decimals=golden["create"]["input"]["decimals"],
            initial_supply=golden["create"]["input"]["initial_supply"],
            max_supply=golden["create"]["input"]["max_supply"],
            burnable=golden["create"]["input"]["burnable"],
            mint_authority=golden["create"]["input"]["mint_authority"],
            metadata=bytes.fromhex(golden["create"]["input"]["metadata_hex"]),
        )
        self.assertEqual(create.hex(), golden["create"]["data_hex"])

        transfer = encode_token_transfer_data(
            token_id=golden["transfer"]["input"]["token_id"],
            to=golden["transfer"]["input"]["to"],
            amount=golden["transfer"]["input"]["amount"],
        )
        self.assertEqual(transfer.hex(), golden["transfer"]["data_hex"])

        approve = encode_token_approve_data(
            token_id=golden["approve"]["input"]["token_id"],
            spender=golden["approve"]["input"]["spender"],
            amount=golden["approve"]["input"]["amount"],
        )
        self.assertEqual(approve.hex(), golden["approve"]["data_hex"])

        mint = encode_token_mint_data(
            token_id=golden["mint"]["input"]["token_id"],
            to=golden["mint"]["input"]["to"],
            amount=golden["mint"]["input"]["amount"],
        )
        self.assertEqual(mint.hex(), golden["mint"]["data_hex"])

        burn = encode_token_burn_data(
            token_id=golden["burn"]["input"]["token_id"],
            amount=golden["burn"]["input"]["amount"],
        )
        self.assertEqual(burn.hex(), golden["burn"]["data_hex"])

    def test_token_builders_produce_rust_compatible_signed_transactions(self):
        path = _python_fixture_path("golden-token-operations.json")
        golden = json.loads(path.read_text())
        keypair = Keypair.from_secret_hex(golden["secret_hex"])

        def transport(method, url, headers, body, timeout):
            raise AssertionError("network should not be used when chain, nonce, and validity are explicit")

        client = ZinchaClient(base_url="http://node.test/", transport=transport)

        def common(transaction):
            return {
                "fee_micro_zin": transaction["fee_micro_zin"],
                "nonce": transaction["nonce"],
                "chain_id": transaction["chain_id"],
                "timestamp_ms": transaction["timestamp"],
                "reference_block_height": transaction["reference_block_height"],
                "reference_block_hash": transaction["reference_block_hash"],
                "max_valid_block_height": transaction["max_valid_block_height"],
            }

        create = client.build_create_token(
            keypair,
            **common(golden["create"]["transaction"]),
            name=golden["create"]["input"]["name"],
            symbol=golden["create"]["input"]["symbol"],
            decimals=golden["create"]["input"]["decimals"],
            initial_supply=golden["create"]["input"]["initial_supply"],
            max_supply=golden["create"]["input"]["max_supply"],
            burnable=golden["create"]["input"]["burnable"],
            mint_authority=golden["create"]["input"]["mint_authority"],
            metadata=bytes.fromhex(golden["create"]["input"]["metadata_hex"]),
        )
        self.assertEqual(signed_transaction_hex(create), golden["create"]["transaction"]["signed_tx_hex"])

        transfer = client.build_transfer_token(
            keypair,
            **common(golden["transfer"]["transaction"]),
            token_id=golden["transfer"]["input"]["token_id"],
            to=golden["transfer"]["input"]["to"],
            amount=golden["transfer"]["input"]["amount"],
        )
        self.assertEqual(signed_transaction_hex(transfer), golden["transfer"]["transaction"]["signed_tx_hex"])

        approve = client.build_approve_token(
            keypair,
            **common(golden["approve"]["transaction"]),
            token_id=golden["approve"]["input"]["token_id"],
            spender=golden["approve"]["input"]["spender"],
            amount=golden["approve"]["input"]["amount"],
        )
        self.assertEqual(signed_transaction_hex(approve), golden["approve"]["transaction"]["signed_tx_hex"])

        mint = client.build_mint_token(
            keypair,
            **common(golden["mint"]["transaction"]),
            token_id=golden["mint"]["input"]["token_id"],
            to=golden["mint"]["input"]["to"],
            amount=golden["mint"]["input"]["amount"],
        )
        self.assertEqual(signed_transaction_hex(mint), golden["mint"]["transaction"]["signed_tx_hex"])

        burn = client.build_burn_token(
            keypair,
            **common(golden["burn"]["transaction"]),
            token_id=golden["burn"]["input"]["token_id"],
            amount=golden["burn"]["input"]["amount"],
        )
        self.assertEqual(signed_transaction_hex(burn), golden["burn"]["transaction"]["signed_tx_hex"])

    def test_contract_encoders_match_rust_golden(self):
        path = _python_fixture_path("golden-contract-operations.json")
        golden = json.loads(path.read_text())

        deploy = encode_contract_deploy_data(
            bytecode=bytes.fromhex(golden["contract_deploy"]["input"]["bytecode_hex"])
        )
        self.assertEqual(deploy.hex(), golden["contract_deploy"]["data_hex"])

        call = encode_contract_call_data(
            contract_address=golden["contract_call"]["input"]["contract_address"],
            function_name=golden["contract_call"]["input"]["function"],
            args=bytes.fromhex(golden["contract_call"]["input"]["args_hex"]),
            gas_limit=golden["contract_call"]["input"]["gas_limit"],
        )
        self.assertEqual(call.hex(), golden["contract_call"]["data_hex"])

        verify = encode_contract_verify_data(
            contract_address=golden["contract_verify"]["input"]["contract_address"],
            proof=golden["contract_verify"]["input"]["proof"],
        )
        self.assertEqual(verify.hex(), golden["contract_verify"]["data_hex"])

        publish_abi = encode_contract_publish_abi_data(
            contract_address=golden["contract_publish_abi"]["input"]["contract_address"],
            abi=golden["contract_publish_abi"]["input"]["abi"],
        )
        self.assertEqual(publish_abi.hex(), golden["contract_publish_abi"]["data_hex"])

        route_update = encode_contract_route_update_data(
            route_name=golden["contract_route_update"]["input"]["route_name"],
            target_contract_address=golden["contract_route_update"]["input"]["target_contract_address"],
        )
        self.assertEqual(route_update.hex(), golden["contract_route_update"]["data_hex"])

        route_call = encode_contract_route_call_data(
            deployer=golden["contract_route_call"]["input"]["deployer"],
            route_name=golden["contract_route_call"]["input"]["route_name"],
            function_name=golden["contract_route_call"]["input"]["function"],
            args=bytes.fromhex(golden["contract_route_call"]["input"]["args_hex"]),
            gas_limit=golden["contract_route_call"]["input"]["gas_limit"],
        )
        self.assertEqual(route_call.hex(), golden["contract_route_call"]["data_hex"])

        deactivate = encode_contract_deactivate_data(
            contract_address=golden["contract_deactivate"]["input"]["contract_address"]
        )
        self.assertEqual(deactivate.hex(), golden["contract_deactivate"]["data_hex"])

    def test_contract_builders_produce_rust_compatible_signed_transactions(self):
        path = _python_fixture_path("golden-contract-operations.json")
        golden = json.loads(path.read_text())
        keypair = Keypair.from_secret_hex(golden["secret_hex"])

        def transport(method, url, headers, body, timeout):
            raise AssertionError("network should not be used when chain, nonce, and validity are explicit")

        client = ZinchaClient(base_url="http://node.test/", transport=transport)

        def common(transaction):
            return {
                "fee_micro_zin": transaction["fee_micro_zin"],
                "nonce": transaction["nonce"],
                "chain_id": transaction["chain_id"],
                "timestamp_ms": transaction["timestamp"],
                "reference_block_height": transaction["reference_block_height"],
                "reference_block_hash": transaction["reference_block_hash"],
                "max_valid_block_height": transaction["max_valid_block_height"],
            }

        deploy = client.build_deploy_contract(
            keypair,
            **common(golden["contract_deploy"]["transaction"]),
            bytecode=bytes.fromhex(golden["contract_deploy"]["input"]["bytecode_hex"]),
            amount_micro_zin=golden["contract_deploy"]["input"]["amount_micro_zin"],
        )
        self.assertEqual(
            signed_transaction_hex(deploy),
            golden["contract_deploy"]["transaction"]["signed_tx_hex"],
        )

        call = client.build_call_contract(
            keypair,
            **common(golden["contract_call"]["transaction"]),
            contract_address=golden["contract_call"]["input"]["contract_address"],
            function_name=golden["contract_call"]["input"]["function"],
            args=bytes.fromhex(golden["contract_call"]["input"]["args_hex"]),
            gas_limit=golden["contract_call"]["input"]["gas_limit"],
            amount_micro_zin=golden["contract_call"]["input"]["amount_micro_zin"],
        )
        self.assertEqual(
            signed_transaction_hex(call),
            golden["contract_call"]["transaction"]["signed_tx_hex"],
        )

        verify = client.build_verify_contract(
            keypair,
            **common(golden["contract_verify"]["transaction"]),
            contract_address=golden["contract_verify"]["input"]["contract_address"],
            proof=golden["contract_verify"]["input"]["proof"],
        )
        self.assertEqual(
            signed_transaction_hex(verify),
            golden["contract_verify"]["transaction"]["signed_tx_hex"],
        )

        publish_abi = client.build_publish_contract_abi(
            keypair,
            **common(golden["contract_publish_abi"]["transaction"]),
            contract_address=golden["contract_publish_abi"]["input"]["contract_address"],
            abi=golden["contract_publish_abi"]["input"]["abi"],
        )
        self.assertEqual(
            signed_transaction_hex(publish_abi),
            golden["contract_publish_abi"]["transaction"]["signed_tx_hex"],
        )

        route_update = client.build_update_contract_route(
            keypair,
            **common(golden["contract_route_update"]["transaction"]),
            route_name=golden["contract_route_update"]["input"]["route_name"],
            target_contract_address=golden["contract_route_update"]["input"]["target_contract_address"],
        )
        self.assertEqual(
            signed_transaction_hex(route_update),
            golden["contract_route_update"]["transaction"]["signed_tx_hex"],
        )

        route_call = client.build_call_contract_route(
            keypair,
            **common(golden["contract_route_call"]["transaction"]),
            deployer=golden["contract_route_call"]["input"]["deployer"],
            route_name=golden["contract_route_call"]["input"]["route_name"],
            function_name=golden["contract_route_call"]["input"]["function"],
            args=bytes.fromhex(golden["contract_route_call"]["input"]["args_hex"]),
            gas_limit=golden["contract_route_call"]["input"]["gas_limit"],
            amount_micro_zin=golden["contract_route_call"]["input"]["amount_micro_zin"],
        )
        self.assertEqual(
            signed_transaction_hex(route_call),
            golden["contract_route_call"]["transaction"]["signed_tx_hex"],
        )

        deactivate = client.build_deactivate_contract(
            keypair,
            **common(golden["contract_deactivate"]["transaction"]),
            contract_address=golden["contract_deactivate"]["input"]["contract_address"],
        )
        self.assertEqual(
            signed_transaction_hex(deactivate),
            golden["contract_deactivate"]["transaction"]["signed_tx_hex"],
        )

    def test_staking_validator_encoders_match_rust_golden(self):
        path = _python_fixture_path("golden-staking-validator.json")
        golden = json.loads(path.read_text())

        validator_register = encode_validator_register_data(
            executor_services=golden["validator_register"]["input"]["executor_services"],
            vrf_public_key=golden["validator_register"]["input"]["vrf_public_key"],
        )
        self.assertEqual(validator_register.hex(), golden["validator_register"]["data_hex"])

        validator_update = encode_validator_update_data(
            executor_services=golden["validator_update"]["input"]["executor_services"],
            vrf_public_key=golden["validator_update"]["input"]["vrf_public_key"],
        )
        self.assertEqual(validator_update.hex(), golden["validator_update"]["data_hex"])

        self.assertEqual(encode_validator_exit_data().hex(), golden["validator_exit"]["data_hex"])

        vrf_commit = encode_validator_vrf_commit_data(
            target_epoch=golden["validator_vrf_commit"]["input"]["target_epoch"],
            commitment=golden["validator_vrf_commit"]["input"]["commitment"],
        )
        self.assertEqual(vrf_commit.hex(), golden["validator_vrf_commit"]["data_hex"])

        vrf_contribution = encode_validator_vrf_contribution_data(
            target_epoch=golden["validator_vrf_contribution"]["input"]["target_epoch"],
            vrf_output=bytes.fromhex(golden["validator_vrf_contribution"]["input"]["vrf_output_hex"]),
            vrf_proof=bytes.fromhex(golden["validator_vrf_contribution"]["input"]["vrf_proof_hex"]),
        )
        self.assertEqual(vrf_contribution.hex(), golden["validator_vrf_contribution"]["data_hex"])

        self.assertEqual(
            encode_stake_data(target=golden["stake_agent"]["input"]["target"]).hex(),
            golden["stake_agent"]["data_hex"],
        )
        self.assertEqual(
            encode_stake_data(target=golden["stake_validator"]["input"]["target"]).hex(),
            golden["stake_validator"]["data_hex"],
        )
        self.assertEqual(
            encode_stake_data(target=golden["stake_requester_auto_match"]["input"]["target"]).hex(),
            golden["stake_requester_auto_match"]["data_hex"],
        )
        self.assertEqual(
            encode_unstake_data(target=golden["unstake_agent"]["input"]["target"]).hex(),
            golden["unstake_agent"]["data_hex"],
        )
        self.assertEqual(
            encode_unstake_data(target=golden["unstake_validator"]["input"]["target"]).hex(),
            golden["unstake_validator"]["data_hex"],
        )

    def test_staking_validator_builders_produce_rust_compatible_signed_transactions(self):
        path = _python_fixture_path("golden-staking-validator.json")
        golden = json.loads(path.read_text())
        keypair = Keypair.from_secret_hex(golden["secret_hex"])

        def transport(method, url, headers, body, timeout):
            raise AssertionError("network should not be used when chain, nonce, and validity are explicit")

        client = ZinchaClient(base_url="http://node.test/", transport=transport)

        def common(transaction):
            return {
                "fee_micro_zin": transaction["fee_micro_zin"],
                "nonce": transaction["nonce"],
                "chain_id": transaction["chain_id"],
                "timestamp_ms": transaction["timestamp"],
                "reference_block_height": transaction["reference_block_height"],
                "reference_block_hash": transaction["reference_block_hash"],
                "max_valid_block_height": transaction["max_valid_block_height"],
            }

        validator_register = client.build_register_validator(
            keypair,
            **common(golden["validator_register"]["transaction"]),
            stake_micro_zin=golden["validator_register"]["input"]["stake_micro_zin"],
            executor_services=golden["validator_register"]["input"]["executor_services"],
            vrf_public_key=golden["validator_register"]["input"]["vrf_public_key"],
        )
        self.assertEqual(
            signed_transaction_hex(validator_register),
            golden["validator_register"]["transaction"]["signed_tx_hex"],
        )

        validator_update = client.build_update_validator(
            keypair,
            **common(golden["validator_update"]["transaction"]),
            executor_services=golden["validator_update"]["input"]["executor_services"],
            vrf_public_key=golden["validator_update"]["input"]["vrf_public_key"],
        )
        self.assertEqual(
            signed_transaction_hex(validator_update),
            golden["validator_update"]["transaction"]["signed_tx_hex"],
        )

        validator_exit = client.build_exit_validator(
            keypair,
            **common(golden["validator_exit"]["transaction"]),
        )
        self.assertEqual(
            signed_transaction_hex(validator_exit),
            golden["validator_exit"]["transaction"]["signed_tx_hex"],
        )

        vrf_commit = client.build_commit_validator_vrf(
            keypair,
            **common(golden["validator_vrf_commit"]["transaction"]),
            target_epoch=golden["validator_vrf_commit"]["input"]["target_epoch"],
            commitment=golden["validator_vrf_commit"]["input"]["commitment"],
        )
        self.assertEqual(
            signed_transaction_hex(vrf_commit),
            golden["validator_vrf_commit"]["transaction"]["signed_tx_hex"],
        )

        vrf_contribution = client.build_contribute_validator_vrf(
            keypair,
            **common(golden["validator_vrf_contribution"]["transaction"]),
            target_epoch=golden["validator_vrf_contribution"]["input"]["target_epoch"],
            vrf_output=bytes.fromhex(golden["validator_vrf_contribution"]["input"]["vrf_output_hex"]),
            vrf_proof=bytes.fromhex(golden["validator_vrf_contribution"]["input"]["vrf_proof_hex"]),
        )
        self.assertEqual(
            signed_transaction_hex(vrf_contribution),
            golden["validator_vrf_contribution"]["transaction"]["signed_tx_hex"],
        )

        stake_agent = client.build_stake(
            keypair,
            **common(golden["stake_agent"]["transaction"]),
            target=golden["stake_agent"]["input"]["target"],
            amount_micro_zin=golden["stake_agent"]["input"]["amount_micro_zin"],
        )
        self.assertEqual(signed_transaction_hex(stake_agent), golden["stake_agent"]["transaction"]["signed_tx_hex"])

        stake_validator = client.build_stake(
            keypair,
            **common(golden["stake_validator"]["transaction"]),
            target=golden["stake_validator"]["input"]["target"],
            amount_micro_zin=golden["stake_validator"]["input"]["amount_micro_zin"],
        )
        self.assertEqual(signed_transaction_hex(stake_validator), golden["stake_validator"]["transaction"]["signed_tx_hex"])

        stake_requester = client.build_stake(
            keypair,
            **common(golden["stake_requester_auto_match"]["transaction"]),
            target=golden["stake_requester_auto_match"]["input"]["target"],
            amount_micro_zin=golden["stake_requester_auto_match"]["input"]["amount_micro_zin"],
        )
        self.assertEqual(
            signed_transaction_hex(stake_requester),
            golden["stake_requester_auto_match"]["transaction"]["signed_tx_hex"],
        )

        unstake_agent = client.build_unstake(
            keypair,
            **common(golden["unstake_agent"]["transaction"]),
            target=golden["unstake_agent"]["input"]["target"],
            amount_micro_zin=golden["unstake_agent"]["input"]["amount_micro_zin"],
        )
        self.assertEqual(signed_transaction_hex(unstake_agent), golden["unstake_agent"]["transaction"]["signed_tx_hex"])

        unstake_validator = client.build_unstake(
            keypair,
            **common(golden["unstake_validator"]["transaction"]),
            target=golden["unstake_validator"]["input"]["target"],
            amount_micro_zin=golden["unstake_validator"]["input"]["amount_micro_zin"],
        )
        self.assertEqual(
            signed_transaction_hex(unstake_validator),
            golden["unstake_validator"]["transaction"]["signed_tx_hex"],
        )

        with self.assertRaises(ValueError):
            client.build_unstake(
                keypair,
                target="requester_auto_match",
                amount_micro_zin=1,
                chain_id="zincha-vega-1",
                nonce=99,
                reference_block_height=42,
                reference_block_hash="11" * 32,
                max_valid_block_height=100,
            )


if __name__ == "__main__":
    unittest.main()
