#!/usr/bin/env python3
"""Opt-in, bounded Vega CLI transfer using disposable keys and faucet funds only."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--evidence-dir", type=Path)
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    if args.timeout < 1 or args.timeout > 300:
        parser.error("timeout must be between 1 and 300 seconds")
    if args.evidence_dir:
        args.evidence_dir.mkdir(parents=True, exist_ok=True)

    def run(label, *command):
        result = subprocess.run(
            [binary, "--json", "--release", "vega", *map(str, command)],
            capture_output=True, text=True, timeout=args.timeout + 35,
        )
        if args.evidence_dir:
            (args.evidence_dir / f"{label}.json").write_text(result.stdout)
            (args.evidence_dir / f"{label}.stderr").write_text(result.stderr)
        if result.returncode:
            raise RuntimeError(f"{label} failed ({result.returncode}): {result.stderr}")
        envelope = json.loads(result.stdout)
        require(envelope.get("ok") is True, f"{label}: unsuccessful envelope")
        return envelope["data"]

    def confirmed(receipt):
        require(receipt.get("status") == "confirmed", "transaction did not confirm")
        require(receipt.get("terminal") is True, "nonterminal receipt")
        require(receipt.get("source") == "canonical_chain", "noncanonical receipt")

    info = run("chain-info", "info")
    require(info["chain_id"] == "zincha-vega-1", "this test only spends Vega faucet funds")
    with tempfile.TemporaryDirectory(prefix="zincha-live-keys-") as directory:
        sender_key = Path(directory) / "sender.hex"
        sender = run("sender", "keygen", "--out", sender_key)["address"]
        recipient = run("recipient", "keygen", "--out", Path(directory) / "recipient.hex")["address"]
        funding = run("faucet", "faucet", "--address", sender, "--amount-micro-zin", "5000000")
        funded = run("funding-receipt", "tx", "wait", funding["tx_hash"], "--timeout-secs", args.timeout, "--poll-interval-ms", "1000")
        confirmed(funded)
        sender_before = run("sender-before", "query", "account", sender)
        recipient_before = run("recipient-before", "query", "account", recipient)
        nonce_before = run("nonce-before", "query", "account-nonce", sender)
        # No reference/TTL overrides: this deliberately checks the normal defaults.
        transfer = run("transfer", "tx", "transfer", "--key-file", sender_key,
                       "--to", recipient, "--amount", "1000", "--submit", "--wait",
                       "--wait-timeout-secs", args.timeout, "--wait-interval-ms", "1000")
        receipt = transfer["wait"]
        confirmed(receipt)
        require(transfer["hash"] == transfer["submission"]["tx_hash"] == receipt["tx_hash"], "transaction hash mismatch")
        require(receipt["sender"] == sender and receipt["recipient"] == recipient, "wrong transaction participants")
        require(receipt["amount"] == 1000 and receipt["nonce"] == nonce_before["next_nonce"], "wrong transaction amount/nonce")
        deadline = time.monotonic() + args.timeout
        while True:
            finalized = run("finalized-tip", "query", "/v1/blocks/headers/latest?finalized_only=true")
            if finalized["block_number"] >= receipt["block_number"]:
                break
            require(time.monotonic() < deadline, "finalized tip did not reach receipt")
            time.sleep(1)
        proof = run("finality-proof", "query", f"/v1/blocks/headers?after_height={receipt['block_number']}&after_hash={receipt['block_hash']}&limit=1&finalized_only=true")
        require(proof["snapshot_finalized_floor"] >= receipt["block_number"], "receipt anchor is not finalized")
        sender_after = run("sender-after", "query", "account", sender)
        recipient_after = run("recipient-after", "query", "account", recipient)
        nonce_after = run("nonce-after", "query", "account-nonce", sender)
        require(nonce_after["next_nonce"] == nonce_before["next_nonce"] + 1, "nonce did not advance exactly once")
        require(recipient_after["balance_micro_zin"] - recipient_before["balance_micro_zin"] == 1000, "recipient balance mismatch")
        require(sender_before["balance_micro_zin"] - sender_after["balance_micro_zin"] == 1000 + receipt["fee_charged"], "sender balance/fee mismatch")
        print(f"Vega CLI transfer PASS: {receipt['tx_hash']} finalized at {receipt['block_number']}")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


if __name__ == "__main__":
    main()
