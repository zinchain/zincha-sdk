import assert from "node:assert/strict";
import { test } from "node:test";
import {
  Keypair,
  createTransaction,
  hashTransaction,
  hexToBytes,
  parseSignedRequestMessage,
  signTransaction,
  signTransactionWith,
  signedRequestHeaders,
  signedRequestHeadersAsync,
  signedRequestMessage,
  transactionFromJson,
  transactionToJson,
  verifySignedTransactionSignature,
  type SignedTransaction,
  type Transaction,
  type TransactionSigner,
} from "../src/index.ts";

const SECRET = "3a".repeat(32);

function sampleTx(kp: Keypair): Transaction {
  return createTransaction({
    txType: "transfer",
    sender: kp.address(),
    recipient: "zn1" + "ab".repeat(20),
    amount: 1_500_000n,
    fee: 10n,
    nonce: 7n,
    timestampMs: 1_700_000_000_000n,
    referenceBlockHeight: 100n,
    referenceBlockHash: "cd".repeat(32),
    maxValidBlockHeight: 160n,
    chainId: "zincha-vega-1",
  });
}

test("signTransactionWith(Keypair) equals signTransaction", async () => {
  const kp = Keypair.fromSecretHex(SECRET);
  const tx = sampleTx(kp);
  const sync = signTransaction(tx, kp);
  const viaSigner = await signTransactionWith(tx, kp);
  assert.deepEqual(viaSigner, sync);
  assert.equal(verifySignedTransactionSignature(viaSigner), true);
});

test("signTransactionWith routes through an external signTransaction and verifies the result", async () => {
  const kp = Keypair.fromSecretHex(SECRET);
  const tx = sampleTx(kp);
  let seen: Transaction | null = null;
  const wallet: TransactionSigner = {
    address: () => kp.address(),
    publicKeyHex: () => kp.publicKeyHex(),
    sign: async (m) => kp.sign(m),
    signTransaction: async (t) => {
      seen = t;
      // Simulate a wallet that re-parses JSON transport and signs canonically.
      const round = transactionFromJson(transactionToJson(t));
      return signTransaction(round, kp);
    },
  };
  const signed = await signTransactionWith(tx, wallet);
  assert.ok(seen);
  assert.equal(signed.hash, hashTransaction(tx));
  assert.equal(verifySignedTransactionSignature(signed), true);
});

test("signTransactionWith rejects a wallet that substitutes the transaction", async () => {
  const kp = Keypair.fromSecretHex(SECRET);
  const tx = sampleTx(kp);
  const evil: TransactionSigner = {
    address: () => kp.address(),
    publicKeyHex: () => kp.publicKeyHex(),
    sign: (m) => kp.sign(m),
    signTransaction: async (t) => signTransaction({ ...t, amount: t.amount * 10n }, kp),
  };
  await assert.rejects(() => signTransactionWith(tx, evil), /different transaction/);
});

test("signTransactionWith rejects a wallet whose key does not own the sender", async () => {
  const kp = Keypair.fromSecretHex(SECRET);
  const other = Keypair.fromSecretHex("4b".repeat(32));
  const tx = sampleTx(kp);
  const wrongKey: TransactionSigner = {
    address: () => kp.address(),
    publicKeyHex: () => other.publicKeyHex(),
    sign: (m) => other.sign(m),
  };
  await assert.rejects(() => signTransactionWith(tx, wrongKey), /invalid signature/);
});

test("verifySignedTransactionSignature detects tampering", () => {
  const kp = Keypair.fromSecretHex(SECRET);
  const signed = signTransaction(sampleTx(kp), kp);
  const tampered: SignedTransaction = { ...signed, transaction: { ...signed.transaction, fee: 11n } };
  assert.equal(verifySignedTransactionSignature(tampered), false);
  const badSig: SignedTransaction = { ...signed, signature: "00".repeat(64) };
  assert.equal(verifySignedTransactionSignature(badSig), false);
});

test("transaction JSON codec round-trips and validates", () => {
  const kp = Keypair.fromSecretHex(SECRET);
  const tx = { ...sampleTx(kp), data: hexToBytes("0102ff") };
  const json = transactionToJson(tx);
  assert.equal(json.amount, "1500000");
  assert.equal(json.data, "0102ff");
  assert.deepEqual(transactionFromJson(json), tx);
  assert.throws(() => transactionFromJson({ ...json, amount: "-1" }), /decimal string/);
  assert.throws(() => transactionFromJson({ ...json, amount: "18446744073709551616" }), /unsigned 64/);
  assert.throws(() => transactionFromJson({ ...json, chainId: "" }), /chainId/);
});

test("signed-request message parses back and async headers match sync headers", async () => {
  const kp = Keypair.fromSecretHex(SECRET);
  const input = { method: "get", requestTarget: "/v1/tasks/abc?x=1", body: "", nonce: "0".repeat(32), timestampMs: 1_700_000_000_000 };
  const built = signedRequestMessage(kp, input);
  const parsed = parseSignedRequestMessage(built.message);
  assert.ok(parsed);
  assert.equal(parsed.method, "GET");
  assert.equal(parsed.requestTarget, "/v1/tasks/abc?x=1");
  assert.equal(parsed.address, kp.address());
  assert.deepEqual(await signedRequestHeadersAsync(kp, input), signedRequestHeaders(kp, input));
  assert.equal(parseSignedRequestMessage(new Uint8Array(32)), null);
  assert.equal(parseSignedRequestMessage(new TextEncoder().encode("hello")), null);
});
