import assert from "node:assert/strict";
import test from "node:test";
import { x25519 } from "@noble/curves/ed25519";
import { readFileSync } from "node:fs";
import {
  ConversationOutbox,
  ConversationClient,
  Keypair,
  createConversationDelegation,
  decryptConversationE2e,
  encryptConversationE2e,
  type OutboxStore,
  type QueuedConversationMessage,
  signConversationMessage,
  conversationPayloadDigest,
  delegationSigningBytes,
  messageSigningBytes,
  bytesToHex,
  decodeConversationProfile,
  encodeConversationProfile,
  hexToBytes,
  verifyConversationServiceProfile,
  type ConversationProfileV1,
} from "../src/index.ts";

test("conversation delegation and message use account and operational identities", async () => {
  const account = Keypair.fromSecretBytes(new Uint8Array(32).fill(7));
  const operational = Keypair.fromSecretBytes(new Uint8Array(32).fill(9));
  const encryptionSecret = new Uint8Array(32).fill(11);
  const subject = { network: "testnet", chain_id: "zincha-test", kind: "task" as const, id: "ab".repeat(32) };
  const delegation = await createConversationDelegation({
    account,
    operational,
    encryptionPublicKey: x25519.getPublicKey(encryptionSecret),
    subject,
    homeServiceId: "marketplace.example/conversations",
    notBeforeMs: 1,
    expiresAtMs: 2,
  });
  assert.equal(delegation.participant_address, account.address());
  assert.equal(delegation.operational_signing_key, operational.publicKeyHex());
  await assert.rejects(createConversationDelegation({
    account,
    operational,
    encryptionPublicKey: new Uint8Array(32),
    subject,
    homeServiceId: "marketplace.example/conversations",
    notBeforeMs: 1,
    expiresAtMs: 2,
  }), /non-contributory/);
  const message = await signConversationMessage({
    operational,
    delegationId: delegation.delegation_id,
    conversationId: "cd".repeat(32),
    sender: account.address(),
    payload: { encoding: "plaintext", parts: [{ type: "text", text: "hello" }] },
  });
  assert.equal(message.signature.length, 128);
  await assert.rejects(signConversationMessage({
    operational,
    delegationId: delegation.delegation_id,
    conversationId: "cd".repeat(32),
    sender: account.address(),
    payload: { encoding: "plaintext", parts: [{ type: "text", text: "hello" }] },
    keyEpoch: 1,
  }), /cannot include a key epoch/);
  await assert.rejects(signConversationMessage({
    operational,
    delegationId: delegation.delegation_id,
    conversationId: "cd".repeat(32),
    sender: account.address(),
    payload: { encoding: "plaintext", parts: [{ type: "artifact_reference", artifact_id: "bad", digest: "00".repeat(32), media_type: "text/plain", size: 1 }] },
  }), /artifact ID/);
});

test("conversation E2E envelope binds conversation and epoch", () => {
  const secret = new Uint8Array(32).fill(19);
  const plaintext = { encoding: "plaintext" as const, parts: [{ type: "text" as const, text: "hello" }] };
  const encrypted = encryptConversationE2e("cd".repeat(32), 7, plaintext, [
    { keyId: "recipient", publicKey: x25519.getPublicKey(secret) },
  ]);
  assert.throws(() => encryptConversationE2e("cd".repeat(32), 7, { encoding: "plaintext", parts: [] }, [{ keyId: "recipient", publicKey: x25519.getPublicKey(secret) }]), /1-256/);
  assert.deepEqual(decryptConversationE2e("cd".repeat(32), 7, encrypted, "recipient", secret), plaintext);
  assert.throws(() => decryptConversationE2e("ef".repeat(32), 7, encrypted, "recipient", secret));
  assert.throws(() => decryptConversationE2e("cd".repeat(32), 8, encrypted, "recipient", secret), /epoch/);
  assert.throws(() => decryptConversationE2e("cd".repeat(32), 7, encrypted, "missing-recipient", secret), /recipient/);
  if (encrypted.encoding !== "ciphertext") throw new Error("E2E encryption must produce ciphertext");
  const last = encrypted.ciphertext.at(-1);
  const tampered = { ...encrypted, ciphertext: `${encrypted.ciphertext.slice(0, -1)}${last === "A" ? "B" : "A"}` };
  assert.throws(() => decryptConversationE2e("cd".repeat(32), 7, tampered, "recipient", secret));
  const nonContributoryEnvelope = JSON.parse(Buffer.from(encrypted.ciphertext, "base64url").toString("utf8")) as Record<string, unknown>;
  nonContributoryEnvelope.ephemeral_public_key = "00".repeat(32);
  const nonContributoryEphemeral = { ...encrypted, ciphertext: Buffer.from(JSON.stringify(nonContributoryEnvelope)).toString("base64url") };
  assert.throws(() => decryptConversationE2e("cd".repeat(32), 7, nonContributoryEphemeral, "recipient", secret), /key/);
  assert.throws(() => encryptConversationE2e("cd".repeat(32), 7, plaintext, [{ keyId: "non-contributory", publicKey: new Uint8Array(32) }]), /key/);
  assert.throws(() => encryptConversationE2e("cd".repeat(32), Number.MAX_SAFE_INTEGER + 1, plaintext, [{ keyId: "recipient", publicKey: x25519.getPublicKey(secret) }]), /epoch/);
});

test("conversation outbox preserves failures for retry", async () => {
  class Store implements OutboxStore {
    items: QueuedConversationMessage[] = [];
    async load(): Promise<QueuedConversationMessage[]> { return structuredClone(this.items); }
    async save(items: QueuedConversationMessage[]): Promise<void> { this.items = structuredClone(items); }
  }
  const store = new Store();
  const outbox = new ConversationOutbox(store);
  const request = {
    message_id: "11111111-1111-4111-8111-111111111111",
    client_timestamp_ms: 1,
    reply_to: null,
    key_epoch: null,
    payload: { encoding: "plaintext" as const, parts: [{ type: "text" as const, text: "hello" }] },
    signing_key_id: "22222222-2222-4222-8222-222222222222",
    signature: "00".repeat(64),
  };
  await outbox.enqueue("conversation", request);
  await outbox.enqueue("conversation", request);
  assert.equal(store.items.length, 1);
  const sent = await outbox.flush({ submit: async () => { throw new Error("offline"); } } as never);
  assert.equal(sent, 0);
  assert.equal(store.items[0].attempts, 1);
});

test("conversation outbox serializes mutations and enforces bounds", async () => {
  class Store implements OutboxStore {
    items: QueuedConversationMessage[] = [];
    async load(): Promise<QueuedConversationMessage[]> { return structuredClone(this.items); }
    async save(items: QueuedConversationMessage[]): Promise<void> { this.items = structuredClone(items); }
  }
  const store = new Store();
  const outbox = new ConversationOutbox(store, { maxEntries: 1, maxSerializedBytes: 16_384 });
  const request = {
    message_id: "11111111-1111-4111-8111-111111111111", client_timestamp_ms: 1,
    reply_to: null, key_epoch: null,
    payload: { encoding: "plaintext" as const, parts: [{ type: "text" as const, text: "hello" }] },
    signing_key_id: "22222222-2222-4222-8222-222222222222", signature: "00".repeat(64),
  };
  await Promise.all([outbox.enqueue("conversation", request), outbox.enqueue("conversation", request)]);
  assert.equal(store.items.length, 1);
  await assert.rejects(outbox.enqueue("conversation", { ...request, message_id: "33333333-3333-4333-8333-333333333333" }), /entry limit/);
});

test("conversation profiles and client URLs are strictly validated", () => {
  const profile: ConversationProfileV1 = {
    version: 1,
    service_id: "marketplace.example/conversations",
    discovery_url: "https://conversations.example/v1",
    privacy_modes: ["platform_readable", "end_to_end"],
    protocol_versions: [1],
    service_signing_public_key: "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
  };
  assert.deepEqual(decodeConversationProfile(encodeConversationProfile(profile)), profile);
  assert.doesNotThrow(() => verifyConversationServiceProfile(profile, profile));
  assert.throws(() => encodeConversationProfile({ ...profile, discovery_url: "http://conversations.example" }), /HTTPS/);
  assert.throws(() => encodeConversationProfile({ ...profile, discovery_url: "https://user:secret@conversations.example" }), /HTTPS/);
  assert.throws(() => encodeConversationProfile({ ...profile, unexpected: true } as never), /unknown fields/);
  const client = new ConversationClient({ baseUrl: "http://127.0.0.1:8080/base", fetch: (() => undefined) as never });
  assert.throws(() => client.conversation("../profile"), /identifier/);
  assert.throws(() => new ConversationClient({ baseUrl: "http://conversations.example", fetch: (() => undefined) as never }), /HTTPS/);
  assert.throws(() => decodeConversationProfile(new Uint8Array(4_097)), /metadata limit/);
});

test("conversation client validates session identifiers and operational binding", async () => {
  const account = Keypair.fromSecretBytes(new Uint8Array(32).fill(7));
  const operational = Keypair.fromSecretBytes(new Uint8Array(32).fill(9));
  const subject = { network: "testnet", chain_id: "zincha-test", kind: "task" as const, id: "ab".repeat(32) };
  const delegation = await createConversationDelegation({
    account, operational, encryptionPublicKey: x25519.getPublicKey(new Uint8Array(32).fill(11)),
    subject, homeServiceId: "marketplace.example/conversations", notBeforeMs: 1, expiresAtMs: 2,
  });
  const fetchImpl = async (): Promise<Response> => new Response(JSON.stringify({ success: true, data: { access_token: "token", expires_at_ms: 2 } }), { status: 201, headers: { "content-type": "application/json" } });
  const client = new ConversationClient({ baseUrl: "http://127.0.0.1:8080", fetch: fetchImpl as typeof fetch });
  const session = await client.createSession({ challenge_id: "11111111-1111-4111-8111-111111111111", challenge: "challenge", expires_at_ms: 2 }, delegation, operational);
  assert.equal(session.access_token, "token");
  assert.throws(
    () => client.createSession({ challenge_id: "invalid", challenge: "challenge", expires_at_ms: 2 }, delegation, operational),
    /challenge ID/,
  );
  await assert.rejects(client.revokeDelegation("../sessions"), /delegation ID/);

  const oversized = new ConversationClient({
    baseUrl: "http://127.0.0.1:8080",
    fetch: (async () => new Response("{}", { headers: { "content-length": String(65 * 1024 * 1024) } })) as typeof fetch,
  });
  await assert.rejects(oversized.profile(), /64 MiB/);
});

test("conversation protocol bytes match cross-language golden", () => {
  const golden = JSON.parse(readFileSync(new URL("../../testdata/golden-conversation-v1.json", import.meta.url), "utf8"));
  assert.equal(bytesToHex(delegationSigningBytes(golden.delegation)), golden.delegation_signing_hex);
  const digest = conversationPayloadDigest(golden.payload);
  assert.equal(digest, golden.payload_digest);
  assert.equal(bytesToHex(messageSigningBytes(golden.conversation_id, golden.sender, golden.message, digest)), golden.message_signing_hex);
});

test("conversation E2E envelope decrypts the cross-language golden", () => {
  const golden = JSON.parse(readFileSync(new URL("../../testdata/golden-conversation-e2e-v1.json", import.meta.url), "utf8"));
  assert.deepEqual(
    decryptConversationE2e(
      golden.conversation_id,
      golden.epoch,
      golden.payload,
      golden.recipient_key_id,
      hexToBytes(golden.recipient_secret_hex),
    ),
    golden.plaintext,
  );
});
