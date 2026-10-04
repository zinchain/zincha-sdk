import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 as nobleSha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes, randomBytes, sha256Hex } from "./crypto.ts";
import type { TransactionSigner } from "./types.ts";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const DELEGATION_DOMAIN = "zincha-conversation-delegation-v1";
const CHALLENGE_DOMAIN = "zincha-conversation-challenge-v1";
const MESSAGE_DOMAIN = "zincha-conversation-message-v1";
const E2E_CONTENT_DOMAIN = "zincha-conversation-e2e-content-v1";
const E2E_WRAP_DOMAIN = "zincha-conversation-e2e-wrap-v1";
const MAX_CONVERSATION_RESPONSE_BYTES = 64 * 1024 * 1024;
const MAX_SSE_EVENT_BYTES = 256 * 1024;
const MAX_OUTBOX_ERROR_CHARS = 1_024;

export type ConversationSubjectKind = "task" | "agreement" | "tool_job" | "tool_session";
export type ConversationPrivacyMode = "platform_readable" | "end_to_end";
export interface ConversationSubjectRef { network: string; chain_id: string; kind: ConversationSubjectKind; id: string }
export interface ConversationTlsCertificatePin { sha256: string; not_before_ms: number; not_after_ms: number }
export type ConversationInterface =
  | { type: "https"; url: string }
  | { type: "zincha_tls_v1"; host: string; port: number; certificate_pins: ConversationTlsCertificatePin[] };
export interface ConversationProfileV2 { version: 2; service_id: string; interfaces: ConversationInterface[]; privacy_modes: ConversationPrivacyMode[]; protocol_versions: number[] }
export type ConversationTransportPolicy = "auto" | "https_only" | "zincha_tls_only";
export interface ConversationKeyDelegationV1 {
  version: 1; delegation_id: string; participant_address: string; participant_public_key: string;
  subject: ConversationSubjectRef; home_service_id: string; operational_signing_key: string;
  encryption_key: string; capabilities: string[]; not_before_ms: number; expires_at_ms: number;
  nonce: string; signature: string;
}
export interface ConversationChallenge { challenge_id: string; challenge: string; expires_at_ms: number }
export interface ConversationSession { access_token: string; expires_at_ms: number }
export interface Conversation { id: string; tenant_id: string; subject: ConversationSubjectRef; home_service_id: string; privacy_mode: ConversationPrivacyMode; snapshot: unknown; created_at_ms: number; updated_at_ms: number }
export type ConversationMessagePart =
  | { type: "text"; text: string }
  | { type: "data"; value: unknown }
  | { type: "artifact_reference"; artifact_id: string; digest: string; media_type: string; size: number };
export type ConversationMessagePayload =
  | { encoding: "plaintext"; parts: ConversationMessagePart[] }
  | { encoding: "ciphertext"; ciphertext: string };
export interface SubmitConversationMessage {
  message_id: string; client_timestamp_ms: number; reply_to?: string | null; key_epoch?: number | null;
  payload: ConversationMessagePayload; signing_key_id: string; signature: string;
}
export interface ConversationMessage extends SubmitConversationMessage { conversation_id: string; sequence: number; sender: string; accepted_at_ms: number; payload_digest: string }
export interface ConversationPage<T> { items: T[]; next_cursor?: number | null }

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("canonical JSON cannot encode non-finite numbers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).filter((key) => object[key] !== undefined).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`).join(",")}}`;
  }
  throw new Error("value is not JSON-compatible");
}

export function delegationSigningBytes(delegation: ConversationKeyDelegationV1): Uint8Array {
  const capabilities = [...new Set(delegation.capabilities)].sort().join(",");
  return encoder.encode([
    DELEGATION_DOMAIN, delegation.version, delegation.delegation_id, delegation.participant_address,
    delegation.participant_public_key, delegation.subject.network, delegation.subject.chain_id,
    delegation.subject.kind, delegation.subject.id, delegation.home_service_id,
    delegation.operational_signing_key, delegation.encryption_key, capabilities,
    delegation.not_before_ms, delegation.expires_at_ms, delegation.nonce,
  ].join("\n"));
}

export async function createConversationDelegation(input: {
  account: TransactionSigner; operational: TransactionSigner; encryptionPublicKey: Uint8Array;
  subject: ConversationSubjectRef; homeServiceId: string; notBeforeMs: number; expiresAtMs: number;
  capabilities?: string[];
}): Promise<ConversationKeyDelegationV1> {
  validateX25519PublicKey(input.encryptionPublicKey);
  validateConversationSubject(input.subject);
  validateServiceId(input.homeServiceId);
  if (!Number.isSafeInteger(input.notBeforeMs) || !Number.isSafeInteger(input.expiresAtMs) || input.notBeforeMs >= input.expiresAtMs || input.expiresAtMs - input.notBeforeMs > 31 * 24 * 60 * 60 * 1_000) throw new Error("delegation validity must be positive and no longer than 31 days");
  const capabilities = input.capabilities ?? ["read", "write"];
  if (capabilities.length === 0 || new Set(capabilities).size !== capabilities.length || capabilities.some((capability) => capability !== "read" && capability !== "write")) throw new Error("delegation capabilities must be unique read/write values");
  const delegation: ConversationKeyDelegationV1 = {
    version: 1, delegation_id: uuidV4(), participant_address: input.account.address(),
    participant_public_key: input.account.publicKeyHex(), subject: input.subject,
    home_service_id: input.homeServiceId, operational_signing_key: input.operational.publicKeyHex(),
    encryption_key: bytesToHex(input.encryptionPublicKey), capabilities,
    not_before_ms: input.notBeforeMs, expires_at_ms: input.expiresAtMs,
    nonce: bytesToHex(randomBytes(16)), signature: "",
  };
  delegation.signature = bytesToHex(await input.account.sign(delegationSigningBytes(delegation)));
  return delegation;
}

export function challengeSigningBytes(challenge: ConversationChallenge): Uint8Array {
  return encoder.encode(`${CHALLENGE_DOMAIN}\n${challenge.challenge_id}\n${challenge.challenge}`);
}

export function conversationPayloadDigest(payload: ConversationMessagePayload): string {
  return sha256Hex(encoder.encode(canonicalJson(payload)));
}

export function messageSigningBytes(conversationId: string, sender: string, request: SubmitConversationMessage, digest: string): Uint8Array {
  return encoder.encode([
    MESSAGE_DOMAIN, conversationId, request.message_id, sender, request.client_timestamp_ms,
    request.reply_to ?? "", request.key_epoch ?? "", digest, request.signing_key_id,
  ].join("\n"));
}

export async function signConversationMessage(input: {
  operational: TransactionSigner; delegationId: string; conversationId: string;
  sender: string; payload: ConversationMessagePayload; replyTo?: string; keyEpoch?: number;
}): Promise<SubmitConversationMessage> {
  validateConversationId(input.conversationId);
  validateConversationAddress(input.sender);
  validateUuid(input.delegationId, "delegation ID");
  if (input.replyTo !== undefined) validateUuid(input.replyTo, "reply ID");
  if (input.keyEpoch !== undefined) validateEpoch(input.keyEpoch);
  validateConversationMessagePayload(input.payload, input.keyEpoch);
  const request: SubmitConversationMessage = {
    message_id: uuidV4(), client_timestamp_ms: Date.now(), reply_to: input.replyTo ?? null,
    key_epoch: input.keyEpoch ?? null, payload: input.payload, signing_key_id: input.delegationId, signature: "",
  };
  const digest = conversationPayloadDigest(request.payload);
  request.signature = bytesToHex(await input.operational.sign(messageSigningBytes(input.conversationId, input.sender, request, digest)));
  return request;
}

export class ConversationClient {
  readonly baseUrl: string;
  private accessToken?: string;
  private readonly fetchImpl: typeof fetch;
  constructor(options: { baseUrl: string; accessToken?: string; fetch?: typeof fetch }) {
    this.baseUrl = normalizeConversationBaseUrl(options.baseUrl); this.accessToken = options.accessToken;
    this.fetchImpl = options.fetch ?? globalThis.fetch;
    if (!this.fetchImpl) throw new Error("ConversationClient requires fetch");
  }
  static async fromProfile(profile: ConversationProfileV2, options: { policy?: ConversationTransportPolicy; accessToken?: string; fetch?: typeof fetch } = {}): Promise<ConversationClient> {
    validateConversationProfile(profile);
    const policy = options.policy ?? "auto";
    if (policy === "zincha_tls_only") throw new Error("zincha-tls-v1 is unsupported in browser runtimes; use the @zincha/client/conversation-node export");
    const selected = profile.interfaces.find((entry) => entry.type === "https");
    if (!selected) throw new Error("conversation profile has no HTTPS interface supported by this runtime");
    const client = new ConversationClient({ baseUrl: selected.url, fetch: options.fetch });
    const live = await client.profile();
    verifyConversationServiceProfile(profile, live);
    if (options.accessToken !== undefined) client.setAccessToken(options.accessToken);
    return client;
  }
  setAccessToken(token: string): void { this.accessToken = token; }
  profile(): Promise<ConversationProfileV2> { return this.request("GET", "/v1/profile", undefined, false); }
  issueChallenge(participantAddress: string, subject: ConversationSubjectRef): Promise<ConversationChallenge> { validateConversationAddress(participantAddress); validateConversationSubject(subject); return this.request("POST", "/v1/auth/challenges", { participant_address: participantAddress, subject }, false); }
  createSession(challenge: ConversationChallenge, delegation: ConversationKeyDelegationV1, operational: TransactionSigner): Promise<ConversationSession> {
    validateUuid(challenge.challenge_id, "challenge ID");
    if (typeof challenge.challenge !== "string" || challenge.challenge.length === 0 || challenge.challenge.length > 1024) throw new Error("conversation challenge is invalid");
    validateUuid(delegation.delegation_id, "delegation ID"); validateConversationSubject(delegation.subject);
    validateConversationAddress(delegation.participant_address); validateServiceId(delegation.home_service_id);
    if (delegation.operational_signing_key !== operational.publicKeyHex()) throw new Error("operational key does not match delegation");
    return Promise.resolve(operational.sign(challengeSigningBytes(challenge))).then((signature) => this.request("POST", "/v1/auth/sessions", { challenge_id: challenge.challenge_id, delegation, challenge_signature: bytesToHex(signature) }, false));
  }
  resolve(subject: ConversationSubjectRef, providerAddress: string, privacyMode: ConversationPrivacyMode): Promise<Conversation> { validateConversationSubject(subject); validateConversationAddress(providerAddress); return this.request("POST", "/v1/conversations/resolve", { subject, provider_address: providerAddress, privacy_mode: privacyMode }); }
  conversation(id: string): Promise<Conversation> { validateConversationId(id); return this.request("GET", `/v1/conversations/${id}`); }
  submit(id: string, message: SubmitConversationMessage): Promise<ConversationMessage> { validateConversationId(id); return this.request("POST", `/v1/conversations/${id}/messages`, message); }
  messages(id: string, after = 0, limit = 100): Promise<ConversationPage<ConversationMessage>> { validateConversationId(id); if (!Number.isSafeInteger(after) || after < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 500) throw new Error("message page cursor or limit is invalid"); return this.request("GET", `/v1/conversations/${id}/messages?after=${after}&limit=${limit}`); }
  async acknowledge(id: string, throughSequence: number): Promise<void> { validateConversationId(id); if (!Number.isSafeInteger(throughSequence) || throughSequence < 0) throw new Error("acknowledgement sequence is invalid"); await this.request("POST", `/v1/conversations/${id}/acknowledgements`, { through_sequence: throughSequence }, true, true); }
  async revokeDelegation(id: string): Promise<void> { validateUuid(id, "delegation ID"); await this.request("DELETE", `/v1/auth/delegations/${id}`, undefined, true, true); }
  async *events(id: string, after = 0, signal?: AbortSignal): AsyncGenerator<ConversationMessage> {
    validateConversationId(id);
    if (!Number.isSafeInteger(after) || after < 0) throw new Error("message cursor is invalid");
    let cursor = after; let delay = 250;
    while (!signal?.aborted) {
      try {
        const response = await this.fetchImpl(`${this.baseUrl}/v1/conversations/${id}/events?after=${cursor}&limit=100`, { headers: { ...this.headers(), accept: "text/event-stream" }, signal });
        if (response.status === 401 || response.status === 403) throw new ConversationAuthorizationRequiredError(`conversation SSE HTTP ${response.status}`);
        if (!response.ok && response.status !== 408 && response.status !== 429 && response.status < 500) throw new ConversationStreamError(response.status);
        if (!response.ok || !response.body) throw new Error(`conversation SSE HTTP ${response.status}`);
        const reader = response.body.getReader(); let buffer = ""; let resync = false;
        readLoop: for (;;) {
          const { value, done } = await reader.read(); if (done) break;
          if (value.length > MAX_SSE_EVENT_BYTES || buffer.length > MAX_SSE_EVENT_BYTES - value.length) throw new Error("conversation SSE event exceeds 256 KiB");
          buffer = (buffer + decoder.decode(value, { stream: true })).replace(/\r\n/g, "\n");
          if (buffer.length > MAX_SSE_EVENT_BYTES) throw new Error("conversation SSE event exceeds 256 KiB");
          for (;;) {
            const boundary = buffer.indexOf("\n\n"); if (boundary < 0) break;
            const block = buffer.slice(0, boundary); buffer = buffer.slice(boundary + 2);
            const event = parseSse(block);
            if (event.event === "authorization_required") throw new ConversationAuthorizationRequiredError("conversation authorization must be renewed");
            if (event.event === "resync_required") { resync = true; break readLoop; }
            if (event.event === "message" && event.data) {
              const message = JSON.parse(event.data) as ConversationMessage;
              if (message.sequence > cursor) { cursor = message.sequence; yield message; }
            }
          }
        }
        await reader.cancel().catch(() => undefined);
        if (resync) {
          for (;;) {
            const previousCursor = cursor;
            const page = await this.messages(id, cursor, 100);
            for (const message of page.items) if (message.sequence > cursor) { cursor = message.sequence; yield message; }
            if (page.next_cursor === null) break;
            if (cursor <= previousCursor || page.next_cursor !== cursor) throw new Error("conversation message pagination did not advance coherently");
          }
          delay = 250;
          continue;
        }
        throw new Error("conversation SSE connection closed");
      } catch (error) {
        if (signal?.aborted) return;
        if (error instanceof ConversationAuthorizationRequiredError) throw error;
        if (error instanceof ConversationStreamError) throw error;
        await new Promise((resolve) => setTimeout(resolve, delay)); delay = Math.min(delay * 2, 30_000);
      }
    }
  }
  private headers(): Record<string, string> { return this.accessToken ? { authorization: `Bearer ${this.accessToken}` } : {}; }
  private async request<T>(method: string, path: string, body?: unknown, authenticated = true, allowEmpty = false): Promise<T> {
    const headers: Record<string, string> = { accept: "application/json", ...(authenticated ? this.headers() : {}) };
    const encoded = body === undefined ? undefined : JSON.stringify(body); if (encoded !== undefined) headers["content-type"] = "application/json";
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, { method, headers, body: encoded });
    if (allowEmpty && response.ok && response.status === 204) return undefined as T;
    const value = await readJsonBounded(response) as { success?: boolean; data?: T; error?: string };
    if (!response.ok || value.success !== true) throw new Error(value.error ?? `conversation HTTP ${response.status}`);
    return value.data as T;
  }
}

async function readJsonBounded(response: Response): Promise<unknown> {
  const declared = response.headers.get("content-length");
  if (declared !== null && /^\d+$/.test(declared) && Number(declared) > MAX_CONVERSATION_RESPONSE_BYTES) throw new Error("conversation response exceeds 64 MiB");
  if (!response.body) throw new Error("conversation response has no body");
  const reader = response.body.getReader(); const chunks: Uint8Array[] = []; let length = 0;
  for (;;) {
    const { value, done } = await reader.read(); if (done) break;
    if (length > MAX_CONVERSATION_RESPONSE_BYTES - value.length) { await reader.cancel().catch(() => undefined); throw new Error("conversation response exceeds 64 MiB"); }
    length += value.length; chunks.push(value);
  }
  const encoded = new Uint8Array(length); let offset = 0;
  for (const chunk of chunks) { encoded.set(chunk, offset); offset += chunk.length; }
  return JSON.parse(decoder.decode(encoded));
}

export class ConversationAuthorizationRequiredError extends Error {
  constructor(message: string) { super(message); this.name = "ConversationAuthorizationRequiredError"; }
}

export class ConversationStreamError extends Error {
  readonly status: number;
  constructor(status: number) { super(`conversation SSE HTTP ${status}`); this.name = "ConversationStreamError"; this.status = status; }
}

interface E2eWrappedKey { key_id: string; nonce: string; ciphertext: string }
interface E2eEnvelopeV1 { version: 1; epoch: number; ephemeral_public_key: string; content_nonce: string; ciphertext: string; recipients: E2eWrappedKey[] }
export interface E2eRecipient { keyId: string; publicKey: Uint8Array }

export function encryptConversationE2e(conversationId: string, epoch: number, plaintext: ConversationMessagePayload, recipients: E2eRecipient[]): ConversationMessagePayload {
  validateConversationId(conversationId); validateEpoch(epoch);
  validatePlaintextPayload(plaintext);
  if (recipients.length === 0 || recipients.length > 256) throw new Error("E2E encryption requires plaintext and 1-256 recipients");
  const ephemeralSecret = randomBytes(32); const ephemeralPublic = x25519.getPublicKey(ephemeralSecret);
  const contentKey = randomBytes(32); const contentNonce = randomBytes(24);
  const contentAad = encoder.encode(`${E2E_CONTENT_DOMAIN}\n${conversationId}\n${epoch}`);
  const ciphertext = xchacha20poly1305(contentKey, contentNonce, contentAad).encrypt(encoder.encode(canonicalJson(plaintext)));
  const seen = new Set<string>();
  const wrapped = recipients.map((recipient): E2eWrappedKey => {
    validateE2eKeyId(recipient.keyId);
    if (!(recipient.publicKey instanceof Uint8Array) || recipient.publicKey.length !== 32) throw new Error("E2E recipient public key must be 32 bytes");
    if (seen.has(recipient.keyId)) throw new Error("duplicate E2E recipient key ID"); seen.add(recipient.keyId);
    const shared = x25519.getSharedSecret(ephemeralSecret, recipient.publicKey);
    const wrapAad = encoder.encode(`${E2E_WRAP_DOMAIN}\n${conversationId}\n${epoch}\n${recipient.keyId}`);
    const wrapKey = hkdf(nobleSha256, shared, encoder.encode(conversationId), wrapAad, 32);
    const nonce = randomBytes(24); const encryptedKey = xchacha20poly1305(wrapKey, nonce, wrapAad).encrypt(contentKey);
    return { key_id: recipient.keyId, nonce: base64url(nonce), ciphertext: base64url(encryptedKey) };
  });
  const envelope: E2eEnvelopeV1 = { version: 1, epoch, ephemeral_public_key: bytesToHex(ephemeralPublic), content_nonce: base64url(contentNonce), ciphertext: base64url(ciphertext), recipients: wrapped };
  return { encoding: "ciphertext", ciphertext: base64url(encoder.encode(canonicalJson(envelope))) };
}

export function decryptConversationE2e(conversationId: string, epoch: number, payload: ConversationMessagePayload, recipientKeyId: string, recipientSecret: Uint8Array): ConversationMessagePayload {
  validateConversationId(conversationId); validateEpoch(epoch); validateE2eKeyId(recipientKeyId);
  if (payload.encoding !== "ciphertext" || !(recipientSecret instanceof Uint8Array) || recipientSecret.length !== 32) throw new Error("invalid E2E payload or recipient key");
  const envelope = JSON.parse(decoder.decode(fromBase64url(payload.ciphertext))) as E2eEnvelopeV1;
  if (envelope.version !== 1 || envelope.epoch !== epoch) throw new Error("E2E envelope version or epoch mismatch");
  if (!Array.isArray(envelope.recipients) || envelope.recipients.length === 0 || envelope.recipients.length > 256) throw new Error("E2E envelope recipient count is invalid");
  const recipientIds = new Set<string>();
  for (const item of envelope.recipients) { validateE2eKeyId(item.key_id); if (recipientIds.has(item.key_id)) throw new Error("duplicate E2E recipient key ID"); recipientIds.add(item.key_id); }
  const recipient = envelope.recipients.find((item) => item.key_id === recipientKeyId); if (!recipient) throw new Error("recipient not in E2E envelope");
  const shared = x25519.getSharedSecret(recipientSecret, hexToBytes(envelope.ephemeral_public_key, 32));
  const wrapAad = encoder.encode(`${E2E_WRAP_DOMAIN}\n${conversationId}\n${epoch}\n${recipientKeyId}`);
  const wrapKey = hkdf(nobleSha256, shared, encoder.encode(conversationId), wrapAad, 32);
  const contentKey = xchacha20poly1305(wrapKey, fromBase64url(recipient.nonce), wrapAad).decrypt(fromBase64url(recipient.ciphertext));
  const contentAad = encoder.encode(`${E2E_CONTENT_DOMAIN}\n${conversationId}\n${epoch}`);
  const decoded = xchacha20poly1305(contentKey, fromBase64url(envelope.content_nonce), contentAad).decrypt(fromBase64url(envelope.ciphertext));
  const plaintext = JSON.parse(decoder.decode(decoded)) as unknown;
  validatePlaintextPayload(plaintext);
  return plaintext;
}

function validateX25519PublicKey(publicKey: Uint8Array): void {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) throw new Error("encryption public key must be 32 bytes");
  try { x25519.getSharedSecret(new Uint8Array(32).fill(0x42), publicKey); }
  catch { throw new Error("encryption public key is non-contributory"); }
}

function validateConversationMessagePayload(payload: unknown, keyEpoch?: number): asserts payload is ConversationMessagePayload {
  if (isRecord(payload) && payload.encoding === "plaintext") {
    if (keyEpoch !== undefined) throw new Error("plaintext messages cannot include a key epoch");
    validatePlaintextPayload(payload);
    return;
  }
  if (!isRecord(payload) || !hasExactKeys(payload, ["encoding", "ciphertext"]) || payload.encoding !== "ciphertext" || typeof payload.ciphertext !== "string" || payload.ciphertext.length === 0 || payload.ciphertext.length % 4 === 1 || !/^[A-Za-z0-9_-]+$/.test(payload.ciphertext) || keyEpoch === undefined) throw new Error("ciphertext messages require URL-safe ciphertext and a key epoch");
}

function validatePlaintextPayload(payload: unknown): asserts payload is Extract<ConversationMessagePayload, { encoding: "plaintext" }> {
  if (!isRecord(payload) || !hasExactKeys(payload, ["encoding", "parts"]) || payload.encoding !== "plaintext" || !Array.isArray(payload.parts) || payload.parts.length === 0 || payload.parts.length > 256) throw new Error("plaintext messages require 1-256 valid parts");
  for (const part of payload.parts) {
    if (!isRecord(part) || typeof part.type !== "string") throw new Error("conversation message part is invalid");
    if (part.type === "text") {
      if (!hasExactKeys(part, ["type", "text"]) || typeof part.text !== "string") throw new Error("conversation text part is invalid");
    } else if (part.type === "data") {
      if (!hasExactKeys(part, ["type", "value"])) throw new Error("conversation data part is invalid");
    } else if (part.type === "artifact_reference") {
      if (!hasExactKeys(part, ["type", "artifact_id", "digest", "media_type", "size"]) || typeof part.artifact_id !== "string" || typeof part.digest !== "string" || !/^[0-9a-f]{64}$/.test(part.digest) || typeof part.media_type !== "string" || encoder.encode(part.media_type).length === 0 || encoder.encode(part.media_type).length > 255 || /[\u0000-\u001f\u007f-\u009f]/u.test(part.media_type) || !Number.isSafeInteger(part.size) || Number(part.size) < 0) throw new Error("conversation artifact reference is invalid");
      validateUuid(part.artifact_id, "artifact ID");
    } else {
      throw new Error("conversation message part type is invalid");
    }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}

export interface OutboxStore { load(): Promise<QueuedConversationMessage[]>; save(items: QueuedConversationMessage[]): Promise<void> }
export interface QueuedConversationMessage { conversationId: string; request: SubmitConversationMessage; attempts: number; nextAttemptMs: number; lastError?: string }
export class ConversationOutbox {
  private readonly store: OutboxStore;
  private readonly maxEntries: number;
  private readonly maxSerializedBytes: number;
  private tail: Promise<void> = Promise.resolve();
  constructor(store: OutboxStore, options: { maxEntries?: number; maxSerializedBytes?: number } = {}) {
    this.store = store;
    this.maxEntries = options.maxEntries ?? 1_000;
    this.maxSerializedBytes = options.maxSerializedBytes ?? 64 * 1024 * 1024;
    if (!Number.isSafeInteger(this.maxEntries) || this.maxEntries <= 0 || !Number.isSafeInteger(this.maxSerializedBytes) || this.maxSerializedBytes <= 0) throw new Error("outbox limits must be positive safe integers");
  }
  async enqueue(conversationId: string, request: SubmitConversationMessage): Promise<void> {
    return this.exclusive(async () => {
      const items = await this.load(); const existing = items.find((item) => item.request.message_id === request.message_id);
      if (existing) { if (existing.conversationId === conversationId && canonicalJson(existing.request) === canonicalJson(request)) return; throw new Error("outbox message ID conflict"); }
      if (items.length >= this.maxEntries) throw new Error("conversation outbox entry limit reached");
      items.push({ conversationId, request, attempts: 0, nextAttemptMs: Date.now() }); await this.save(items);
    });
  }
  async flush(client: ConversationClient, limit = 100): Promise<number> {
    if (!Number.isSafeInteger(limit) || limit <= 0) throw new Error("outbox flush limit must be a positive safe integer");
    return this.exclusive(async () => {
      const items = await this.load(); let sent = 0; const now = Date.now();
      for (const item of items.filter((value) => value.nextAttemptMs <= now).slice(0, limit)) {
        try { await client.submit(item.conversationId, item.request); items.splice(items.indexOf(item), 1); sent++; }
        catch (error) { item.attempts++; item.nextAttemptMs = now + Math.min(250 * 2 ** Math.min(item.attempts, 8), 60_000); item.lastError = [...String(error)].slice(0, MAX_OUTBOX_ERROR_CHARS).join(""); }
      }
      await this.save(items); return sent;
    });
  }
  private async exclusive<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.tail;
    let release = (): void => undefined;
    this.tail = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    try { return await operation(); } finally { release(); }
  }
  private async load(): Promise<QueuedConversationMessage[]> {
    const items = await this.store.load();
    if (!Array.isArray(items) || items.length > this.maxEntries) throw new Error("conversation outbox entry limit exceeded");
    if (encoder.encode(JSON.stringify(items)).length > this.maxSerializedBytes) throw new Error("conversation outbox byte limit exceeded");
    return items;
  }
  private async save(items: QueuedConversationMessage[]): Promise<void> {
    if (items.length > this.maxEntries) throw new Error("conversation outbox entry limit exceeded");
    if (encoder.encode(JSON.stringify(items)).length > this.maxSerializedBytes) throw new Error("conversation outbox byte limit exceeded");
    await this.store.save(items);
  }
}
export class LocalStorageOutboxStore implements OutboxStore {
  private readonly storage: Storage;
  private readonly key: string;
  constructor(storage: Storage, key = "zincha-conversation-outbox-v1") { this.storage = storage; this.key = key; }
  async load(): Promise<QueuedConversationMessage[]> { const raw = this.storage.getItem(this.key); return raw ? JSON.parse(raw) as QueuedConversationMessage[] : []; }
  async save(items: QueuedConversationMessage[]): Promise<void> { this.storage.setItem(this.key, JSON.stringify(items)); }
}

export function validateConversationProfile(profile: ConversationProfileV2): void {
  validateExactKeys(profile, ["version", "service_id", "interfaces", "privacy_modes", "protocol_versions"], "conversation profile");
  if (profile.version !== 2 || !Array.isArray(profile.protocol_versions) || !profile.protocol_versions.includes(1)) throw new Error("unsupported conversation profile");
  validateServiceId(profile.service_id);
  if (!Array.isArray(profile.privacy_modes) || profile.privacy_modes.length === 0 || new Set(profile.privacy_modes).size !== profile.privacy_modes.length || profile.privacy_modes.some((mode) => mode !== "platform_readable" && mode !== "end_to_end")) throw new Error("conversation profile privacy modes are invalid");
  if (profile.protocol_versions.length > 64 || new Set(profile.protocol_versions).size !== profile.protocol_versions.length || profile.protocol_versions.some((version) => !Number.isSafeInteger(version) || version <= 0)) throw new Error("conversation profile protocol versions are invalid");
  if (!Array.isArray(profile.interfaces) || profile.interfaces.length < 1 || profile.interfaces.length > 4) throw new Error("conversation profile must advertise 1-4 interfaces");
  const endpoints = new Set<string>();
  for (const entry of profile.interfaces) {
    if (!isRecord(entry) || typeof entry.type !== "string") throw new Error("conversation interface is invalid");
    let identity: string;
    if (entry.type === "https") {
      validateExactKeys(entry, ["type", "url"], "HTTPS conversation interface");
      if (typeof entry.url !== "string" || entry.url.length > 2048) throw new Error("HTTPS conversation interface URL exceeds the supported length");
      const normalized = normalizeConversationBaseUrl(String(entry.url));
      if (!normalized.startsWith("https://")) throw new Error("advertised HTTPS interface must use HTTPS");
      identity = `https:${normalized}`;
    } else if (entry.type === "zincha_tls_v1") {
      validateExactKeys(entry, ["type", "host", "port", "certificate_pins"], "zincha-tls-v1 conversation interface");
      if (typeof entry.host !== "string" || !isCanonicalIp(entry.host) || !Number.isSafeInteger(entry.port) || entry.port < 1 || entry.port > 65535) throw new Error("zincha-tls-v1 host or port is invalid");
      if (!Array.isArray(entry.certificate_pins) || entry.certificate_pins.length < 1 || entry.certificate_pins.length > 2) throw new Error("zincha-tls-v1 requires one active and at most one next pin");
      const hashes = new Set<string>();
      for (const pin of entry.certificate_pins) {
        validateExactKeys(pin, ["sha256", "not_before_ms", "not_after_ms"], "zincha-tls-v1 certificate pin");
        if (typeof pin.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(pin.sha256) || !Number.isSafeInteger(pin.not_before_ms) || !Number.isSafeInteger(pin.not_after_ms) || pin.not_before_ms >= pin.not_after_ms || hashes.has(pin.sha256)) throw new Error("zincha-tls-v1 certificate pin is invalid or duplicated");
        hashes.add(pin.sha256);
      }
      identity = `zincha_tls_v1:${entry.host}:${entry.port}`;
    } else {
      throw new Error("conversation interface type is unsupported");
    }
    if (endpoints.has(identity)) throw new Error("conversation profile interfaces must be unique");
    endpoints.add(identity);
  }
  if (encoder.encode(canonicalJson(profile)).length > 4096) throw new Error("conversation profile exceeds agent metadata limit");
}

export function validateConversationSubject(subject: ConversationSubjectRef): void {
  validateExactKeys(subject, ["network", "chain_id", "kind", "id"], "conversation subject");
  if (!subject || typeof subject.network !== "string" || subject.network.trim().length === 0 || subject.network.length > 64 || /[\u0000-\u001f\u007f]/.test(subject.network) || typeof subject.chain_id !== "string" || subject.chain_id.trim().length === 0 || subject.chain_id.length > 128 || /[\u0000-\u001f\u007f]/.test(subject.chain_id) || !["task", "agreement", "tool_job", "tool_session"].includes(subject.kind)) throw new Error("conversation subject is invalid");
  validateConversationId(subject.id);
}

function validateExactKeys(value: unknown, allowed: readonly string[], label: string): void {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is invalid`);
  const permitted = new Set(allowed);
  if (Object.keys(value).some((key) => !permitted.has(key))) throw new Error(`${label} contains unknown fields`);
  if (Object.keys(value).length !== allowed.length || allowed.some((key) => !Object.prototype.hasOwnProperty.call(value, key))) throw new Error(`${label} is missing required fields`);
}

function validateServiceId(value: string): void {
  if (typeof value !== "string" || value.trim().length === 0 || value.length > 256 || /[\u0000-\u001f\u007f]/.test(value)) throw new Error("conversation profile service ID is invalid");
}

function validateConversationId(value: string): void {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new Error("conversation identifier must be 32 bytes of lowercase hexadecimal");
}

function validateConversationAddress(value: string): void {
  if (!/^zn1[0-9a-f]{40}$/.test(value)) throw new Error("conversation address is invalid");
}
function validateUuid(value: string, label: string): void {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) throw new Error(`${label} is invalid`);
}
function validateEpoch(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("conversation key epoch is invalid");
}
function validateE2eKeyId(value: string): void {
  if (typeof value !== "string" || value.length === 0 || value.length > 256 || /[\u0000-\u001f\u007f]/.test(value)) throw new Error("E2E recipient key ID is invalid");
}
export function encodeConversationProfile(profile: ConversationProfileV2): Uint8Array { validateConversationProfile(profile); const bytes = encoder.encode(canonicalJson(profile)); if (bytes.length > 4096) throw new Error("conversation profile exceeds agent metadata limit"); return bytes; }
export function decodeConversationProfile(metadata: Uint8Array): ConversationProfileV2 { if (metadata.length > 4096) throw new Error("conversation profile exceeds agent metadata limit"); const profile = JSON.parse(decoder.decode(metadata)) as ConversationProfileV2; validateConversationProfile(profile); return profile; }
export function verifyConversationServiceProfile(advertised: ConversationProfileV2, live: ConversationProfileV2): void { validateConversationProfile(advertised); validateConversationProfile(live); if (canonicalJson(advertised) !== canonicalJson(live)) throw new Error("live conversation profile does not match authenticated agent metadata"); }

function isCanonicalIp(value: string): boolean {
  const parts = value.split(".");
  if (parts.length === 4) return parts.every((part) => /^(0|[1-9][0-9]{0,2})$/.test(part) && Number(part) <= 255);
  if (!value.includes(":") || value.includes("%") || value !== value.toLowerCase()) return false;
  try {
    const normalized = new URL(`https://[${value}]/`).hostname;
    return normalized.slice(1, -1) === value;
  } catch {
    return false;
  }
}

function normalizeConversationBaseUrl(value: string): string {
  let url: URL;
  try { url = new URL(value); } catch { throw new Error("conversation service URL is invalid"); }
  const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if ((url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) || url.username !== "" || url.password !== "") throw new Error("conversation service URL must use HTTPS, except for loopback development");
  if (url.search !== "" || url.hash !== "") throw new Error("conversation service URL cannot contain a query or fragment");
  return url.toString().replace(/\/+$/, "");
}

function uuidV4(): string { const bytes = randomBytes(16); bytes[6] = (bytes[6] & 0x0f) | 0x40; bytes[8] = (bytes[8] & 0x3f) | 0x80; const hex = bytesToHex(bytes); return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`; }
function base64url(bytes: Uint8Array): string { let binary = ""; for (const byte of bytes) binary += String.fromCharCode(byte); return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function fromBase64url(value: string): Uint8Array { if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) throw new Error("invalid URL-safe base64"); const normalized = value.replace(/-/g, "+").replace(/_/g, "/"); const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4)); return Uint8Array.from(binary, (char) => char.charCodeAt(0)); }
function parseSse(block: string): { event?: string; data?: string } { const result: { event?: string; data?: string } = {}; for (const line of block.replace(/\r/g, "").split("\n")) { const index = line.indexOf(":"); const name = index < 0 ? line : line.slice(0, index); const value = index < 0 ? "" : line.slice(index + 1).replace(/^ /, ""); if (name === "event") result.event = value; if (name === "data") result.data = result.data === undefined ? value : `${result.data}\n${value}`; } return result; }
