// Isomorphic Zincha crypto layer.
//
// Runs unchanged in Node, browsers, and the MetaMask Snaps (SES) sandbox: no
// `node:crypto`, no `Buffer`. Ed25519 comes from @noble/curves and SHA-256
// from @noble/hashes — the same audited, pure-JS primitives that
// @metamask/key-tree is built on, so a Snap bundle carries one crypto stack.
//
// The public surface is a strict superset of the previous Node-only module:
// every exported name behaves identically (byte-for-byte compatible with the
// Rust node; verified by the golden vectors in sdk/testdata), plus the async
// `TransactionSigner` helpers that external wallets need.

import { ed25519 } from "@noble/curves/ed25519";
import { sha256 as nobleSha256 } from "@noble/hashes/sha256";
import { randomBytes as nobleRandomBytes } from "@noble/hashes/utils";
import type {
  AddressString,
  Hex,
  SignedRequestSigner,
  TransactionSigner,
} from "./types.ts";

export const ADDRESS_PREFIX = "zn1";

/** Domain tag that prefixes every authenticated-request signature payload. */
export const SIGNED_REQUEST_DOMAIN = "zincha-rpc-signed-request-v1";

export function stripHexPrefix(hex: string): string {
  return hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
}

export function bytesToHex(bytes: Uint8Array): Hex {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

export function hexToBytes(hex: string, expectedLength?: number): Uint8Array {
  const normalized = stripHexPrefix(hex).trim();
  if (normalized.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(normalized)) {
    throw new Error("invalid hex string");
  }
  const bytes = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  if (expectedLength !== undefined && bytes.length !== expectedLength) {
    throw new Error(`expected ${expectedLength} bytes, got ${bytes.length}`);
  }
  return bytes;
}

export function sha256(data: Uint8Array | string): Uint8Array {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return nobleSha256(bytes);
}

export function sha256Hex(data: Uint8Array | string): Hex {
  return bytesToHex(sha256(data));
}

export function normalizeAddress(address: string): AddressString {
  const raw = rawAddressHex(address);
  return `${ADDRESS_PREFIX}${raw}` as AddressString;
}

export function rawAddressHex(address: string): Hex {
  const value = address.trim().toLowerCase();
  const raw = value.startsWith(ADDRESS_PREFIX) ? value.slice(ADDRESS_PREFIX.length) : value;
  if (!/^[0-9a-f]{40}$/.test(raw)) {
    throw new Error(`invalid ZINCHA address: ${address}`);
  }
  return raw;
}

export function addressFromPublicKey(publicKey: Uint8Array): AddressString {
  if (publicKey.length !== 32) {
    throw new Error(`public key must be 32 bytes, got ${publicKey.length}`);
  }
  const digest = sha256(publicKey);
  return `${ADDRESS_PREFIX}${bytesToHex(digest.slice(12, 32))}` as AddressString;
}

/** Cryptographically secure random bytes (WebCrypto-backed on every platform). */
export function randomBytes(length: number): Uint8Array {
  return nobleRandomBytes(length);
}

/**
 * Verify an Ed25519 signature against a raw 32-byte public key. Never throws:
 * malformed inputs simply verify as `false`.
 */
export function verifySignature(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    if (publicKey.length !== 32 || signature.length !== 64) return false;
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

/**
 * Ed25519 keypair, byte-compatible with the Rust node. The 32-byte secret is
 * the Ed25519 seed; the public key and signatures are derived
 * deterministically (RFC 8032), so signatures match every other Zincha SDK.
 *
 * Implements `TransactionSigner`, so it can be used anywhere an external
 * (async) signer such as the MetaMask Snap adapter can.
 */
export class Keypair implements SignedRequestSigner, TransactionSigner {
  private readonly secret: Uint8Array;
  private readonly publicKeyBytes: Uint8Array;
  private readonly addressValue: AddressString;

  private constructor(secret: Uint8Array) {
    if (secret.length !== 32) {
      throw new Error(`secret key must be 32 bytes, got ${secret.length}`);
    }
    this.secret = new Uint8Array(secret);
    this.publicKeyBytes = ed25519.getPublicKey(this.secret);
    this.addressValue = addressFromPublicKey(this.publicKeyBytes);
  }

  static generate(): Keypair {
    return new Keypair(randomBytes(32));
  }

  static fromSecretBytes(secret: Uint8Array): Keypair {
    return new Keypair(secret);
  }

  static fromSecretHex(secretHex: string): Keypair {
    return new Keypair(hexToBytes(secretHex, 32));
  }

  secretBytes(): Uint8Array {
    return new Uint8Array(this.secret);
  }

  secretHex(): Hex {
    return bytesToHex(this.secret);
  }

  publicKey(): Uint8Array {
    return new Uint8Array(this.publicKeyBytes);
  }

  publicKeyHex(): Hex {
    return bytesToHex(this.publicKeyBytes);
  }

  address(): AddressString {
    return this.addressValue;
  }

  sign(message: Uint8Array): Uint8Array {
    return ed25519.sign(message, this.secret);
  }

  verify(message: Uint8Array, signature: Uint8Array): boolean {
    return verifySignature(this.publicKeyBytes, message, signature);
  }
}

export interface SignedRequestHeadersInput {
  method: string;
  requestTarget: string;
  body?: Uint8Array | string;
  nonce?: string;
  timestampMs?: number;
}

export interface SignedRequestMessage {
  /** Exact bytes that must be signed with the account's Ed25519 key. */
  message: Uint8Array;
  method: string;
  requestTarget: string;
  timestampMs: number;
  nonce: string;
  bodyHash: Hex;
  address: AddressString;
  publicKey: Hex;
}

/**
 * Build the canonical `zincha-rpc-signed-request-v1` payload. Exposed so that
 * external wallets can construct, inspect, and display exactly what they are
 * being asked to sign.
 */
export function signedRequestMessage(
  signer: Pick<TransactionSigner, "address" | "publicKeyHex">,
  input: SignedRequestHeadersInput,
): SignedRequestMessage {
  const body = typeof input.body === "string"
    ? new TextEncoder().encode(input.body)
    : input.body ?? new Uint8Array();
  const timestampMs = input.timestampMs ?? Date.now();
  const nonce = input.nonce ?? bytesToHex(randomBytes(16));
  const bodyHash = sha256Hex(body);
  const publicKey = signer.publicKeyHex();
  const address = signer.address();
  const method = input.method.toUpperCase();
  const message = new TextEncoder().encode(
    [
      SIGNED_REQUEST_DOMAIN,
      method,
      input.requestTarget,
      String(timestampMs),
      nonce,
      bodyHash,
      address,
      publicKey,
    ].join("\n"),
  );
  return { message, method, requestTarget: input.requestTarget, timestampMs, nonce, bodyHash, address, publicKey };
}

/**
 * Parse a `zincha-rpc-signed-request-v1` payload back into its fields.
 * Returns `null` for anything that is not a well-formed signed-request
 * message — wallets use this to decide what a signing request really is.
 */
export function parseSignedRequestMessage(
  message: Uint8Array,
): Omit<SignedRequestMessage, "message"> | null {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(message);
  } catch {
    return null;
  }
  const parts = text.split("\n");
  if (parts.length !== 8 || parts[0] !== SIGNED_REQUEST_DOMAIN) return null;
  const [, method, requestTarget, timestamp, nonce, bodyHash, address, publicKey] = parts;
  if (!/^[A-Z]+$/.test(method) || !requestTarget.startsWith("/")) return null;
  if (!/^\d{1,16}$/.test(timestamp)) return null;
  if (!/^[0-9a-f]{64}$/.test(bodyHash) || !/^[0-9a-f]{64}$/.test(publicKey)) return null;
  try {
    normalizeAddress(address);
  } catch {
    return null;
  }
  return {
    method,
    requestTarget,
    timestampMs: Number(timestamp),
    nonce,
    bodyHash,
    address: address as AddressString,
    publicKey,
  };
}

function headersFor(
  built: SignedRequestMessage,
  signature: Uint8Array,
): Record<string, string> {
  return {
    "x-zincha-address": built.address,
    "x-zincha-public-key": built.publicKey,
    "x-zincha-signature": bytesToHex(signature),
    "x-zincha-timestamp-ms": String(built.timestampMs),
    "x-zincha-nonce": built.nonce,
    "x-zincha-body-sha256": built.bodyHash,
  };
}

/** Synchronous variant for in-process signers (`Keypair`). */
export function signedRequestHeaders(
  signer: SignedRequestSigner,
  input: SignedRequestHeadersInput,
): Record<string, string> {
  const built = signedRequestMessage(signer, input);
  return headersFor(built, signer.sign(built.message));
}

/** Async variant that also accepts external wallets (`TransactionSigner`). */
export async function signedRequestHeadersAsync(
  signer: TransactionSigner,
  input: SignedRequestHeadersInput,
): Promise<Record<string, string>> {
  const built = signedRequestMessage(signer, input);
  const signature = await signer.sign(built.message);
  return headersFor(built, signature);
}
