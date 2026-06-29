import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign as nodeSign,
  verify as nodeVerify,
  type KeyObject,
} from "node:crypto";
import type { AddressString, Hex, SignedRequestSigner } from "./types.ts";

export const ADDRESS_PREFIX = "zn1";
const ED25519_PKCS8_SEED_PREFIX = "302e020100300506032b657004220420";
const ED25519_SPKI_PREFIX = "302a300506032b6570032100";

export function stripHexPrefix(hex: string): string {
  return hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
}

export function bytesToHex(bytes: Uint8Array): Hex {
  return Buffer.from(bytes).toString("hex");
}

export function hexToBytes(hex: string, expectedLength?: number): Uint8Array {
  const normalized = stripHexPrefix(hex).trim();
  if (normalized.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(normalized)) {
    throw new Error("invalid hex string");
  }
  const bytes = Uint8Array.from(Buffer.from(normalized, "hex"));
  if (expectedLength !== undefined && bytes.length !== expectedLength) {
    throw new Error(`expected ${expectedLength} bytes, got ${bytes.length}`);
  }
  return bytes;
}

export function sha256(data: Uint8Array | string): Uint8Array {
  return Uint8Array.from(createHash("sha256").update(data).digest());
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

function privateKeyFromSeed(secret: Uint8Array): KeyObject {
  if (secret.length !== 32) {
    throw new Error(`secret key must be 32 bytes, got ${secret.length}`);
  }
  const der = Buffer.from(`${ED25519_PKCS8_SEED_PREFIX}${bytesToHex(secret)}`, "hex");
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

function publicKeyBytesFromPrivateKey(privateKey: KeyObject): Uint8Array {
  const der = createPublicKey(privateKey).export({ format: "der", type: "spki" }) as Buffer;
  const hex = der.toString("hex");
  if (!hex.startsWith(ED25519_SPKI_PREFIX)) {
    throw new Error("unexpected Ed25519 public key DER encoding");
  }
  return Uint8Array.from(der.subarray(der.length - 32));
}

export class Keypair implements SignedRequestSigner {
  private readonly secret: Uint8Array;
  private readonly privateKey: KeyObject;
  private readonly publicKeyBytes: Uint8Array;
  private readonly addressValue: AddressString;

  private constructor(secret: Uint8Array) {
    this.secret = new Uint8Array(secret);
    this.privateKey = privateKeyFromSeed(secret);
    this.publicKeyBytes = publicKeyBytesFromPrivateKey(this.privateKey);
    this.addressValue = addressFromPublicKey(this.publicKeyBytes);
  }

  static generate(): Keypair {
    return Keypair.fromSecretBytes(randomBytes(32));
  }

  static fromSecretBytes(secret: Uint8Array): Keypair {
    return new Keypair(secret);
  }

  static fromSecretHex(secretHex: string): Keypair {
    return Keypair.fromSecretBytes(hexToBytes(secretHex, 32));
  }

  static generateNodeNative(): { privateKey: KeyObject; publicKey: KeyObject } {
    return generateKeyPairSync("ed25519");
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
    return Uint8Array.from(nodeSign(null, Buffer.from(message), this.privateKey));
  }

  verify(message: Uint8Array, signature: Uint8Array): boolean {
    return nodeVerify(
      null,
      Buffer.from(message),
      createPublicKey(this.privateKey),
      Buffer.from(signature),
    );
  }
}

export interface SignedRequestHeadersInput {
  method: string;
  requestTarget: string;
  body?: Uint8Array | string;
  nonce?: string;
  timestampMs?: number;
}

export function signedRequestHeaders(
  signer: SignedRequestSigner,
  input: SignedRequestHeadersInput,
): Record<string, string> {
  const body = typeof input.body === "string"
    ? new TextEncoder().encode(input.body)
    : input.body ?? new Uint8Array();
  const timestampMs = input.timestampMs ?? Date.now();
  const nonce = input.nonce ?? bytesToHex(randomBytes(16));
  const bodyHash = sha256Hex(body);
  const publicKey = signer.publicKeyHex();
  const message = new TextEncoder().encode(
    [
      "zincha-rpc-signed-request-v1",
      input.method.toUpperCase(),
      input.requestTarget,
      String(timestampMs),
      nonce,
      bodyHash,
      signer.address(),
      publicKey,
    ].join("\n"),
  );
  return {
    "x-zincha-address": signer.address(),
    "x-zincha-public-key": publicKey,
    "x-zincha-signature": bytesToHex(signer.sign(message)),
    "x-zincha-timestamp-ms": String(timestampMs),
    "x-zincha-nonce": nonce,
    "x-zincha-body-sha256": bodyHash,
  };
}
