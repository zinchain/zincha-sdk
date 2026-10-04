import { createHash, timingSafeEqual } from "node:crypto";
import type { TLSSocket } from "node:tls";
import { Agent, buildConnector, fetch as undiciFetch } from "undici";
import {
  ConversationClient,
  type ConversationInterface,
  type ConversationProfileV2,
  type ConversationTlsCertificatePin,
  type ConversationTransportPolicy,
  validateConversationProfile,
  verifyConversationServiceProfile,
} from "./conversation.ts";

const agents = new Map<string, Agent>();
const serviceAgentKeys = new Map<string, string>();
const CLOCK_SKEW_MS = 5 * 60 * 1_000;
const MAX_PINNED_AGENT_POOLS = 256;

export async function createNodeConversationClient(
  profile: ConversationProfileV2,
  options: { policy?: ConversationTransportPolicy; accessToken?: string; connectTimeoutMs?: number } = {},
): Promise<ConversationClient> {
  validateConversationProfile(profile);
  const policy = options.policy ?? "auto";
  const timeout = options.connectTimeoutMs ?? 5_000;
  let supported = false;
  const unreachable: string[] = [];
  for (const entry of profile.interfaces) {
    if ((entry.type === "https" && policy === "zincha_tls_only") || (entry.type === "zincha_tls_v1" && policy === "https_only")) continue;
    supported = true;
    const baseUrl = interfaceUrl(entry);
    const fetchImpl = entry.type === "zincha_tls_v1" ? pinnedFetch(profile.service_id, baseUrl, entry.certificate_pins, timeout) : globalThis.fetch;
    if (!fetchImpl) throw new Error("Node conversation client requires fetch");
    const client = new ConversationClient({ baseUrl, fetch: fetchImpl });
    let live: ConversationProfileV2;
    try {
      live = await client.profile();
    } catch (cause) {
      if (policy === "auto" && isReachabilityError(cause)) {
        unreachable.push(baseUrl);
        continue;
      }
      throw cause;
    }
    // TLS, pin, identity, HTTP, and profile errors are terminal. Auto only
    // advances when the request failed with a recognized network reachability
    // code; it never opens a speculative probe connection.
    verifyConversationServiceProfile(profile, live);
    if (options.accessToken !== undefined) client.setAccessToken(options.accessToken);
    return client;
  }
  if (!supported) throw new Error("conversation profile has no interface supported by the selected transport policy");
  throw new Error(`all supported conversation interfaces were unreachable: ${unreachable.join(", ")}`);
}

function interfaceUrl(entry: ConversationInterface): string {
  if (entry.type === "https") return entry.url;
  const host = entry.host.includes(":") ? `[${entry.host}]` : entry.host;
  return `https://${host}:${entry.port}`;
}

function pinnedFetch(serviceId: string, baseUrl: string, pins: ConversationTlsCertificatePin[], timeoutMs: number): typeof globalThis.fetch {
  const key = `${serviceId}\n${baseUrl}\n${pins.map((pin) => `${pin.sha256}:${pin.not_before_ms}:${pin.not_after_ms}`).join(",")}`;
  const previous = serviceAgentKeys.get(serviceId);
  if (previous !== undefined && previous !== key) {
    const stale = agents.get(previous);
    agents.delete(previous);
    void stale?.close();
  }
  serviceAgentKeys.set(serviceId, key);
  let agent = agents.get(key);
  if (agent) {
    agents.delete(key);
    agents.set(key, agent);
  }
  if (!agent) {
    const connector = buildConnector({ rejectUnauthorized: false, minVersion: "TLSv1.3", maxVersion: "TLSv1.3", ALPNProtocols: ["http/1.1"], timeout: timeoutMs });
    agent = new Agent({
      connect(options, callback) {
        connector(options, (error, socket) => {
          if (error || !socket) { callback(error, socket); return; }
          try {
            verifyPeerCertificate(socket as TLSSocket, pins);
            callback(null, socket);
          } catch (cause) {
            socket.destroy();
            callback(cause instanceof Error ? cause : new Error(String(cause)), null);
          }
        });
      },
      connections: 10_000,
      pipelining: 1,
    });
    agents.set(key, agent);
    while (agents.size > MAX_PINNED_AGENT_POOLS) {
      const oldest = agents.entries().next().value as [string, Agent] | undefined;
      if (!oldest) break;
      agents.delete(oldest[0]);
      for (const [cachedServiceId, cachedKey] of serviceAgentKeys) {
        if (cachedKey === oldest[0]) serviceAgentKeys.delete(cachedServiceId);
      }
      void oldest[1].close();
    }
  }
  const dispatcher = agent;
  return ((input: RequestInfo | URL, init?: RequestInit) =>
    undiciFetch(input as Parameters<typeof undiciFetch>[0], { ...init, dispatcher } as Parameters<typeof undiciFetch>[1]) as unknown as Promise<Response>) as typeof globalThis.fetch;
}

function isReachabilityError(cause: unknown): boolean {
  const reachabilityCodes = new Set([
    "ECONNREFUSED",
    "EHOSTUNREACH",
    "ENETUNREACH",
    "ENOTFOUND",
    "EAI_AGAIN",
    "ETIMEDOUT",
    "UND_ERR_CONNECT_TIMEOUT",
  ]);
  const visited = new Set<unknown>();
  let current = cause;
  while (current !== null && typeof current === "object" && !visited.has(current)) {
    visited.add(current);
    const record = current as { code?: unknown; cause?: unknown };
    if (typeof record.code === "string" && reachabilityCodes.has(record.code)) return true;
    current = record.cause;
  }
  return false;
}

function verifyPeerCertificate(socket: TLSSocket, pins: ConversationTlsCertificatePin[]): void {
  const certificate = socket.getPeerCertificate(true);
  if (!certificate.raw) throw new Error("zincha-tls-v1 peer did not present a certificate");
  const digest = createHash("sha256").update(certificate.raw).digest();
  const pin = pins.find((candidate) => timingSafeEqual(digest, Buffer.from(candidate.sha256, "hex")));
  if (!pin) throw new Error("zincha-tls-v1 certificate pin mismatch");
  const notBeforeMs = Date.parse(certificate.valid_from);
  const notAfterMs = Date.parse(certificate.valid_to);
  if (!Number.isSafeInteger(notBeforeMs) || !Number.isSafeInteger(notAfterMs) || notBeforeMs !== pin.not_before_ms || notAfterMs !== pin.not_after_ms) throw new Error("zincha-tls-v1 certificate validity does not match the on-chain pin");
  const current = Date.now();
  if (current + CLOCK_SKEW_MS < pin.not_before_ms || current - CLOCK_SKEW_MS > pin.not_after_ms) throw new Error("zincha-tls-v1 certificate pin is outside its advertised validity");
}
