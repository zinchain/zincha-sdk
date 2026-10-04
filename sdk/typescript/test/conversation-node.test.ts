import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:tls";
import test from "node:test";
import { createNodeConversationClient } from "../src/conversation-node.ts";
import type { ConversationProfileV2, ConversationTlsCertificatePin } from "../src/conversation.ts";

function certificatePin(certificate: X509Certificate): ConversationTlsCertificatePin {
  return {
    sha256: createHash("sha256").update(certificate.raw).digest("hex"),
    not_before_ms: Date.parse(certificate.validFrom),
    not_after_ms: Date.parse(certificate.validTo),
  };
}

async function startProfileServer(
  certificate: Buffer,
  privateKey: Buffer,
  currentProfile: () => ConversationProfileV2,
  requests: string[],
): Promise<{ server: ReturnType<typeof createServer>; port: number }> {
  const server = createServer({
    cert: certificate,
    key: privateKey,
    minVersion: "TLSv1.3",
    maxVersion: "TLSv1.3",
    ALPNProtocols: ["http/1.1"],
  }, (socket) => {
    socket.once("data", (data) => {
      requests.push(data.toString("utf8"));
      const body = Buffer.from(JSON.stringify({ success: true, data: currentProfile() }));
      const headers = Buffer.from(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`);
      socket.end(Buffer.concat([headers, body]));
    });
  });
  server.on("tlsClientError", () => undefined);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert(address && typeof address !== "string");
  return { server, port: address.port };
}

function profileFor(port: number, pins: ConversationTlsCertificatePin[]): ConversationProfileV2 {
  return {
    version: 2,
    service_id: "provider/conversations-node-test",
    interfaces: [{ type: "zincha_tls_v1", host: "127.0.0.1", port, certificate_pins: pins }],
    privacy_modes: ["platform_readable"],
    protocol_versions: [1],
  };
}

test("Node pinned transport enforces rotation and verifies before application data", async () => {
  const oldCertificatePem = readFileSync(new URL("../../testdata/conversation-tls-test-cert.pem", import.meta.url));
  const oldPrivateKeyPem = readFileSync(new URL("../../testdata/conversation-tls-test-key.pem", import.meta.url));
  const nextCertificatePem = readFileSync(new URL("../../testdata/conversation-tls-next-test-cert.pem", import.meta.url));
  const nextPrivateKeyPem = readFileSync(new URL("../../testdata/conversation-tls-next-test-key.pem", import.meta.url));
  const oldPin = certificatePin(new X509Certificate(oldCertificatePem));
  const nextPin = certificatePin(new X509Certificate(nextCertificatePem));
  let profile!: ConversationProfileV2;
  const oldRequests: string[] = [];
  const nextRequests: string[] = [];
  const oldServer = await startProfileServer(oldCertificatePem, oldPrivateKeyPem, () => profile, oldRequests);
  const nextServer = await startProfileServer(nextCertificatePem, nextPrivateKeyPem, () => profile, nextRequests);

  const unavailable = createServer();
  await new Promise<void>((resolve, reject) => {
    unavailable.once("error", reject);
    unavailable.listen(0, "127.0.0.1", resolve);
  });
  const unavailableAddress = unavailable.address();
  assert(unavailableAddress && typeof unavailableAddress !== "string");
  await new Promise<void>((resolve) => unavailable.close(() => resolve()));

  try {
    profile = profileFor(oldServer.port, [oldPin]);
    await createNodeConversationClient(profile, { policy: "zincha_tls_only" });

    profile = profileFor(oldServer.port, [oldPin, nextPin]);
    profile.interfaces.unshift({ type: "https", url: `https://127.0.0.1:${unavailableAddress.port}/before-pinned` });
    profile.interfaces.push({ type: "https", url: `https://127.0.0.1:${unavailableAddress.port}/after-pin-failure` });
    await createNodeConversationClient(profile, { policy: "auto", accessToken: "secret" });
    assert.doesNotMatch(oldRequests.at(-1) ?? "", /authorization:/i);

    profile = profileFor(nextServer.port, [oldPin, nextPin]);
    await createNodeConversationClient(profile, { policy: "zincha_tls_only" });

    profile = profileFor(nextServer.port, [nextPin]);
    await createNodeConversationClient(profile, { policy: "zincha_tls_only" });

    const requestsBeforeRemovedPin = oldRequests.length;
    profile = profileFor(oldServer.port, [nextPin]);
    profile.interfaces.push({ type: "https", url: `https://127.0.0.1:${unavailableAddress.port}/after-pin-failure` });
    await assert.rejects(createNodeConversationClient(profile, { policy: "auto" }), /fetch failed|pin mismatch/i);
    assert.equal(oldRequests.length, requestsBeforeRemovedPin, "removed old pin must fail before HTTP application data");
    assert.equal(nextRequests.length, 2, "new certificate must serve overlap and new-only phases");
  } finally {
    await Promise.all([
      new Promise<void>((resolve) => oldServer.server.close(() => resolve())),
      new Promise<void>((resolve) => nextServer.server.close(() => resolve())),
    ]);
  }
});
