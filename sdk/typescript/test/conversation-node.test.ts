import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:tls";
import test from "node:test";
import { createNodeConversationClient } from "../src/conversation-node.ts";
import type { ConversationProfileV2 } from "../src/conversation.ts";

test("Node pinned transport verifies the serving socket before application data", async () => {
  const certificatePem = readFileSync(new URL("../../testdata/conversation-tls-test-cert.pem", import.meta.url));
  const privateKeyPem = readFileSync(new URL("../../testdata/conversation-tls-test-key.pem", import.meta.url));
  const certificate = new X509Certificate(certificatePem);
  let profile: ConversationProfileV2;
  const requests: string[] = [];
  const server = createServer({
    cert: certificatePem,
    key: privateKeyPem,
    minVersion: "TLSv1.3",
    maxVersion: "TLSv1.3",
    ALPNProtocols: ["http/1.1"],
  }, (socket) => {
    socket.once("data", (data) => {
      requests.push(data.toString("utf8"));
      const body = Buffer.from(JSON.stringify({ success: true, data: profile }));
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
  profile = {
    version: 2,
    service_id: "provider/conversations-node-test",
    interfaces: [{
      type: "zincha_tls_v1",
      host: "127.0.0.1",
      port: address.port,
      certificate_pins: [
        {
          sha256: "11".repeat(32),
          not_before_ms: Date.parse(certificate.validFrom),
          not_after_ms: Date.parse(certificate.validTo),
        },
        {
          sha256: createHash("sha256").update(certificate.raw).digest("hex"),
          not_before_ms: Date.parse(certificate.validFrom),
          not_after_ms: Date.parse(certificate.validTo),
        },
      ],
    }],
    privacy_modes: ["platform_readable"],
    protocol_versions: [1],
  };
  try {
    await createNodeConversationClient(profile, { policy: "zincha_tls_only", accessToken: "secret" });
    assert.equal(requests.length, 1);
    assert.doesNotMatch(requests[0], /authorization:/i);

    const wrong: ConversationProfileV2 = structuredClone(profile);
    if (wrong.interfaces[0].type !== "zincha_tls_v1") throw new Error("test profile changed type");
    wrong.interfaces[0].certificate_pins.length = 1;
    await assert.rejects(createNodeConversationClient(wrong, { policy: "auto" }), /fetch failed|pin mismatch/i);
    assert.equal(requests.length, 1, "pin mismatch must fail before HTTP application data");
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
