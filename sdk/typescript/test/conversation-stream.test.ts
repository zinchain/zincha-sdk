import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "node:http";
import { ConversationClient, ConversationAuthorizationRequiredError, ConversationStreamError } from "../src/index.ts";

const encoder = new TextEncoder();
const conversationId = "ab".repeat(32);
const profile = {
  version: 2,
  service_id: "provider/conversations",
  interfaces: [{ type: "https", url: "https://conversations.example" }],
  privacy_modes: ["platform_readable"],
  protocol_versions: [1],
};

function controlledBody() {
  let controller!: ReadableStreamDefaultController<Uint8Array>;
  let cancelled = false;
  const body = new ReadableStream<Uint8Array>({
    start(value) { controller = value; },
    cancel() { cancelled = true; },
  });
  return { body, enqueue: (bytes: Uint8Array) => controller.enqueue(bytes), cancelled: () => cancelled };
}

function eventBytes(text: string) {
  return encoder.encode(`event: message\ndata: ${JSON.stringify({ sequence: 1, payload: { encoding: "plaintext", parts: [{ type: "text", text }] } })}\n\n`);
}

const settleReads = () => new Promise<void>((resolve) => setImmediate(resolve));

test("SSE UTF-8 decoding is isolated from concurrent JSON requests", { timeout: 5_000 }, async () => {
  const stream = controlledBody();
  const client = new ConversationClient({
    baseUrl: "https://conversations.example",
    fetch: async (input) => String(input).includes("/events?")
      ? new Response(stream.body)
      : Response.json({ success: true, data: profile }),
  });
  const events = client.events(conversationId);
  const next = events.next();
  const bytes = eventBytes("café");
  const split = bytes.indexOf(0xc3) + 1;
  stream.enqueue(bytes.slice(0, split));
  await settleReads();
  const result = await client.profile().catch((error: unknown) => error);
  stream.enqueue(bytes.slice(split));
  try {
    const message = await next;
    assert.deepEqual(result, profile);
    assert.deepEqual(message.value?.payload, { encoding: "plaintext", parts: [{ type: "text", text: "café" }] });
  } finally {
    await events.return(undefined);
  }
});

test("concurrent SSE connections retain independent partial UTF-8 characters", { timeout: 5_000 }, async () => {
  const streams = [controlledBody(), controlledBody()];
  let request = 0;
  const client = new ConversationClient({ baseUrl: "https://conversations.example", fetch: async () => new Response(streams[request++].body) });
  const events = [client.events(conversationId), client.events("cd".repeat(32))];
  const pending = events.map((iterator) => iterator.next());
  const bytes = [eventBytes("café"), eventBytes("東京")];
  const splits = [bytes[0].indexOf(0xc3) + 1, bytes[1].indexOf(0xe6) + 1];
  for (let index = 0; index < streams.length; index++) {
    streams[index].enqueue(bytes[index].slice(0, splits[index]));
    await settleReads();
  }
  for (let index = 0; index < streams.length; index++) streams[index].enqueue(bytes[index].slice(splits[index]));
  try {
    const messages = await Promise.all(pending);
    for (const [index, text] of ["café", "東京"].entries()) {
      assert.deepEqual(messages[index].value?.payload, { encoding: "plaintext", parts: [{ type: "text", text }] });
    }
  } finally {
    await Promise.all(events.map((iterator) => iterator.return(undefined)));
  }
});

test("returning from an SSE iterator cancels and unlocks the response", async () => {
  const stream = controlledBody();
  stream.enqueue(eventBytes("hello"));
  const client = new ConversationClient({ baseUrl: "https://conversations.example", fetch: async () => new Response(stream.body) });
  for await (const message of client.events(conversationId)) {
    assert.equal(message.sequence, 1);
    break;
  }
  assert.equal(stream.cancelled(), true);
  assert.equal(stream.body.locked, false);
});

test("SSE authorization events close the response before failing", async () => {
  const stream = controlledBody();
  stream.enqueue(encoder.encode("event: authorization_required\ndata: {}\n\n"));
  const client = new ConversationClient({ baseUrl: "https://conversations.example", fetch: async () => new Response(stream.body) });
  await assert.rejects(client.events(conversationId).next(), ConversationAuthorizationRequiredError);
  assert.equal(stream.cancelled(), true);
  assert.equal(stream.body.locked, false);
});

test("malformed SSE data closes the old connection before retrying", { timeout: 5_000 }, async () => {
  const stream = controlledBody();
  stream.enqueue(encoder.encode("event: message\ndata: not-json\n\n"));
  let requests = 0;
  let closedBeforeRetry = false;
  const client = new ConversationClient({
    baseUrl: "https://conversations.example",
    fetch: async () => {
      if (requests++ === 0) return new Response(stream.body);
      closedBeforeRetry = stream.cancelled() && !stream.body.locked;
      return new Response(null, { status: 401 });
    },
  });
  await assert.rejects(client.events(conversationId).next(), ConversationAuthorizationRequiredError);
  assert.equal(closedBeforeRetry, true);
  assert.equal(requests, 2);
});

test("terminal SSE HTTP errors cancel unread response bodies", async () => {
  for (const status of [401, 403, 404]) {
    const stream = controlledBody();
    const client = new ConversationClient({ baseUrl: "https://conversations.example", fetch: async () => new Response(stream.body, { status }) });
    await assert.rejects(client.events(conversationId).next(), status === 404 ? ConversationStreamError : ConversationAuthorizationRequiredError);
    assert.equal(stream.cancelled(), true);
    assert.equal(stream.body.locked, false);
  }
});

test("oversized profile responses are canceled with and without Content-Length", async () => {
  for (const declared of [true, false]) {
    const stream = controlledBody();
    stream.enqueue(new Uint8Array(8 * 1024 + 1));
    const headers: Record<string, string> = declared ? { "content-length": String(8 * 1024 + 1) } : {};
    const client = new ConversationClient({ baseUrl: "https://conversations.example", fetch: async () => new Response(stream.body, { headers }) });
    await assert.rejects(client.profile(), /bounded limit/);
    assert.equal(stream.cancelled(), true);
    assert.equal(stream.body.locked, false);
  }
});

test("conversation requests and SSE reject redirects without following them", { timeout: 5_000 }, async () => {
  let followed = 0;
  const server = createServer((request, response) => {
    if (request.url === "/unverified") {
      followed++;
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ success: true, data: profile }));
      return;
    }
    response.writeHead(307, { location: "/unverified", "content-type": "application/json" });
    response.end(JSON.stringify({ success: false, error: "redirect refused" }));
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    const address = server.address();
    assert(address && typeof address !== "string");
    const client = new ConversationClient({ baseUrl: `http://127.0.0.1:${address.port}`, accessToken: "test-token" });
    await assert.rejects(client.profile(), /redirect refused/);
    await assert.rejects(client.acknowledge(conversationId, 1), /redirect refused/);
    await assert.rejects(client.events(conversationId).next(), ConversationStreamError);
    assert.equal(followed, 0, "credentials, workflow identifiers and bodies must stay on the verified endpoint");
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
