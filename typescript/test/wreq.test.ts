import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { describe, expect, test } from "bun:test";

import { createWreqClient } from "../src/wreq";

const persona = {
  deviceId: "0000000000000000001",
  installId: "0000000000000000002",
};

describe("wreq-js transport", () => {
  test("sends shared signed headers through wreq-js", async () => {
    const seen: Record<string, string> = {};
    const server = createServer((request, response) => {
      for (const [name, value] of Object.entries(request.headers)) seen[name] = String(value);
      response.writeHead(200, { "content-type": "text/plain", "content-length": "2", connection: "close" });
      response.end("ok");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("missing local server address");
    try {
      const client = createWreqClient(persona, { browser: "chrome_149", os: "macos" });
      const response = await client.fetch(`http://127.0.0.1:${address.port}/signed?aid=1233`, {
        replay: { nowSeconds: 1793934086 },
      });
      expect(response.status).toBe(200);
      expect(await response.text()).toBe("ok");
      for (const name of ["x-argus", "x-gorgon", "x-khronos", "x-ss-req-ticket", "x-ladon", "x-ss-stub"]) {
        expect(seen[name]).toBeDefined();
      }
      expect(seen["x-khronos"]).toBe("1793934086");
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });

  test("sends the exact bodyBase64 bytes and body stub", async () => {
    let body = "";
    const seen: Record<string, string> = {};
    const server = createServer(async (request, response) => {
      const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(Buffer.from(chunk));
      body = Buffer.concat(chunks).toString("utf8");
      for (const [name, value] of Object.entries(request.headers)) seen[name] = String(value);
      response.writeHead(200, { "content-type": "text/plain", connection: "close" });
      response.end(body);
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("missing local server address");
    try {
      const client = createWreqClient(persona);
      const response = await client.fetch(`http://127.0.0.1:${address.port}/signed?aid=1233`, {
        method: "POST",
        headers: { "content-type": "text/plain", "x-request-proof": "present" },
        bodyBase64: Buffer.from("probe").toString("base64"),
        replay: { nowSeconds: 1793934086 },
      });
      expect(response.status).toBe(200);
      expect(await response.text()).toBe("probe");
      expect(body).toBe("probe");
      expect(seen["x-request-proof"]).toBe("present");
      expect(seen["x-ss-stub"]).toBe(createHash("md5").update("probe").digest("hex").toUpperCase());
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });
});
