import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, expect, test } from "bun:test";

import { createWreqSession, signRequest, type WreqSession } from "../src/index";

const persona = {
  deviceId: "0000000000000000001",
  installId: "0000000000000000002",
  f34: "9066089097591521280",
  f35: "13838013542538480364",
  f36: "7678332264662476164",
};
const replay = {
  nowSeconds: 1793934086,
  nonce: 818642162,
  rnd4Hex: "f1fb0209",
  ladonRandom4Hex: "65743635",
  headerHex: "ecc5582d37019c0318",
  trailerHex: "48228a29a79e78e0800000f50d",
  key4Hex: "ffffeff4",
} as const;

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return (server.address() as AddressInfo).port;
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

describe("wreq-js persistent sessions", () => {
  test("keeps cookies and proxy settings while signing default headers", async () => {
    const targetSeen: { path: string; headers: Record<string, string | string[] | undefined> }[] = [];
    const target = createServer((request, response) => {
      targetSeen.push({ path: request.url ?? "", headers: request.headers });
      const headers: Record<string, string> = { "content-type": "text/plain", connection: "close" };
      if (request.url?.startsWith("/start")) headers["set-cookie"] = "flow=abc; Path=/; HttpOnly";
      response.writeHead(200, headers);
      response.end(request.url?.startsWith("/next") ? request.headers.cookie ?? "" : "ok");
    });
    const proxyRequests: string[] = [];
    const proxy = createServer((incoming, outgoing) => {
      if (incoming.headers["proxy-authorization"] !== "Basic dXNlcjpwYXNz") {
        outgoing.writeHead(407, { "proxy-authenticate": "Basic realm=test" });
        outgoing.end();
        return;
      }
      const destination = new URL(incoming.url ?? "");
      proxyRequests.push(destination.pathname);
      const headers: Record<string, string | string[] | undefined> = { ...incoming.headers, host: destination.host, connection: "close" };
      delete headers["proxy-authorization"];
      delete headers["proxy-connection"];
      const forwarded = httpRequest({
        hostname: destination.hostname,
        port: destination.port,
        path: `${destination.pathname}${destination.search}`,
        method: incoming.method,
        headers,
      }, (response) => {
        outgoing.writeHead(response.statusCode ?? 502, { ...response.headers, "x-local-proxy": "hit" });
        response.pipe(outgoing);
      });
      forwarded.on("error", (error) => {
        outgoing.writeHead(502, { "content-type": "text/plain" });
        outgoing.end(error.message);
      });
      incoming.pipe(forwarded);
    });
    const targetPort = await listen(target);
    const proxyPort = await listen(proxy);
    const origin = `http://127.0.0.1:${targetPort}`;
    let session: WreqSession | undefined;
    try {
      const defaultHeaders = { "x-common-params-v2": "aid=1233", "x-default-proof": "present" };
      const url = `${origin}/start?aid=1233`;
      const expected = signRequest({ persona, url, headers: defaultHeaders, bodyBase64: "", ...replay });
      session = await createWreqSession(persona, {
        browser: "chrome_149",
        os: "macos",
        proxy: `http://user:pass@127.0.0.1:${proxyPort}`,
        defaultHeaders,
      });
      const first = await session.fetch(url, { replay });
      expect(first.status).toBe(200);
      expect(first.headers.get("x-local-proxy")).toBe("hit");
      expect(targetSeen[0]?.headers["x-argus"]).toBe(expected.headers["X-Argus"]);
      expect(targetSeen[0]?.headers["x-default-proof"]).toBe("present");
      expect(targetSeen[0]?.headers["proxy-authorization"]).toBeUndefined();

      const second = await session.fetch(`${origin}/next?aid=1233`, { replay });
      expect(second.status).toBe(200);
      expect(await second.text()).toBe("flow=abc");
      expect(session.getCookies(origin).flow).toBe("abc");
      expect(proxyRequests).toEqual(["/start", "/next"]);
      for (const seen of targetSeen) {
        for (const name of ["x-argus", "x-gorgon", "x-khronos", "x-ss-req-ticket", "x-ladon", "x-ss-stub"]) {
          expect(seen.headers[name]).toBeDefined();
        }
      }
      await session.close();
      expect(session.closed).toBe(true);
      await expect(session.fetch(url)).rejects.toThrow();
    } finally {
      if (session && !session.closed) await session.close();
      await close(proxy);
      await close(target);
    }
  });

  test("isolates and clears cookie jars", async () => {
    const first = await createWreqSession(persona);
    const second = await createWreqSession(persona);
    try {
      first.setCookie("flow", "abc", "https://example.com/path");
      expect(first.getCookies("https://example.com/next").flow).toBe("abc");
      expect(first.getAllCookies()).toContainEqual(expect.objectContaining({ name: "flow", value: "abc" }));
      expect(second.getCookies("https://example.com/next")).toEqual({});
      await first.clearCookies();
      expect(first.getCookies("https://example.com/next")).toEqual({});
    } finally {
      await Promise.all([first.close(), second.close()]);
    }
  });
});
