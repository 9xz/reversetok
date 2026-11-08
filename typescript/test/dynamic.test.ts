import { describe, expect, test } from "bun:test";

import { extractDynamicFields, signRequest } from "../src/index";

const url = "https://example.invalid/path?aid=1233&probe=dynamic";
const bodyBase64 = Buffer.from("probe").toString("base64");

function nativeArgus(): string {
  return signRequest({
    persona: {
      deviceId: "1",
      installId: "2",
      dynSeed: Buffer.alloc(16, 7).toString("base64"),
      dynVersion: 6,
      seedState: 3,
      f26Tail: [
        { algorithm: 229, outputHex: "deadbeef" },
        { algorithm: 547, outputHex: "01020304" },
      ],
    },
    url,
    bodyBase64,
    nowSeconds: 1700000000,
    nonce: 7,
  }).headers["X-Argus"]!;
}

describe("dynamic task extraction", () => {
  test("validates and returns native task entries", () => {
    const fields = extractDynamicFields({ argus: nativeArgus(), url, bodyBase64 });
    expect(fields.dynVersion).toBe(6);
    expect(fields.seedState).toBe(3);
    expect(fields.nonce).toBe(7);
    expect(fields.nowSeconds).toBe(1700000000);
    expect(fields.f26Tail).toEqual([
      { algorithm: 229, outputHex: "deadbeef" },
      { algorithm: 547, outputHex: "01020304" },
    ]);
  });

  test("rejects task state from another query", () => {
    expect(() => extractDynamicFields({
      argus: nativeArgus(),
      url: "https://example.invalid/path?aid=1233&probe=other",
      bodyBase64,
    })).toThrow("does not match");
  });
});
