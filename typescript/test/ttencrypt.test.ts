import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";

import { ttDecrypt, ttDecryptGzip, ttEncrypt, ttEncryptGzip } from "../src/index";

interface Vector {
  name: string;
  inputBase64: string;
  keyStreamBase64: string;
  outputBase64: string;
}

const fixtures = JSON.parse(
  readFileSync(join(import.meta.dir, "../../fixtures/vectors.json"), "utf8"),
) as { ttEncrypt: Vector[] };

describe("native TTEncrypt", () => {
  for (const vector of fixtures.ttEncrypt) {
    test(`matches ${vector.name} byte-for-byte`, () => {
      const input = Buffer.from(vector.inputBase64, "base64");
      const keyStream = Buffer.from(vector.keyStreamBase64, "base64");
      const expected = Buffer.from(vector.outputBase64, "base64");
      expect(ttEncrypt(input, keyStream).equals(expected)).toBe(true);
      expect(ttDecrypt(expected).equals(input)).toBe(true);
    });
  }

  test("round-trips gzip payloads with the Java OS header", () => {
    const input = Buffer.from("device registration payload");
    const encrypted = ttEncryptGzip(input, Uint8Array.from([...Array(32).keys()]));
    expect(ttDecrypt(encrypted)[9]).toBe(255);
    expect(ttDecryptGzip(encrypted).equals(input)).toBe(true);
  });

  test("rejects invalid inputs and modified ciphertext", () => {
    expect(() => ttEncrypt(new Uint8Array())).toThrow("empty");
    expect(() => ttEncrypt(Buffer.from("probe"), new Uint8Array(4))).toThrow("32 bytes");
    const modified = ttEncrypt(Buffer.from("probe"), new Uint8Array(32));
    const last = modified.length - 1;
    modified[last] = modified[last]! ^ 1;
    expect(() => ttDecrypt(modified)).toThrow();
  });
});
