import { decryptArgus, dynEncode, MASK32, md5Bytes, ProtoReader } from "./crypto";
import type { DynamicFields, DynamicInput } from "./types";

export function extractDynamicFields(input: DynamicInput): DynamicFields {
  const body =
    input.body !== undefined
      ? typeof input.body === "string"
        ? Buffer.from(input.body, "utf8")
        : Buffer.from(input.body)
      : input.bodyBase64
        ? Buffer.from(input.bodyBase64, "base64")
        : Buffer.alloc(0);
  const parsedUrl = new URL(input.url);
  const query = parsedUrl.search.startsWith("?") ? parsedUrl.search.slice(1) : "";
  const bodyStub = md5Bytes(body);
  const protobuf = decryptArgus(input.argus);
  const reader = new ProtoReader(protobuf);

  let dynSeed: string | undefined;
  let seedState: number | undefined;
  let nonce: number | undefined;
  let nowSeconds: number | undefined;
  const entries: { algorithm: number; output: Buffer }[] = [];

  while (true) {
    const item = reader.nextField();
    if (item === null) break;
    if (item.field === 3 && item.wire === 0) nonce = Number(item.value >> 1n);
    else if (item.field === 12 && item.wire === 0) nowSeconds = Number(item.value >> 1n);
    else if (item.field === 24 && item.wire === 2) dynSeed = item.value.toString("utf8");
    else if (item.field === 25 && item.wire === 0) seedState = Number(item.value >> 1n);
    else if (item.field === 26 && item.wire === 2) {
      const nested = new ProtoReader(item.value);
      let alg: number | undefined;
      let outBuf: Buffer | undefined;
      while (true) {
        const n = nested.nextField();
        if (n === null) break;
        if (n.field === 1 && n.wire === 0) alg = Number(n.value >> 1n);
        else if (n.field === 2 && n.wire === 2) outBuf = n.value;
      }
      if (alg === undefined || outBuf === undefined) {
        throw new Error("dynamic entry is missing its algorithm or output");
      }
      entries.push({ algorithm: alg, output: outBuf });
    }
  }

  if (dynSeed === undefined) throw new Error("Argus has no dynamic seed field");
  if (nonce === undefined || nonce < 0 || nonce > MASK32) throw new Error("Argus has no valid nonce");
  if (nowSeconds === undefined) throw new Error("Argus has no timestamp");
  if (seedState === undefined) throw new Error("Argus has no dynamic seed state");

  let builtinIndex = -1;
  let dynVersion = 0;
  for (let idx = 0; idx < entries.length; idx++) {
    const entry = entries[idx]!;
    if (entry.algorithm >= 1 && entry.algorithm <= 6) {
      const expected = dynEncode(entry.algorithm, Buffer.from(query, "utf8"), bodyStub, nonce);
      if (entry.output.equals(expected)) {
        builtinIndex = idx;
        dynVersion = entry.algorithm;
        break;
      }
    }
  }
  if (builtinIndex === -1) {
    throw new Error("built-in dynamic entry does not match the request");
  }

  return {
    dynSeed,
    dynVersion,
    seedState,
    nonce,
    nowSeconds,
    f26Tail: entries
      .filter((_, idx) => idx !== builtinIndex)
      .map((e) => ({ algorithm: e.algorithm, outputHex: e.output.toString("hex") })),
  };
}
