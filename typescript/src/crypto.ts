import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

import type { DynTail, Persona, SignInput, SignOutput } from "./types";

export const VERSION = "0.1.0";
const MASK64 = 0xffffffffffffffffn;
export const MASK32 = 0xffffffff;

export const ARGUS_SIGN_KEY = Buffer.from([
  0xc0, 0x2f, 0x25, 0x0f, 0x86, 0xcc, 0x4f, 0x19, 0x8d, 0x57, 0x06, 0x39, 0x8d, 0x29, 0x2a, 0x8b,
  0x74, 0x16, 0x9a, 0xba, 0x61, 0xaf, 0xfe, 0x7c, 0xba, 0x02, 0xe4, 0xa3, 0xb5, 0x19, 0x81, 0x63,
]);
const ARGUS_AES_KEY = Buffer.from([
  0x82, 0x52, 0x97, 0x0d, 0x95, 0x9b, 0x06, 0xdb, 0x10, 0x2e, 0x17, 0xd8, 0x5c, 0x0e, 0xc1, 0xaf,
]);
const ARGUS_AES_IV = Buffer.from([
  0x4d, 0x20, 0x7e, 0xa3, 0x7a, 0x41, 0x9f, 0x7d, 0x62, 0x2f, 0x81, 0xc6, 0xa2, 0xf5, 0x35, 0x94,
]);
const DEFAULT_HEADER = Buffer.from([0xec, 0xc5, 0x58, 0x2d, 0x37, 0x01, 0x9c, 0x03, 0x18]);
const DEFAULT_TRAILER = Buffer.from([0x48, 0x22, 0x8a, 0x29, 0xa7, 0x9e, 0x78, 0xe0, 0x80, 0x00, 0x00, 0xf5, 0x0d]);
const GORGON_PREFIX = Buffer.from([0x84, 0x04, 0xa0, 0x97, 0x00, 0x00]);
const GORGON_KEYSTREAM = Buffer.from([
  0xa7, 0xfd, 0xd6, 0xa3, 0xa4, 0xa7, 0xb6, 0xaf, 0xbb, 0xc5, 0xfd, 0xa4, 0xd7, 0x6e, 0xa4, 0xf0,
  0xdb, 0xf5, 0xf2, 0xf0,
]);
const Z4_BITS = "11010001111001101011011000100000010111000011001010010011101111110100";

const SM3_IV = [
  0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
  0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
];

function rol32(x: number, n: number): number {
  const s = n & 31;
  return s === 0 ? x >>> 0 : (((x << s) | (x >>> (32 - s))) >>> 0);
}

function rol64(x: bigint, n: bigint): bigint {
  const s = n & 63n;
  return s === 0n ? x & MASK64 : (((x << s) | ((x & MASK64) >> (64n - s))) & MASK64);
}

function ror64(x: bigint, n: bigint): bigint {
  const s = n & 63n;
  return s === 0n ? x & MASK64 : ((((x & MASK64) >> s) | (x << (64n - s))) & MASK64);
}

function p0(x: number): number {
  return (x ^ rol32(x, 9) ^ rol32(x, 17)) >>> 0;
}

function p1(x: number): number {
  return (x ^ rol32(x, 15) ^ rol32(x, 23)) >>> 0;
}

export function sm3(data: Uint8Array): Buffer {
  const bitLen = BigInt(data.length) * 8n;
  const rem = (data.length + 1) % 64;
  const zeroPad = rem <= 56 ? 56 - rem : 120 - rem;
  const padded = Buffer.alloc(data.length + 1 + zeroPad + 8);
  padded.set(data, 0);
  padded[data.length] = 0x80;
  padded.writeBigUInt64BE(bitLen, padded.length - 8);

  const state: number[] = [...SM3_IV];
  const w = new Uint32Array(68);
  const w1 = new Uint32Array(64);

  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = padded.readUInt32BE(offset + i * 4);
    }
    for (let j = 16; j < 68; j++) {
      w[j] = (p1((w[j - 16]! ^ w[j - 9]! ^ rol32(w[j - 3]!, 15)) >>> 0) ^ rol32(w[j - 13]!, 7) ^ w[j - 6]!) >>> 0;
    }
    for (let j = 0; j < 64; j++) {
      w1[j] = (w[j]! ^ w[j + 4]!) >>> 0;
    }

    let [a, b, c, d, e, f, g, h] = state as [number, number, number, number, number, number, number, number];
    for (let j = 0; j < 64; j++) {
      const tj = j < 16 ? 0x79cc4519 : 0x7a879d8a;
      const ss1 = rol32((rol32(a, 12) + e + rol32(tj, j)) >>> 0, 7);
      const ss2 = (ss1 ^ rol32(a, 12)) >>> 0;
      const ff = j < 16 ? ((a ^ b ^ c) >>> 0) : (((a & b) | (a & c) | (b & c)) >>> 0);
      const gg = j < 16 ? ((e ^ f ^ g) >>> 0) : (((e & f) | ((~e >>> 0) & g)) >>> 0);
      const tt1 = (ff + d + ss2 + w1[j]!) >>> 0;
      const tt2 = (gg + h + ss1 + w[j]!) >>> 0;
      d = c;
      c = rol32(b, 9);
      b = a;
      a = tt1;
      h = g;
      g = rol32(f, 19);
      f = e;
      e = p0(tt2);
    }
    state[0] = (state[0]! ^ a) >>> 0;
    state[1] = (state[1]! ^ b) >>> 0;
    state[2] = (state[2]! ^ c) >>> 0;
    state[3] = (state[3]! ^ d) >>> 0;
    state[4] = (state[4]! ^ e) >>> 0;
    state[5] = (state[5]! ^ f) >>> 0;
    state[6] = (state[6]! ^ g) >>> 0;
    state[7] = (state[7]! ^ h) >>> 0;
  }

  const out = Buffer.alloc(32);
  for (let i = 0; i < 8; i++) {
    out.writeUInt32BE(state[i]!, i * 4);
  }
  return out;
}

export function md5Bytes(data: Uint8Array | string): Buffer {
  return createHash("md5").update(data).digest();
}

export function md5Hex(data: Uint8Array | string): string {
  return createHash("md5").update(data).digest("hex");
}

function aesCbcEncryptNoPad(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Buffer {
  const cipher = createCipheriv("aes-128-cbc", key, iv);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

function aesCbcDecryptNoPad(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Buffer {
  const decipher = createDecipheriv("aes-128-cbc", key, iv);
  decipher.setAutoPadding(false);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

function aesOfbLast4(data: Uint8Array, keyAscii: Buffer): number {
  const key = keyAscii.subarray(0, 16);
  let state: Buffer = Buffer.from(keyAscii.subarray(16, 32));
  const pad = 16 - (data.length % 16);
  const padded = Buffer.alloc(data.length + pad, pad);
  padded.set(data, 0);
  const out = Buffer.alloc(padded.length);
  for (let offset = 0; offset < padded.length; offset += 16) {
    const cipher = createCipheriv("aes-128-ecb", key, null);
    cipher.setAutoPadding(false);
    state = Buffer.concat([cipher.update(state), cipher.final()]);
    for (let i = 0; i < 16; i++) {
      out[offset + i] = padded[offset + i]! ^ state[i]!;
    }
  }
  return out.readUInt32LE(out.length - 4);
}

function reverseNibble(x: number): number {
  return (((x >>> 4) | ((x & 0x0f) << 4)) & 0xff) >>> 0;
}

function reverseBits8(x: number): number {
  let res = 0;
  for (let i = 0; i < 8; i++) {
    if ((x & (1 << i)) !== 0) res |= 1 << (7 - i);
  }
  return res >>> 0;
}

function reverseBits32(x: number): number {
  let res = 0;
  for (let i = 0; i < 32; i++) {
    if (((x >>> i) & 1) !== 0) res = (res | (1 << (31 - i))) >>> 0;
  }
  return res >>> 0;
}

export function gorgon(query: string, khronos: number | bigint, stub?: Uint8Array): string {
  const input = Buffer.alloc(20);
  md5Bytes(query).copy(input, 0, 0, 4);
  if (stub !== undefined) {
    Buffer.from(stub).copy(input, 4, 0, 4);
  }
  input.writeUInt32BE(Number(BigInt(khronos) & 0xffffffffn) >>> 0, 16);
  const mixed = Buffer.alloc(20);
  for (let i = 0; i < 20; i++) {
    mixed[i] = input[i]! ^ GORGON_KEYSTREAM[i]!;
  }
  for (let i = 0; i < 20; i++) {
    const b = reverseNibble(mixed[i]!);
    const c = mixed[(i + 1) % 20]!;
    const e = reverseBits8(b ^ c);
    mixed[i] = (~(e ^ 20)) & 0xff;
  }
  return Buffer.concat([GORGON_PREFIX, mixed]).toString("hex");
}

function ladonSchedule(random4: Uint8Array, aid: bigint): bigint[] {
  const md5Ascii = Buffer.from(md5Hex(Buffer.concat([Buffer.from(random4), Buffer.from(aid.toString(), "utf8")])), "ascii");
  const words = [
    md5Ascii.readBigUInt64LE(0),
    md5Ascii.readBigUInt64LE(8),
    md5Ascii.readBigUInt64LE(16),
    md5Ascii.readBigUInt64LE(24),
  ];
  let left = words[0]!;
  let right = words[1]!;
  const queue = [words[2]!, words[3]!];
  const keys = new Array<bigint>(36).fill(0n);
  keys[0] = words[0]!;
  keys[1] = words[1]!;
  keys[2] = words[2]!;
  keys[3] = words[3]!;
  for (let round = 0n; round < 34n; round++) {
    let val = (ror64(right, 8n) + left) & MASK64;
    val ^= round;
    queue.push(val);
    val ^= ror64(left, 61n);
    keys[Number(round) + 1] = val;
    left = val;
    right = queue.shift()!;
  }
  return keys;
}

export function ladon(khronos: bigint, licenseId: bigint, aid: bigint, random4: Uint8Array): string {
  const plain = Buffer.from(`${khronos}-${licenseId}-${aid}`, "utf8");
  const pad = 16 - (plain.length % 16);
  const padded = Buffer.alloc(plain.length + pad, pad);
  plain.copy(padded, 0);
  const keys = ladonSchedule(random4, aid);
  const out = Buffer.alloc(4 + padded.length);
  Buffer.from(random4).copy(out, 0, 0, 4);
  for (let offset = 0; offset < padded.length; offset += 16) {
    let left = padded.readBigUInt64LE(offset);
    let right = padded.readBigUInt64LE(offset + 8);
    for (let i = 0; i < 34; i++) {
      right = keys[i]! ^ ((left + ror64(right, 8n)) & MASK64);
      left = right ^ ror64(left, 61n);
    }
    out.writeBigUInt64LE(left, 4 + offset);
    out.writeBigUInt64LE(right, 4 + offset + 8);
  }
  return out.toString("base64");
}

export function dynEncode(version: number, params: Uint8Array, payload: Uint8Array, rand: number): Buffer {
  const uRand = rand >>> 0;
  const out = Buffer.alloc(12);
  if (version >= 1 && version <= 4) {
    const hashes = [md5Bytes(Buffer.from([0, 0, 0, 1])), md5Bytes(payload), md5Bytes(params)];
    for (let i = 0; i < 3; i++) {
      const h = hashes[i]!;
      let val: number;
      if (version === 1) {
        val = (h.readUInt32LE(0) ^ uRand) >>> 0;
      } else if (version === 2) {
        const rev = Buffer.from([reverseNibble(h[0]!), reverseNibble(h[1]!), reverseNibble(h[2]!), reverseNibble(h[3]!)]);
        val = (rev.readUInt32LE(0) ^ uRand) >>> 0;
      } else if (version === 3) {
        const swapped = Buffer.alloc(4);
        swapped.writeUInt32LE(h.readUInt32BE(0), 0);
        val = (swapped.readUInt32BE(0) ^ 0x5a5a5a5a ^ uRand) >>> 0;
      } else {
        val = (reverseBits32(h.readUInt32BE(0)) ^ uRand) >>> 0;
      }
      out.writeUInt32BE(val, i * 4);
    }
  } else if (version === 5) {
    const hashes = [sm3(Buffer.from([0, 0, 0, 1])), sm3(payload), sm3(params)];
    for (let i = 0; i < 3; i++) {
      const val = (hashes[i]!.readUInt32LE(28) ^ uRand) >>> 0;
      out.writeUInt32BE(val, i * 4);
    }
  } else if (version === 6) {
    const rBuf = Buffer.alloc(4);
    rBuf.writeUInt32BE(uRand, 0);
    const keyAscii = Buffer.from(md5Hex(rBuf), "ascii");
    const inputs = [Buffer.from([0, 0, 0, 1]), payload, params];
    for (let i = 0; i < 3; i++) {
      const val = (aesOfbLast4(inputs[i]!, keyAscii) ^ uRand) >>> 0;
      out.writeUInt32BE(val, i * 4);
    }
  } else {
    throw new Error(`unsupported dynamic version ${version}`);
  }
  return out;
}

function simonKeySchedule(key32: Buffer): bigint[] {
  const k = new Array<bigint>(72).fill(0n);
  for (let i = 0; i < 4; i++) {
    k[i] = key32.readBigUInt64LE(i * 8);
  }
  for (let i = 4; i < 72; i++) {
    const z = BigInt(Z4_BITS.charCodeAt(i - 4) - 48);
    const cZ = (MASK64 - 3n) ^ z;
    let tmp = ror64(k[i - 1]!, 3n) ^ k[i - 3]!;
    tmp ^= ror64(tmp, 1n);
    k[i] = cZ ^ k[i - 4]! ^ tmp;
  }
  return k;
}

function simonEcb(data: Buffer, keys: bigint[], decrypt: boolean): Buffer {
  const out = Buffer.alloc(data.length);
  for (let offset = 0; offset < data.length; offset += 16) {
    let y = data.readBigUInt64LE(offset);
    let x = data.readBigUInt64LE(offset + 8);
    if (decrypt) {
      for (let i = keys.length - 1; i >= 0; i--) {
        const xOld = y;
        y = x ^ (rol64(xOld, 1n) & rol64(xOld, 8n)) ^ rol64(xOld, 2n) ^ keys[i]!;
        x = xOld;
      }
    } else {
      for (const rk of keys) {
        const next = ((rol64(x, 1n) & rol64(x, 8n)) ^ y ^ rol64(x, 2n) ^ rk) & MASK64;
        y = x;
        x = next;
      }
    }
    out.writeBigUInt64LE(y, offset);
    out.writeBigUInt64LE(x, offset + 8);
  }
  return out;
}

function vmChecksum(data: Uint8Array): number {
  let state = 0;
  for (let idx = 0; idx < data.length; idx++) {
    const b = data[idx]!;
    if ((idx & 1) === 1) {
      let work = (b | ((state << 11) >>> 0)) >>> 0;
      work = (work ^ (state >>> 5) ^ state) >>> 0;
      state = (~work) >>> 0;
    } else {
      const work = (b ^ ((state << 7) >>> 0) ^ (state >>> 3)) >>> 0;
      state = (state ^ work) >>> 0;
    }
  }
  return state >>> 0;
}

function key4FromRnd4(rnd4: Uint8Array): Buffer {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(vmChecksum(rnd4.subarray(2, 4)), 0);
  return out;
}

class ProtoWriter {
  private readonly chunks: number[] = [];

  varint(value: bigint | number): void {
    let v = BigInt(value) & MASK64;
    while (true) {
      let b = Number(v & 0x7fn);
      v >>= 7n;
      if (v !== 0n) b |= 0x80;
      this.chunks.push(b);
      if (v === 0n) break;
    }
  }

  fieldVarint(field: number, value: bigint | number): void {
    this.varint(BigInt(field) << 3n);
    this.varint(value);
  }

  fieldBytes(field: number, bytes: Uint8Array): void {
    this.varint((BigInt(field) << 3n) | 2n);
    this.varint(bytes.length);
    for (const b of bytes) this.chunks.push(b);
  }

  nested(field: number, child: ProtoWriter): void {
    this.fieldBytes(field, child.toBuffer());
  }

  toBuffer(): Buffer {
    return Buffer.from(this.chunks);
  }
}

export class ProtoReader {
  private offset = 0;
  constructor(private readonly data: Buffer) {}

  varint(): bigint {
    let val = 0n;
    for (let i = 0; i < 10; i++) {
      if (this.offset >= this.data.length) throw new Error("truncated protobuf varint");
      const b = this.data[this.offset]!;
      this.offset++;
      if (i === 9 && b > 1) throw new Error("protobuf varint overflow");
      val |= BigInt(b & 0x7f) << BigInt(i * 7);
      if ((b & 0x80) === 0) return val;
    }
    throw new Error("protobuf varint is too long");
  }

  nextField(): { field: number; wire: 0; value: bigint } | { field: number; wire: 2; value: Buffer } | null {
    if (this.offset >= this.data.length) return null;
    const tag = this.varint();
    const field = Number(tag >> 3n);
    const wire = Number(tag & 7n);
    if (wire === 0) {
      return { field, wire: 0, value: this.varint() };
    }
    if (wire === 2) {
      const len = Number(this.varint());
      const end = this.offset + len;
      if (end > this.data.length) throw new Error("truncated protobuf bytes");
      const slice = this.data.subarray(this.offset, end);
      this.offset = end;
      return { field, wire: 2, value: slice };
    }
    throw new Error(`unsupported protobuf wire type ${wire}`);
  }
}

interface ResolvedPersona {
  deviceId: string;
  installId: string;
  appId: string;
  licenseId: bigint;
  sdkVersion: string;
  sdkVersionCode: bigint;
  appVersion: string;
  versionCode: string;
  model: string;
  device: string;
  build: string;
  release: string;
  securityPatch: string;
  fingerprint: string;
  channel: string;
  resolution: string;
  dpi: number;
  allowEmptyIdentity: boolean;
  deviceToken?: string;
  dynSeed?: string;
  dynVersion: number;
  seedState: bigint;
  sessionBlobHex?: string;
  rsk2Ms: bigint;
  envSalt32: number;
  f23Field2: bigint;
  f23Field4: bigint;
  f23Field5: bigint;
  f26Tail?: DynTail[];
  f34?: string;
  f35?: string;
  f36?: string;
}

function resolvePersona(raw: Persona): ResolvedPersona {
  const p: ResolvedPersona = {
    deviceId: raw.deviceId ?? "",
    installId: raw.installId ?? "",
    appId: raw.appId ?? "1233",
    licenseId: BigInt(raw.licenseId ?? 2_142_840_551),
    sdkVersion: raw.sdkVersion ?? "v05.03.04-ov-android",
    sdkVersionCode: BigInt(raw.sdkVersionCode ?? 0x0503_0420),
    appVersion: raw.appVersion ?? "47.7.2",
    versionCode: raw.versionCode ?? "2024707020",
    model: raw.model ?? "Pixel 7",
    device: raw.device ?? "panther",
    build: raw.build ?? "TQ3A.230805.001",
    release: raw.release ?? "13",
    securityPatch: raw.securityPatch ?? "2023-08-05",
    fingerprint: raw.fingerprint ?? "google/panther/panther:13/TQ3A.230805.001/10216780:user/release-keys",
    channel: raw.channel ?? "googleplay",
    resolution: raw.resolution ?? "1080x2400",
    dpi: raw.dpi ?? 420,
    allowEmptyIdentity: raw.allowEmptyIdentity ?? false,
    deviceToken: raw.deviceToken,
    dynSeed: raw.dynSeed,
    dynVersion: raw.dynVersion ?? 6,
    seedState: BigInt(raw.seedState ?? (raw.dynSeed !== undefined ? 3 : 1)),
    sessionBlobHex: raw.sessionBlobHex,
    rsk2Ms: BigInt(raw.rsk2Ms ?? 2),
    envSalt32: (raw.envSalt32 ?? 0x4002_0341) >>> 0,
    f23Field2: BigInt(raw.f23Field2 ?? 18),
    f23Field4: BigInt(raw.f23Field4 ?? 283_211_776),
    f23Field5: BigInt(raw.f23Field5 ?? 27_262_976),
    f26Tail: raw.f26Tail,
    f34: raw.f34,
    f35: raw.f35,
    f36: raw.f36,
  };
  if (!p.allowEmptyIdentity && (p.deviceId.length === 0 || p.installId.length === 0)) {
    throw new Error("device_id and install_id are required");
  }
  if (p.dynSeed !== undefined && (p.dynVersion < 1 || p.dynVersion > 6)) {
    throw new Error(`unsupported dynamic version ${p.dynVersion}`);
  }
  return p;
}

function parseOptionalU64(value?: string): bigint | undefined {
  if (value === undefined) return undefined;
  return BigInt(value.trim());
}

function jsonEscape(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

function buildProtobuf(
  persona: ResolvedPersona,
  queryForArgus: string,
  bodyStub: Uint8Array,
  khronos: bigint,
  nonce: number,
): Buffer {
  const p = new ProtoWriter();
  p.fieldVarint(1, 0x2020_0929n << 1n);
  p.fieldVarint(2, 2n);
  p.fieldVarint(3, BigInt(nonce >>> 0) << 1n);
  p.fieldBytes(4, Buffer.from(persona.appId, "utf8"));
  p.fieldBytes(6, Buffer.from(persona.licenseId.toString(), "utf8"));
  p.fieldBytes(7, Buffer.from(persona.appVersion, "utf8"));
  p.fieldBytes(8, Buffer.from(persona.sdkVersion, "utf8"));
  p.fieldVarint(9, persona.sdkVersionCode << 1n);
  p.fieldBytes(10, Buffer.alloc(8));
  p.fieldVarint(12, khronos << 1n);
  p.fieldBytes(13, sm3(bodyStub).subarray(0, 6));
  p.fieldBytes(14, sm3(Buffer.from(queryForArgus, "utf8")).subarray(0, 6));

  const f15 = new ProtoWriter();
  f15.fieldVarint(1, 6n);
  f15.fieldVarint(5, 2n);
  f15.fieldVarint(6, 112n);
  f15.fieldVarint(7, khronos << 1n);
  p.nested(15, f15);

  const devToken =
    persona.deviceToken ??
    `{"device_id":"${jsonEscape(persona.deviceId)}","install_id":"${jsonEscape(persona.installId)}","channel":"${jsonEscape(persona.channel)}","app_version":"${jsonEscape(persona.appVersion)}","os":"Android","os_version":"${jsonEscape(persona.release)}","device_type":"${jsonEscape(persona.model)}","device_brand":"google","resolution":"${jsonEscape(persona.resolution)}","dpi":${persona.dpi},"rom":"${jsonEscape(persona.build)}","host_abi":"arm64-v8a"}`;
  p.fieldBytes(16, Buffer.from(devToken, "utf8"));
  p.fieldVarint(17, khronos << 1n);
  p.fieldBytes(20, Buffer.from("none", "utf8"));
  p.fieldVarint(21, 624n);

  const f23 = new ProtoWriter();
  f23.fieldBytes(1, Buffer.from(persona.model, "utf8"));
  f23.fieldVarint(2, persona.f23Field2);
  f23.fieldBytes(3, Buffer.from(persona.channel, "utf8"));
  f23.fieldVarint(4, persona.f23Field4);
  f23.fieldVarint(5, persona.f23Field5);
  p.nested(23, f23);

  p.fieldVarint(25, persona.seedState << 1n);
  if (persona.dynSeed !== undefined) {
    p.fieldBytes(24, Buffer.from(persona.dynSeed, "utf8"));
    const entry = new ProtoWriter();
    entry.fieldVarint(1, BigInt(persona.dynVersion) << 1n);
    entry.fieldBytes(2, dynEncode(persona.dynVersion, Buffer.from(queryForArgus, "utf8"), bodyStub, nonce));
    p.nested(26, entry);
    p.fieldVarint(28, 10n);
  }
  if (persona.f26Tail !== undefined) {
    for (const item of persona.f26Tail) {
      const entry = new ProtoWriter();
      entry.fieldVarint(1, BigInt(item.algorithm) << 1n);
      entry.fieldBytes(2, Buffer.from(item.outputHex, "hex"));
      p.nested(26, entry);
    }
  }
  p.fieldVarint(29, 2n);
  p.fieldVarint(30, 8n);
  const f31Val = (persona.envSalt32 ^ (nonce >>> 0) ^ Number(khronos & 0xffffffffn)) >>> 0;
  p.fieldVarint(31, BigInt(f31Val) << 1n);
  if (persona.sessionBlobHex !== undefined) {
    p.fieldBytes(32, Buffer.from(persona.sessionBlobHex, "hex"));
  }
  p.fieldVarint(33, persona.rsk2Ms << 1n);

  const f34 =
    parseOptionalU64(persona.f34) ??
    (((randomBytes(8).readBigUInt64BE(0) & 0x1fffffffffffffffn) << 1n) & MASK64);
  p.fieldVarint(34, f34);

  const f35 =
    parseOptionalU64(persona.f35) ??
    (() => {
      const low = BigInt(((randomBytes(4).readUInt32BE(0) & 0x7f0f87ff) | 0x00800000) >>> 0);
      return (((((khronos / 60n) & 0x3fn) << 58n) | (2n << 46n) | low) << 1n) & MASK64;
    })();
  p.fieldVarint(35, f35);

  const f36 =
    parseOptionalU64(persona.f36) ??
    (() => {
      const high = BigInt(randomBytes(4).readUInt32BE(0) & 0x7fffffff) << 32n;
      const low = BigInt(randomBytes(4).readUInt32BE(0));
      return ((high | low) << 1n) & MASK64;
    })();
  p.fieldVarint(36, f36);

  return p.toBuffer();
}

export function encryptArgus(
  protobuf: Buffer,
  header: Buffer,
  key4: Buffer,
  rnd4: Buffer,
  trailer: Buffer,
): string {
  const pad = 16 - (protobuf.length % 16);
  const padded = Buffer.alloc(protobuf.length + pad, pad);
  protobuf.copy(padded, 0);
  const simonKey = sm3(Buffer.concat([ARGUS_SIGN_KEY, rnd4, ARGUS_SIGN_KEY]));
  const keys = simonKeySchedule(simonKey);
  const simon = simonEcb(padded, keys, false);
  const buf = Buffer.alloc(simon.length + 8);
  for (let i = 0; i < simon.length; i++) {
    buf[i] = simon[simon.length - 1 - i]!;
  }
  for (let i = 0; i < buf.length; i++) {
    buf[i] = buf[i]! ^ key4[i % 4]!;
  }
  const pre = Buffer.concat([header, buf, rnd4.subarray(2, 4), trailer]);
  const ciphertext = aesCbcEncryptNoPad(pre, ARGUS_AES_KEY, ARGUS_AES_IV);
  return Buffer.concat([rnd4.subarray(0, 2), ciphertext]).toString("base64");
}

export function decryptArgus(tokenB64: string): Buffer {
  const token = Buffer.from(tokenB64, "base64");
  if (token.length < 18) throw new Error("Argus token is too short");
  const plaintext = aesCbcDecryptNoPad(token.subarray(2), ARGUS_AES_KEY, ARGUS_AES_IV);
  if (plaintext.length < 32) throw new Error("Argus plaintext is too short");
  const buf = plaintext.subarray(9, plaintext.length - 15);
  if (buf.length < 8) throw new Error("Argus buffer is too short");
  const rnd4 = Buffer.concat([token.subarray(0, 2), plaintext.subarray(plaintext.length - 15, plaintext.length - 13)]);
  const key4 = buf.subarray(buf.length - 8, buf.length - 4);
  const unxored = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) {
    unxored[i] = buf[i]! ^ key4[i % 4]!;
  }
  for (let i = unxored.length - 8; i < unxored.length; i++) {
    if (unxored[i] !== 0) throw new Error("Argus trailing zero bytes missing");
  }
  const rev = Buffer.alloc(unxored.length - 8);
  for (let i = 0; i < rev.length; i++) {
    rev[i] = unxored[rev.length - 1 - i]!;
  }
  const keys = simonKeySchedule(sm3(Buffer.concat([ARGUS_SIGN_KEY, rnd4, ARGUS_SIGN_KEY])));
  const padded = simonEcb(rev, keys, true);
  const pad = padded[padded.length - 1] ?? 0;
  if (pad === 0 || pad > 16 || pad > padded.length) throw new Error("invalid Argus padding");
  return padded.subarray(0, padded.length - pad);
}

function resolveBodyBytes(input: Pick<SignInput, "body" | "bodyBase64">): Buffer {
  if (input.body !== undefined) {
    return typeof input.body === "string" ? Buffer.from(input.body, "utf8") : Buffer.from(input.body);
  }
  if (input.bodyBase64 !== undefined && input.bodyBase64.length > 0) {
    return Buffer.from(input.bodyBase64, "base64");
  }
  return Buffer.alloc(0);
}

export function signRequest(input: SignInput): SignOutput {
  const persona = resolvePersona(input.persona);
  const method = input.method ?? "GET";
  const parsedUrl = new URL(input.url);
  const query = parsedUrl.search.startsWith("?") ? parsedUrl.search.slice(1) : "";
  const extraHeaders = input.headers ?? {};
  const commonParams =
    Object.entries(extraHeaders).find(([k]) => k.toLowerCase() === "x-common-params-v2")?.[1] ?? "";
  const argusQuery = `${query}${commonParams}`;
  const body = resolveBodyBytes(input);
  const bodyBase64 = input.bodyBase64 ?? (body.length > 0 ? body.toString("base64") : "");

  const nowMs = Date.now();
  const khronos = BigInt(input.nowSeconds ?? Math.floor(nowMs / 1000));
  const reqTicket = input.nowSeconds !== undefined ? khronos * 1000n : BigInt(nowMs);
  const nonce = input.nonce !== undefined ? (input.nonce >>> 0) : (randomBytes(4).readUInt32BE(0) & 0x7fffffff);
  const rnd4 = input.rnd4Hex !== undefined ? Buffer.from(input.rnd4Hex, "hex") : randomBytes(4);
  if (rnd4.length !== 4) throw new Error("rnd4 must be 4 bytes");
  const key4 = input.key4Hex !== undefined ? Buffer.from(input.key4Hex, "hex") : key4FromRnd4(rnd4);
  if (key4.length !== 4) throw new Error("key4 must be 4 bytes");
  const header = input.headerHex !== undefined ? Buffer.from(input.headerHex, "hex") : DEFAULT_HEADER;
  if (header.length !== 9) throw new Error("header must be 9 bytes");
  const trailer = input.trailerHex !== undefined ? Buffer.from(input.trailerHex, "hex") : DEFAULT_TRAILER;
  if (trailer.length !== 13) throw new Error("trailer must be 13 bytes");
  const ladonRnd4 = input.ladonRandom4Hex !== undefined ? Buffer.from(input.ladonRandom4Hex, "hex") : randomBytes(4);
  if (ladonRnd4.length !== 4) throw new Error("ladon_random4 must be 4 bytes");

  const bodyStub = md5Bytes(body);
  const protobuf = buildProtobuf(persona, argusQuery, bodyStub, khronos, nonce);
  const argus = encryptArgus(protobuf, header, key4, rnd4, trailer);
  const gorgonToken = gorgon(query, khronos, bodyStub);
  const aid = BigInt(persona.appId);
  const ladonToken = ladon(khronos, persona.licenseId, aid, ladonRnd4);
  const stubHex = bodyStub.toString("hex").toUpperCase();

  return {
    headers: {
      "X-Argus": argus,
      "X-Gorgon": gorgonToken,
      "X-Khronos": khronos.toString(),
      "X-Ss-Req-Ticket": reqTicket.toString(),
      "X-Ladon": ladonToken,
      "X-Ss-Stub": stubHex,
    },
    method,
    url: input.url,
    bodyBase64,
  };
}

export function signHeaders(input: SignInput): Record<string, string> {
  return signRequest(input).headers;
}
