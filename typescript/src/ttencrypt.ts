import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { gunzipSync, gzipSync } from "node:zlib";

const TTENCRYPT_PREFIX = Buffer.from([0x74, 0x63, 0x05, 0x10, 0x00, 0x00]);
const TTENCRYPT_KEY_STREAM_LEN = 32;
const TTENCRYPT_KEY_CONSTANT = Buffer.from([
  0x4d, 0xd4, 0xc2, 0xe6, 0xb8, 0x31, 0x62, 0x09, 0x0e, 0x52, 0xb3, 0xc7, 0xa6, 0x73, 0x3b, 0xa4,
  0x1c, 0xb2, 0x46, 0x2b, 0x82, 0x9a, 0xb5, 0x8a, 0x19, 0x6b, 0x39, 0xdb, 0x57, 0x17, 0x75, 0x24,
  0xf4, 0x9b, 0xaf, 0x7f, 0x08, 0xe8, 0xd6, 0x8d, 0x26, 0xa7, 0x2e, 0x37, 0xc1, 0xa9, 0x5a, 0x2f,
  0x1f, 0x05, 0xa5, 0x18, 0x92, 0xae, 0xf2, 0x94, 0x97, 0x32, 0xb6, 0x2a, 0x38, 0xaa, 0xdd, 0x58,
]);

function sha512(data: Uint8Array): Buffer {
  return createHash("sha512").update(data).digest();
}

function deriveKeyMaterial(keyStream: Uint8Array): Buffer {
  if (keyStream.length !== TTENCRYPT_KEY_STREAM_LEN) {
    throw new Error("TTEncrypt keyStream must be 32 bytes");
  }
  const first = sha512(keyStream);
  return sha512(Buffer.concat([first, TTENCRYPT_KEY_CONSTANT]));
}

export function ttEncrypt(data: Uint8Array, keyStream?: Uint8Array): Buffer {
  if (data.length === 0) {
    throw new Error("TTEncrypt content must not be empty");
  }
  const ks = keyStream !== undefined ? Buffer.from(keyStream) : randomBytes(TTENCRYPT_KEY_STREAM_LEN);
  const material = deriveKeyMaterial(ks);
  const payload = Buffer.concat([sha512(data), Buffer.from(data)]);
  const cipher = createCipheriv("aes-128-cbc", material.subarray(0, 16), material.subarray(16, 32));
  const ciphertext = Buffer.concat([cipher.update(payload), cipher.final()]);
  return Buffer.concat([TTENCRYPT_PREFIX, ks, ciphertext]);
}

export function ttDecrypt(data: Uint8Array): Buffer {
  const buf = Buffer.from(data);
  if (
    buf.length < TTENCRYPT_PREFIX.length + TTENCRYPT_KEY_STREAM_LEN + 16 ||
    !buf.subarray(0, TTENCRYPT_PREFIX.length).equals(TTENCRYPT_PREFIX)
  ) {
    throw new Error("invalid TTEncrypt envelope");
  }
  const ks = buf.subarray(TTENCRYPT_PREFIX.length, TTENCRYPT_PREFIX.length + TTENCRYPT_KEY_STREAM_LEN);
  const ciphertext = buf.subarray(TTENCRYPT_PREFIX.length + TTENCRYPT_KEY_STREAM_LEN);
  if (ciphertext.length % 16 !== 0) {
    throw new Error("TTEncrypt ciphertext must be block aligned");
  }
  const material = deriveKeyMaterial(ks);
  const decipher = createDecipheriv("aes-128-cbc", material.subarray(0, 16), material.subarray(16, 32));
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  if (decrypted.length < 64) {
    throw new Error("TTEncrypt plaintext is shorter than its SHA-512 digest");
  }
  const content = decrypted.subarray(64);
  if (!decrypted.subarray(0, 64).equals(sha512(content))) {
    throw new Error("TTEncrypt content digest mismatch");
  }
  return Buffer.from(content);
}

export function ttEncryptGzip(data: Uint8Array, keyStream?: Uint8Array): Buffer {
  const compressed = Buffer.from(gzipSync(data));
  compressed.writeUInt32LE(0, 4);
  compressed[9] = 255;
  return ttEncrypt(compressed, keyStream);
}

export function ttDecryptGzip(data: Uint8Array): Buffer {
  return Buffer.from(gunzipSync(ttDecrypt(data)));
}
