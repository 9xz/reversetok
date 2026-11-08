"""Pure-Python cryptographic primitives and request signing for TikTok 47.7.2."""
from __future__ import annotations

import base64
import hashlib
import os
import struct
import time
from typing import Any, Mapping, TypedDict
from urllib.parse import urlsplit

VERSION = "0.1.0"
MASK64 = 0xFFFFFFFFFFFFFFFF
MASK32 = 0xFFFFFFFF

ARGUS_SIGN_KEY = bytes([
    0xC0, 0x2F, 0x25, 0x0F, 0x86, 0xCC, 0x4F, 0x19, 0x8D, 0x57, 0x06, 0x39, 0x8D, 0x29, 0x2A, 0x8B,
    0x74, 0x16, 0x9A, 0xBA, 0x61, 0xAF, 0xFE, 0x7C, 0xBA, 0x02, 0xE4, 0xA3, 0xB5, 0x19, 0x81, 0x63,
])
ARGUS_AES_KEY = bytes([
    0x82, 0x52, 0x97, 0x0D, 0x95, 0x9B, 0x06, 0xDB, 0x10, 0x2E, 0x17, 0xD8, 0x5C, 0x0E, 0xC1, 0xAF,
])
ARGUS_AES_IV = bytes([
    0x4D, 0x20, 0x7E, 0xA3, 0x7A, 0x41, 0x9F, 0x7D, 0x62, 0x2F, 0x81, 0xC6, 0xA2, 0xF5, 0x35, 0x94,
])
DEFAULT_HEADER = bytes([0xEC, 0xC5, 0x58, 0x2D, 0x37, 0x01, 0x9C, 0x03, 0x18])
DEFAULT_TRAILER = bytes([0x48, 0x22, 0x8A, 0x29, 0xA7, 0x9E, 0x78, 0xE0, 0x80, 0x00, 0x00, 0xF5, 0x0D])
GORGON_PREFIX = bytes([0x84, 0x04, 0xA0, 0x97, 0x00, 0x00])
GORGON_KEYSTREAM = bytes([
    0xA7, 0xFD, 0xD6, 0xA3, 0xA4, 0xA7, 0xB6, 0xAF, 0xBB, 0xC5, 0xFD, 0xA4, 0xD7, 0x6E, 0xA4, 0xF0,
    0xDB, 0xF5, 0xF2, 0xF0,
])
Z4_BITS = b"11010001111001101011011000100000010111000011001010010011101111110100"

_SM3_IV = (
    0x7380166F,
    0x4914B2B9,
    0x172442D7,
    0xDA8A0600,
    0xA96F30BC,
    0x163138AA,
    0xE38DEE4D,
    0xB0FB0E4E,
)

_AES_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)
_AES_INV_SBOX = tuple(_AES_SBOX.index(i) for i in range(256))
_AES_RCON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


class DynTailDict(TypedDict):
    algorithm: int
    outputHex: str


class SignOutputDict(TypedDict):
    headers: dict[str, str]
    method: str
    url: str
    bodyBase64: str


class DynamicFieldsDict(TypedDict):
    dynSeed: str
    dynVersion: int
    seedState: int
    nonce: int
    nowSeconds: int
    f26Tail: list[DynTailDict]


def _rol32(x: int, n: int) -> int:
    n &= 31
    return ((x << n) | (x >> (32 - n))) & MASK32 if n else x & MASK32


def _rol64(x: int, n: int) -> int:
    n &= 63
    return ((x << n) | (x >> (64 - n))) & MASK64 if n else x & MASK64


def _ror64(x: int, n: int) -> int:
    n &= 63
    return ((x >> n) | (x << (64 - n))) & MASK64 if n else x & MASK64


def _p0(x: int) -> int:
    return x ^ _rol32(x, 9) ^ _rol32(x, 17)


def _p1(x: int) -> int:
    return x ^ _rol32(x, 15) ^ _rol32(x, 23)


def sm3(data: bytes) -> bytes:
    bit_len = (len(data) * 8) & MASK64
    padded = bytearray(data)
    padded.append(0x80)
    while len(padded) % 64 != 56:
        padded.append(0)
    padded.extend(struct.pack(">Q", bit_len))

    state = list(_SM3_IV)
    for offset in range(0, len(padded), 64):
        block = padded[offset : offset + 64]
        w = list(struct.unpack(">16I", block)) + [0] * 52
        for j in range(16, 68):
            w[j] = _p1(w[j - 16] ^ w[j - 9] ^ _rol32(w[j - 3], 15)) ^ _rol32(w[j - 13], 7) ^ w[j - 6]
        w1 = [w[j] ^ w[j + 4] for j in range(64)]

        a, b, c, d, e, f, g, h = state
        for j in range(64):
            tj = 0x79CC4519 if j < 16 else 0x7A879D8A
            ss1 = _rol32((_rol32(a, 12) + e + _rol32(tj, j)) & MASK32, 7)
            ss2 = ss1 ^ _rol32(a, 12)
            if j < 16:
                ff = a ^ b ^ c
                gg = e ^ f ^ g
            else:
                ff = (a & b) | (a & c) | (b & c)
                gg = (e & f) | ((~e & MASK32) & g)
            tt1 = (ff + d + ss2 + w1[j]) & MASK32
            tt2 = (gg + h + ss1 + w[j]) & MASK32
            d = c
            c = _rol32(b, 9)
            b = a
            a = tt1
            h = g
            g = _rol32(f, 19)
            f = e
            e = _p0(tt2)
        state = [(s ^ v) & MASK32 for s, v in zip(state, (a, b, c, d, e, f, g, h))]

    return struct.pack(">8I", *state)


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF


def _gf_mul(a: int, b: int) -> int:
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        a = _xtime(a)
        b >>= 1
    return res


def aes128_expand_key(key: bytes) -> list[list[int]]:
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    words = [list(key[i : i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = list(words[i - 1])
        if i % 4 == 0:
            temp = [_AES_SBOX[temp[(j + 1) % 4]] for j in range(4)]
            temp[0] ^= _AES_RCON[i // 4]
        words.append([words[i - 4][j] ^ temp[j] for j in range(4)])
    return [sum(words[r * 4 : (r + 1) * 4], []) for r in range(11)]


def aes128_encrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    s = [block[i] ^ round_keys[0][i] for i in range(16)]
    for r in range(1, 10):
        s = [_AES_SBOX[b] for b in s]
        s = [
            s[0], s[5], s[10], s[15],
            s[4], s[9], s[14], s[3],
            s[8], s[13], s[2], s[7],
            s[12], s[1], s[6], s[11],
        ]
        for c in range(4):
            i = c * 4
            a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
            t = a0 ^ a1 ^ a2 ^ a3
            s[i] ^= t ^ _xtime(a0 ^ a1)
            s[i + 1] ^= t ^ _xtime(a1 ^ a2)
            s[i + 2] ^= t ^ _xtime(a2 ^ a3)
            s[i + 3] ^= t ^ _xtime(a3 ^ a0)
        rk = round_keys[r]
        s = [s[i] ^ rk[i] for i in range(16)]
    s = [_AES_SBOX[b] for b in s]
    s = [
        s[0], s[5], s[10], s[15],
        s[4], s[9], s[14], s[3],
        s[8], s[13], s[2], s[7],
        s[12], s[1], s[6], s[11],
    ]
    rk10 = round_keys[10]
    return bytes(s[i] ^ rk10[i] for i in range(16))


def aes128_decrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    rk10 = round_keys[10]
    s = [block[i] ^ rk10[i] for i in range(16)]
    for r in range(9, 0, -1):
        s = [
            s[0], s[13], s[10], s[7],
            s[4], s[1], s[14], s[11],
            s[8], s[5], s[2], s[15],
            s[12], s[9], s[6], s[3],
        ]
        s = [_AES_INV_SBOX[b] for b in s]
        rk = round_keys[r]
        s = [s[i] ^ rk[i] for i in range(16)]
        for c in range(4):
            i = c * 4
            a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
            s[i] = _gf_mul(a0, 0x0E) ^ _gf_mul(a1, 0x0B) ^ _gf_mul(a2, 0x0D) ^ _gf_mul(a3, 0x09)
            s[i + 1] = _gf_mul(a0, 0x09) ^ _gf_mul(a1, 0x0E) ^ _gf_mul(a2, 0x0B) ^ _gf_mul(a3, 0x0D)
            s[i + 2] = _gf_mul(a0, 0x0D) ^ _gf_mul(a1, 0x09) ^ _gf_mul(a2, 0x0E) ^ _gf_mul(a3, 0x0B)
            s[i + 3] = _gf_mul(a0, 0x0B) ^ _gf_mul(a1, 0x0D) ^ _gf_mul(a2, 0x09) ^ _gf_mul(a3, 0x0E)
    s = [
        s[0], s[13], s[10], s[7],
        s[4], s[1], s[14], s[11],
        s[8], s[5], s[2], s[15],
        s[12], s[9], s[6], s[3],
    ]
    s = [_AES_INV_SBOX[b] for b in s]
    rk0 = round_keys[0]
    return bytes(s[i] ^ rk0[i] for i in range(16))


def aes128_cbc_encrypt_nopad(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(data) % 16 != 0:
        raise ValueError("AES-CBC data must be block-aligned")
    rks = aes128_expand_key(key)
    prev = iv
    out = bytearray()
    for offset in range(0, len(data), 16):
        xored = bytes(data[offset + i] ^ prev[i] for i in range(16))
        prev = aes128_encrypt_block(xored, rks)
        out.extend(prev)
    return bytes(out)


def aes128_cbc_decrypt_nopad(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(data) == 0 or len(data) % 16 != 0:
        raise ValueError("AES-CBC ciphertext must be block-aligned")
    rks = aes128_expand_key(key)
    prev = iv
    out = bytearray()
    for offset in range(0, len(data), 16):
        block = data[offset : offset + 16]
        dec = aes128_decrypt_block(block, rks)
        out.extend(dec[i] ^ prev[i] for i in range(16))
        prev = block
    return bytes(out)


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad = block_size - (len(data) % block_size)
    return data + bytes([pad] * pad)


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("invalid PKCS#7 padded length")
    pad = data[-1]
    if pad == 0 or pad > block_size or any(b != pad for b in data[-pad:]):
        raise ValueError("invalid PKCS#7 padding")
    return data[:-pad]


def _aes_ofb_last4(data: bytes, key_ascii: bytes) -> int:
    rks = aes128_expand_key(key_ascii[:16])
    state = key_ascii[16:32]
    padded = pkcs7_pad(data, 16)
    out = bytearray()
    for offset in range(0, len(padded), 16):
        state = aes128_encrypt_block(state, rks)
        block = padded[offset : offset + 16]
        out.extend(a ^ b for a, b in zip(block, state))
    return int.from_bytes(out[-4:], "little")


def _reverse_nibble(x: int) -> int:
    return ((x >> 4) | ((x & 0x0F) << 4)) & 0xFF


def _reverse_bits8(x: int) -> int:
    res = 0
    for i in range(8):
        if x & (1 << i):
            res |= 1 << (7 - i)
    return res


def _reverse_bits32(x: int) -> int:
    res = 0
    for i in range(32):
        if x & (1 << i):
            res |= 1 << (31 - i)
    return res


def gorgon(query: str, khronos: int, stub: bytes | None = None) -> str:
    buf = bytearray(20)
    buf[:4] = hashlib.md5(query.encode("utf-8")).digest()[:4]
    if stub is not None:
        buf[4:8] = stub[:4]
    buf[16:20] = struct.pack(">I", khronos & MASK32)
    mixed = bytearray(buf[i] ^ GORGON_KEYSTREAM[i] for i in range(20))
    for i in range(20):
        b = _reverse_nibble(mixed[i])
        c = mixed[(i + 1) % 20]
        e = _reverse_bits8(b ^ c)
        mixed[i] = (~(e ^ 20)) & 0xFF
    return (GORGON_PREFIX + bytes(mixed)).hex()


def _ladon_schedule(random4: bytes, aid: int) -> list[int]:
    md5_ascii = hashlib.md5(random4 + str(aid).encode("ascii")).hexdigest().encode("ascii")
    words = [int.from_bytes(md5_ascii[i * 8 : (i + 1) * 8], "little") for i in range(4)]
    left, right = words[0], words[1]
    queue = [words[2], words[3]]
    keys = [0] * 36
    keys[:4] = words
    for r in range(34):
        val = (_ror64(right, 8) + left) & MASK64
        val ^= r
        queue.append(val)
        val ^= _ror64(left, 61)
        keys[r + 1] = val
        left = val
        right = queue.pop(0)
    return keys


def ladon(khronos: int, license_id: int, aid: int, random4: bytes) -> str:
    padded = pkcs7_pad(f"{khronos}-{license_id}-{aid}".encode("utf-8"), 16)
    keys = _ladon_schedule(random4, aid)
    out = bytearray(random4)
    for offset in range(0, len(padded), 16):
        block = padded[offset : offset + 16]
        left = int.from_bytes(block[:8], "little")
        right = int.from_bytes(block[8:16], "little")
        for key in keys[:34]:
            right = key ^ ((left + _ror64(right, 8)) & MASK64)
            left = right ^ _ror64(left, 61)
        out.extend(left.to_bytes(8, "little"))
        out.extend(right.to_bytes(8, "little"))
    return base64.b64encode(bytes(out)).decode("ascii")


def dyn_encode(version: int, params: bytes, payload: bytes, rand: int) -> bytes:
    rand &= MASK32
    out = bytearray()
    if 1 <= version <= 4:
        hashes = (
            hashlib.md5(b"\x00\x00\x00\x01").digest(),
            hashlib.md5(payload).digest(),
            hashlib.md5(params).digest(),
        )
        for h in hashes:
            if version == 1:
                val = int.from_bytes(h[:4], "little") ^ rand
            elif version == 2:
                rev = bytes(_reverse_nibble(b) for b in h[:4])
                val = int.from_bytes(rev, "little") ^ rand
            elif version == 3:
                swapped = int.from_bytes(h[:4], "big").to_bytes(4, "little")
                val = int.from_bytes(swapped, "big") ^ 0x5A5A5A5A ^ rand
            else:
                val = _reverse_bits32(int.from_bytes(h[:4], "big")) ^ rand
            out.extend((val & MASK32).to_bytes(4, "big"))
    elif version == 5:
        for h in (sm3(b"\x00\x00\x00\x01"), sm3(payload), sm3(params)):
            val = (int.from_bytes(h[28:32], "little") ^ rand) & MASK32
            out.extend(val.to_bytes(4, "big"))
    elif version == 6:
        key_ascii = hashlib.md5(rand.to_bytes(4, "big")).hexdigest().encode("ascii")
        for src in (b"\x00\x00\x00\x01", payload, params):
            val = (_aes_ofb_last4(src, key_ascii) ^ rand) & MASK32
            out.extend(val.to_bytes(4, "big"))
    else:
        raise RuntimeError(f"unsupported dynamic version {version}")
    return bytes(out)


def _simon_key_schedule(key32: bytes) -> list[int]:
    k = [int.from_bytes(key32[i * 8 : (i + 1) * 8], "little") for i in range(4)] + [0] * 68
    for i in range(4, 72):
        z = Z4_BITS[i - 4] - 48
        c_z = (MASK64 - 3) ^ z
        tmp = _ror64(k[i - 1], 3) ^ k[i - 3]
        tmp ^= _ror64(tmp, 1)
        k[i] = c_z ^ k[i - 4] ^ tmp
    return k


def _simon_ecb(data: bytes, keys: list[int], decrypt: bool) -> bytes:
    out = bytearray()
    for offset in range(0, len(data), 16):
        y = int.from_bytes(data[offset : offset + 8], "little")
        x = int.from_bytes(data[offset + 8 : offset + 16], "little")
        if decrypt:
            for rk in reversed(keys):
                x_old = y
                y = x ^ (_rol64(x_old, 1) & _rol64(x_old, 8)) ^ _rol64(x_old, 2) ^ rk
                x = x_old
        else:
            for rk in keys:
                nxt = ((_rol64(x, 1) & _rol64(x, 8)) ^ y ^ _rol64(x, 2) ^ rk) & MASK64
                y = x
                x = nxt
        out.extend(y.to_bytes(8, "little"))
        out.extend(x.to_bytes(8, "little"))
    return bytes(out)


def _vm_checksum(data: bytes) -> int:
    state = 0
    for idx, byte in enumerate(data):
        if idx & 1:
            work = (byte | ((state << 11) & MASK32)) & MASK32
            work ^= (state >> 5) ^ state
            state = (~work) & MASK32
        else:
            work = byte ^ ((state << 7) & MASK32) ^ (state >> 3)
            state = (state ^ work) & MASK32
    return state


def key4_from_rnd4(rnd4: bytes) -> bytes:
    return _vm_checksum(rnd4[2:]).to_bytes(4, "big")


class ProtoWriter:
    def __init__(self) -> None:
        self.buf = bytearray()

    def varint(self, value: int) -> None:
        value &= MASK64
        while True:
            byte = value & 0x7F
            value >>= 7
            if value:
                byte |= 0x80
            self.buf.append(byte)
            if not value:
                break

    def field_varint(self, number: int, value: int) -> None:
        self.varint(number << 3)
        self.varint(value)

    def field_bytes(self, number: int, value: bytes) -> None:
        self.varint((number << 3) | 2)
        self.varint(len(value))
        self.buf.extend(value)

    def nested(self, number: int, child: ProtoWriter) -> None:
        self.field_bytes(number, bytes(child.buf))


class ProtoReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def varint(self) -> int:
        value = 0
        for index in range(10):
            if self.offset >= len(self.data):
                raise RuntimeError("truncated protobuf varint")
            byte = self.data[self.offset]
            self.offset += 1
            if index == 9 and byte > 1:
                raise RuntimeError("protobuf varint overflow")
            value |= (byte & 0x7F) << (index * 7)
            if (byte & 0x80) == 0:
                return value
        raise RuntimeError("protobuf varint is too long")

    def next_field(self) -> tuple[int, int, int | bytes] | None:
        if self.offset >= len(self.data):
            return None
        tag = self.varint()
        field = tag >> 3
        wire = tag & 7
        if wire == 0:
            return field, 0, self.varint()
        if wire == 2:
            length = self.varint()
            end = self.offset + length
            if end > len(self.data):
                raise RuntimeError("truncated protobuf bytes")
            raw = self.data[self.offset : end]
            self.offset = end
            return field, 2, raw
        raise RuntimeError(f"unsupported protobuf wire type {wire}")


def resolve_persona(raw: Mapping[str, Any]) -> dict[str, Any]:
    p = {
        "deviceId": str(raw.get("deviceId", "")),
        "installId": str(raw.get("installId", "")),
        "appId": str(raw.get("appId", "1233")),
        "licenseId": int(raw.get("licenseId", 2_142_840_551)),
        "sdkVersion": str(raw.get("sdkVersion", "v05.03.04-ov-android")),
        "sdkVersionCode": int(raw.get("sdkVersionCode", 0x0503_0420)),
        "appVersion": str(raw.get("appVersion", "47.7.2")),
        "versionCode": str(raw.get("versionCode", "2024707020")),
        "model": str(raw.get("model", "Pixel 7")),
        "device": str(raw.get("device", "panther")),
        "build": str(raw.get("build", "TQ3A.230805.001")),
        "release": str(raw.get("release", "13")),
        "securityPatch": str(raw.get("securityPatch", "2023-08-05")),
        "fingerprint": str(
            raw.get("fingerprint", "google/panther/panther:13/TQ3A.230805.001/10216780:user/release-keys")
        ),
        "channel": str(raw.get("channel", "googleplay")),
        "resolution": str(raw.get("resolution", "1080x2400")),
        "dpi": int(raw.get("dpi", 420)),
        "allowEmptyIdentity": bool(raw.get("allowEmptyIdentity", False)),
        "deviceToken": raw.get("deviceToken"),
        "dynSeed": raw.get("dynSeed"),
        "dynVersion": int(raw["dynVersion"]) if raw.get("dynVersion") is not None else 6,
        "seedState": int(raw["seedState"]) if raw.get("seedState") is not None else (3 if raw.get("dynSeed") else 1),
        "sessionBlobHex": raw.get("sessionBlobHex"),
        "rsk2Ms": int(raw.get("rsk2Ms", 2)),
        "envSalt32": int(raw.get("envSalt32", 0x4002_0341)),
        "f23Field2": int(raw.get("f23Field2", 18)),
        "f23Field4": int(raw.get("f23Field4", 283_211_776)),
        "f23Field5": int(raw.get("f23Field5", 27_262_976)),
        "f26Tail": raw.get("f26Tail"),
        "f34": raw.get("f34"),
        "f35": raw.get("f35"),
        "f36": raw.get("f36"),
    }
    if not p["allowEmptyIdentity"] and (not p["deviceId"] or not p["installId"]):
        raise RuntimeError("device_id and install_id are required")
    if p["dynSeed"] is not None:
        base64.b64decode(p["dynSeed"])
        if not 1 <= p["dynVersion"] <= 6:
            raise RuntimeError(f"unsupported dynamic version {p['dynVersion']}")
    if p["sessionBlobHex"] is not None:
        bytes.fromhex(p["sessionBlobHex"])
    return p


def _parse_optional_u64(val: Any) -> int | None:
    if val is None:
        return None
    text = str(val).strip()
    parsed = int(text[2:], 16) if text.startswith("0x") else int(text, 10)
    if parsed < 0 or parsed > MASK64:
        raise RuntimeError(f"invalid u64 {text!r}")
    return parsed


def _json_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def build_protobuf(
    persona: Mapping[str, Any],
    query_for_argus: str,
    body_stub: bytes,
    khronos: int,
    nonce: int,
) -> bytes:
    p = ProtoWriter()
    p.field_varint(1, 0x2020_0929 << 1)
    p.field_varint(2, 2)
    p.field_varint(3, (nonce & MASK32) << 1)
    p.field_bytes(4, persona["appId"].encode("utf-8"))
    p.field_bytes(6, str(persona["licenseId"]).encode("utf-8"))
    p.field_bytes(7, persona["appVersion"].encode("utf-8"))
    p.field_bytes(8, persona["sdkVersion"].encode("utf-8"))
    p.field_varint(9, persona["sdkVersionCode"] << 1)
    p.field_bytes(10, b"\x00" * 8)
    p.field_varint(12, khronos << 1)
    p.field_bytes(13, sm3(body_stub)[:6])
    p.field_bytes(14, sm3(query_for_argus.encode("utf-8"))[:6])

    f15 = ProtoWriter()
    f15.field_varint(1, 6)
    f15.field_varint(5, 2)
    f15.field_varint(6, 112)
    f15.field_varint(7, khronos << 1)
    p.nested(15, f15)

    dev_token = persona["deviceToken"] or (
        f'{{"device_id":"{_json_escape(persona["deviceId"])}",'
        f'"install_id":"{_json_escape(persona["installId"])}",'
        f'"channel":"{_json_escape(persona["channel"])}",'
        f'"app_version":"{_json_escape(persona["appVersion"])}",'
        f'"os":"Android","os_version":"{_json_escape(persona["release"])}",'
        f'"device_type":"{_json_escape(persona["model"])}",'
        f'"device_brand":"google","resolution":"{_json_escape(persona["resolution"])}",'
        f'"dpi":{persona["dpi"]},"rom":"{_json_escape(persona["build"])}","host_abi":"arm64-v8a"}}'
    )
    p.field_bytes(16, str(dev_token).encode("utf-8"))
    p.field_varint(17, khronos << 1)
    p.field_bytes(20, b"none")
    p.field_varint(21, 624)

    f23 = ProtoWriter()
    f23.field_bytes(1, persona["model"].encode("utf-8"))
    f23.field_varint(2, persona["f23Field2"])
    f23.field_bytes(3, persona["channel"].encode("utf-8"))
    f23.field_varint(4, persona["f23Field4"])
    f23.field_varint(5, persona["f23Field5"])
    p.nested(23, f23)

    p.field_varint(25, persona["seedState"] << 1)
    if persona["dynSeed"] is not None:
        p.field_bytes(24, str(persona["dynSeed"]).encode("utf-8"))
        entry = ProtoWriter()
        entry.field_varint(1, persona["dynVersion"] << 1)
        entry.field_bytes(
            2,
            dyn_encode(persona["dynVersion"], query_for_argus.encode("utf-8"), body_stub, nonce),
        )
        p.nested(26, entry)
        p.field_varint(28, 10)
    if persona["f26Tail"]:
        for item in persona["f26Tail"]:
            entry = ProtoWriter()
            entry.field_varint(1, int(item["algorithm"]) << 1)
            entry.field_bytes(2, bytes.fromhex(item["outputHex"]))
            p.nested(26, entry)
    p.field_varint(29, 2)
    p.field_varint(30, 8)
    p.field_varint(31, ((persona["envSalt32"] ^ nonce ^ (khronos & MASK32)) & MASK32) << 1)
    if persona["sessionBlobHex"] is not None:
        p.field_bytes(32, bytes.fromhex(persona["sessionBlobHex"]))
    p.field_varint(33, persona["rsk2Ms"] << 1)

    f34 = _parse_optional_u64(persona["f34"])
    if f34 is None:
        f34 = ((int.from_bytes(os.urandom(8), "big") & 0x1FFFFFFFFFFFFFFF) << 1) & MASK64
    p.field_varint(34, f34)

    f35 = _parse_optional_u64(persona["f35"])
    if f35 is None:
        low = (int.from_bytes(os.urandom(4), "big") & 0x7F0F87FF) | 0x00800000
        f35 = (((((khronos // 60) & 0x3F) << 58) | (2 << 46) | low) << 1) & MASK64
    p.field_varint(35, f35)

    f36 = _parse_optional_u64(persona["f36"])
    if f36 is None:
        high = (int.from_bytes(os.urandom(4), "big") & 0x7FFFFFFF) << 32
        low = int.from_bytes(os.urandom(4), "big")
        f36 = ((high | low) << 1) & MASK64
    p.field_varint(36, f36)
    return bytes(p.buf)


def encrypt_argus(
    protobuf: bytes,
    header: bytes = DEFAULT_HEADER,
    key4: bytes | None = None,
    rnd4: bytes | None = None,
    trailer: bytes = DEFAULT_TRAILER,
) -> str:
    resolved_rnd4 = rnd4 if rnd4 is not None else os.urandom(4)
    resolved_key4 = key4 if key4 is not None else key4_from_rnd4(resolved_rnd4)
    padded = pkcs7_pad(protobuf, 16)
    keys = _simon_key_schedule(sm3(ARGUS_SIGN_KEY + resolved_rnd4 + ARGUS_SIGN_KEY))
    simon = _simon_ecb(padded, keys, decrypt=False)
    buf = bytearray(reversed(simon)) + bytearray(8)
    for i in range(len(buf)):
        buf[i] ^= resolved_key4[i % 4]
    pre = header + bytes(buf) + resolved_rnd4[2:] + trailer
    ciphertext = aes128_cbc_encrypt_nopad(pre, ARGUS_AES_KEY, ARGUS_AES_IV)
    return base64.b64encode(resolved_rnd4[:2] + ciphertext).decode("ascii")


def decrypt_argus(token_b64: str) -> bytes:
    token = base64.b64decode(token_b64)
    if len(token) < 18:
        raise RuntimeError("Argus token is too short")
    plaintext = aes128_cbc_decrypt_nopad(token[2:], ARGUS_AES_KEY, ARGUS_AES_IV)
    if len(plaintext) < 32:
        raise RuntimeError("Argus plaintext is too short")
    buf = plaintext[9 : len(plaintext) - 15]
    if len(buf) < 8:
        raise RuntimeError("Argus buffer is too short")
    rnd4 = token[:2] + plaintext[len(plaintext) - 15 : len(plaintext) - 13]
    key4 = buf[-8:-4]
    unxored = bytes(b ^ key4[i % 4] for i, b in enumerate(buf))
    if unxored[-8:] != b"\x00" * 8:
        raise RuntimeError("Argus trailing zero bytes missing")
    reversed_simon = bytes(reversed(unxored[:-8]))
    keys = _simon_key_schedule(sm3(ARGUS_SIGN_KEY + rnd4 + ARGUS_SIGN_KEY))
    padded = _simon_ecb(reversed_simon, keys, decrypt=True)
    pad = padded[-1] if padded else 0
    if pad == 0 or pad > 16 or pad > len(padded):
        raise RuntimeError("invalid Argus padding")
    return padded[:-pad]


def sign_request(
    persona: Mapping[str, Any],
    url: str,
    *,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    body: bytes = b"",
    nowSeconds: int | None = None,
    nonce: int | None = None,
    rnd4Hex: str | None = None,
    ladonRandom4Hex: str | None = None,
    headerHex: str | None = None,
    trailerHex: str | None = None,
    key4Hex: str | None = None,
) -> SignOutputDict:
    resolved_persona = resolve_persona(persona)
    parsed = urlsplit(url)
    if not parsed.scheme or not parsed.netloc:
        raise RuntimeError(f"invalid URI: {url}")
    query = parsed.query or ""
    extra_headers = dict(headers or {})
    common_params = next(
        (str(v) for k, v in extra_headers.items() if k.lower() == "x-common-params-v2"),
        "",
    )
    argus_query = f"{query}{common_params}"

    now_ns = time.time_ns()
    now_sec = int(nowSeconds) if nowSeconds is not None else now_ns // 1_000_000_000
    req_ticket = now_sec * 1000 if nowSeconds is not None else now_ns // 1_000_000
    resolved_nonce = int(nonce) if nonce is not None else int.from_bytes(os.urandom(4), "big") & 0x7FFFFFFF
    rnd4 = bytes.fromhex(rnd4Hex) if rnd4Hex else os.urandom(4)
    if len(rnd4) != 4:
        raise RuntimeError("rnd4 must be 4 bytes")
    key4 = bytes.fromhex(key4Hex) if key4Hex else key4_from_rnd4(rnd4)
    if len(key4) != 4:
        raise RuntimeError("key4 must be 4 bytes")
    header = bytes.fromhex(headerHex) if headerHex else DEFAULT_HEADER
    if len(header) != 9:
        raise RuntimeError("header must be 9 bytes")
    trailer = bytes.fromhex(trailerHex) if trailerHex else DEFAULT_TRAILER
    if len(trailer) != 13:
        raise RuntimeError("trailer must be 13 bytes")
    ladon_rnd4 = bytes.fromhex(ladonRandom4Hex) if ladonRandom4Hex else os.urandom(4)
    if len(ladon_rnd4) != 4:
        raise RuntimeError("ladon_random4 must be 4 bytes")

    body_stub = hashlib.md5(body).digest()
    protobuf = build_protobuf(resolved_persona, argus_query, body_stub, now_sec, resolved_nonce)
    argus = encrypt_argus(protobuf, header, key4, rnd4, trailer)
    gorgon_tok = gorgon(query, now_sec, body_stub)
    aid = int(resolved_persona["appId"])
    ladon_tok = ladon(now_sec, resolved_persona["licenseId"], aid, ladon_rnd4)
    stub_hex = body_stub.hex().upper()

    return {
        "headers": {
            "X-Argus": argus,
            "X-Gorgon": gorgon_tok,
            "X-Khronos": str(now_sec),
            "X-Ss-Req-Ticket": str(req_ticket),
            "X-Ladon": ladon_tok,
            "X-Ss-Stub": stub_hex,
        },
        "method": method,
        "url": url,
        "bodyBase64": base64.b64encode(body).decode("ascii") if body else "",
    }
