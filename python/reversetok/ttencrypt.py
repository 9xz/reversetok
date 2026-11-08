"""Pure-Python TTEncrypt payload encryption and decryption."""
from __future__ import annotations

import gzip
import hashlib
import io
import os

from .crypto import aes128_cbc_decrypt_nopad, aes128_cbc_encrypt_nopad, pkcs7_pad, pkcs7_unpad

PREFIX = bytes([0x74, 0x63, 0x05, 0x10, 0x00, 0x00])
KEY_STREAM_LEN = 32
KEY_MATERIAL_CONSTANT = bytes([
    0x4D, 0xD4, 0xC2, 0xE6, 0xB8, 0x31, 0x62, 0x09, 0x0E, 0x52, 0xB3, 0xC7, 0xA6, 0x73, 0x3B, 0xA4,
    0x1C, 0xB2, 0x46, 0x2B, 0x82, 0x9A, 0xB5, 0x8A, 0x19, 0x6B, 0x39, 0xDB, 0x57, 0x17, 0x75, 0x24,
    0xF4, 0x9B, 0xAF, 0x7F, 0x08, 0xE8, 0xD6, 0x8D, 0x26, 0xA7, 0x2E, 0x37, 0xC1, 0xA9, 0x5A, 0x2F,
    0x1F, 0x05, 0xA5, 0x18, 0x92, 0xAE, 0xF2, 0x94, 0x97, 0x32, 0xB6, 0x2A, 0x38, 0xAA, 0xDD, 0x58,
])


def _derive_key_material(key_stream: bytes) -> bytes:
    if len(key_stream) != KEY_STREAM_LEN:
        raise RuntimeError("key_stream must be 32 bytes")
    first = hashlib.sha512(key_stream).digest()
    return hashlib.sha512(first + KEY_MATERIAL_CONSTANT).digest()


def tt_encrypt(data: bytes, key_stream: bytes | None = None) -> bytes:
    if not data:
        raise RuntimeError("TTEncrypt content must not be empty")
    ks = key_stream if key_stream is not None else os.urandom(KEY_STREAM_LEN)
    material = _derive_key_material(ks)
    payload = pkcs7_pad(hashlib.sha512(data).digest() + data, 16)
    ciphertext = aes128_cbc_encrypt_nopad(payload, material[:16], material[16:32])
    return PREFIX + ks + ciphertext


def tt_decrypt(data: bytes) -> bytes:
    if len(data) < len(PREFIX) + KEY_STREAM_LEN + 16 or not data.startswith(PREFIX):
        raise RuntimeError("invalid TTEncrypt envelope")
    ks = data[len(PREFIX) : len(PREFIX) + KEY_STREAM_LEN]
    ciphertext = data[len(PREFIX) + KEY_STREAM_LEN :]
    if len(ciphertext) % 16 != 0:
        raise RuntimeError("TTEncrypt ciphertext must be block aligned")
    material = _derive_key_material(ks)
    try:
        decrypted = pkcs7_unpad(aes128_cbc_decrypt_nopad(ciphertext, material[:16], material[16:32]), 16)
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc
    if len(decrypted) < 64:
        raise RuntimeError("TTEncrypt plaintext is shorter than its SHA-512 digest")
    content = decrypted[64:]
    if decrypted[:64] != hashlib.sha512(content).digest():
        raise RuntimeError("TTEncrypt content digest mismatch")
    return content


def _gzip_java_os(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", compresslevel=6, mtime=0, fileobj=buf) as gz:
        gz.write(data)
    raw = bytearray(buf.getvalue())
    raw[9] = 255
    return bytes(raw)


def tt_encrypt_gzip(data: bytes, key_stream: bytes | None = None) -> bytes:
    return tt_encrypt(_gzip_java_os(data), key_stream)


def tt_decrypt_gzip(data: bytes) -> bytes:
    return gzip.decompress(tt_decrypt(data))
