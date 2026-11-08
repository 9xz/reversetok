"""Extract validated dynamic task fields from X-Argus."""
from __future__ import annotations

import hashlib
from urllib.parse import urlsplit

from .crypto import DynamicFieldsDict, MASK32, ProtoReader, decrypt_argus, dyn_encode


def extract_dynamic_fields(
    argus: str,
    url: str,
    *,
    body: bytes = b"",
) -> DynamicFieldsDict:
    query = urlsplit(url).query or ""
    body_stub = hashlib.md5(body).digest()
    protobuf = decrypt_argus(argus)
    reader = ProtoReader(protobuf)

    dyn_seed: str | None = None
    seed_state: int | None = None
    nonce: int | None = None
    now_seconds: int | None = None
    entries: list[tuple[int, bytes]] = []

    while True:
        item = reader.next_field()
        if item is None:
            break
        field, wire, val = item
        if field == 3 and wire == 0:
            assert isinstance(val, int)
            nonce = val >> 1
        elif field == 12 and wire == 0:
            assert isinstance(val, int)
            now_seconds = val >> 1
        elif field == 24 and wire == 2:
            assert isinstance(val, bytes)
            dyn_seed = val.decode("utf-8")
        elif field == 25 and wire == 0:
            assert isinstance(val, int)
            seed_state = val >> 1
        elif field == 26 and wire == 2:
            assert isinstance(val, bytes)
            nested = ProtoReader(val)
            alg: int | None = None
            out_bytes: bytes | None = None
            while True:
                n_item = nested.next_field()
                if n_item is None:
                    break
                nf, nw, nv = n_item
                if nf == 1 and nw == 0:
                    assert isinstance(nv, int)
                    alg = nv >> 1
                elif nf == 2 and nw == 2:
                    assert isinstance(nv, bytes)
                    out_bytes = nv
            if alg is None or out_bytes is None:
                raise RuntimeError("dynamic entry is missing its algorithm or output")
            entries.append((alg, out_bytes))

    if dyn_seed is None:
        raise RuntimeError("Argus has no dynamic seed field")
    if nonce is None or not 0 <= nonce <= MASK32:
        raise RuntimeError("Argus has no valid nonce")
    if now_seconds is None:
        raise RuntimeError("Argus has no timestamp")
    if seed_state is None:
        raise RuntimeError("Argus has no dynamic seed state")

    builtin: tuple[int, int] | None = None
    for idx, (alg, output) in enumerate(entries):
        if 1 <= alg <= 6:
            expected = dyn_encode(alg, query.encode("utf-8"), body_stub, nonce)
            if output == expected:
                builtin = (idx, alg)
                break
    if builtin is None:
        raise RuntimeError("built-in dynamic entry does not match the request")
    builtin_idx, dyn_version = builtin
    return {
        "dynSeed": dyn_seed,
        "dynVersion": dyn_version,
        "seedState": seed_state,
        "nonce": nonce,
        "nowSeconds": now_seconds,
        "f26Tail": [
            {"algorithm": alg, "outputHex": out_b.hex()}
            for idx, (alg, out_b) in enumerate(entries)
            if idx != builtin_idx
        ],
    }
