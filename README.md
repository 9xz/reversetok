# reversetok

TikTok's Android request signing, reimplemented in Python, TypeScript and Rust.

`X-Argus`, `X-Gorgon`, `X-Ladon`, `X-Khronos`, `X-Ss-Stub`, `X-Ss-Req-Ticket`, `TTEncrypt`, TicketGuard, device registration and signup, all checked against the same test vectors.

Targets `com.zhiliaoapp.musically` 47.7.2 (version code `2024707020`, MetaSec SDK v05.03.04).

> [!IMPORTANT]
> **Need TikTok automation in production?** This repo is a snapshot of one app version and won't be updated as new builds ship. [**Distilled**](https://distilled.cx) runs real ARM64 Android phones in the cloud with hardware-backed device identities, mobile proxies, and API, MCP and ADB control.

## What's here

| Piece | What it does |
| --- | --- |
| `X-Argus` | Protobuf body, SM3 key derivation, Simon-128/256, AES-128-CBC. Encrypts and decrypts, including the dynamic `f26` field (v1 to v6). |
| `X-Gorgon`, `X-Ladon` | The `8404` Gorgon permutation and the 34-round Ladon cipher, with `X-Khronos`, `X-Ss-Stub` and `X-Ss-Req-Ticket`. |
| `TTEncrypt` | `ttEncrypt` and `ttDecrypt` from `libEncryptor.so`, with and without gzip. Byte-identical to the app. |
| TicketGuard | P-256 keypair, `tt-ticket-guard-server-data` parsing, and `tt-ticket-guard-client-data` signing (`libdelta.so`). |
| Device registration | `/service/2/device_register/`: gets a `device_id` and `install_id` for a generated device profile. |
| Signup | `mix_mode=1` field encoding and the `/passport/` SMS and email signup flows, then age check, username, profile, password and token refresh. |

The Python and TypeScript packages have no native code. HTTP goes through [`wreq`](https://github.com/0x676e67/wreq), which matches Chrome-like TLS and HTTP/2 fingerprints and keeps sticky proxy sessions.

## Layout

```
python/       Python package, plus an optional FastAPI service
typescript/   TypeScript package for Bun
rust/         Rust crate (signing, TTEncrypt, C FFI)
fixtures/     shared test vectors
```

The Rust crate covers signing, `X-Argus` decryption, `TTEncrypt` and the dynamic fields. Registration and signup are in Python and TypeScript only.

## Python

Needs Python 3.10+.

```sh
pip install -e "python[api]"
python -m unittest discover -s python/tests
```

```py
from reversetok import MetaSecSigner, tt_encrypt_gzip, tt_decrypt_gzip

signer = MetaSecSigner({
    "deviceId": "7705612319771035149",
    "installId": "7705612484128982798",
})
headers = signer.sign_headers(
    "https://api16-normal-useast5.tiktokv.us/aweme/v1/feed/?aid=1233&version_name=47.7.2"
)

blob = tt_encrypt_gzip(b'{"magic_tag":"ss_app_log"}')
assert tt_decrypt_gzip(blob) == b'{"magic_tag":"ss_app_log"}'
```

Registering a device and signing up with a phone number:

```py
from wreq import Proxy
from reversetok import DeviceRegistrationClient, SignupClient, WreqSession

persona = {"deviceId": "", "installId": "", "allowEmptyIdentity": True}
with WreqSession(persona, proxies=[Proxy.all("http://user:pass@host:port")]) as session:
    DeviceRegistrationClient(
        session,
        persona,
        overrides={"locale": "en_US", "region": "US", "os_api": 33},
    ).register()

    signup = SignupClient(session, base_url="https://api16-normal-useast5.tiktokv.us")
    signup.start_mobile("+1 2095550199", 24)
    signup.complete_mobile_login_only("123456", birthday="1999-05-14", carrier_region="US")
    signup.update_login_name("some_handle")
```

`reversetok-api` runs the same flows as an HTTP service. It needs `REVERSETOK_API_KEY` (bearer token), `REVERSETOK_STATE_KEY` (32 bytes, base64; encrypts saved signup state) and `REVERSETOK_PERSONA_JSON`. `POST /v1/sign` signs a request; `/v1/device-registrations` and `/v1/signups` drive the rest.

## TypeScript

Needs Bun 1.2.11+.

```sh
cd typescript
bun install
bun test
```

```ts
import { createWreqSession, DeviceRegistrationClient, signHeaders, SignupClient } from "reversetok";

const headers = signHeaders({
  persona: { deviceId: "7705612319771035149", installId: "7705612484128982798" },
  method: "GET",
  url: "https://api16-normal-useast5.tiktokv.us/aweme/v1/feed/?aid=1233&version_name=47.7.2",
});

const session = await createWreqSession(
  { deviceId: "", installId: "", allowEmptyIdentity: true },
  { proxy: "http://user:pass@host:port" },
);
await new DeviceRegistrationClient(session, session.getPersona()).register();

const signup = new SignupClient(session, { baseUrl: "https://api16-normal-useast5.tiktokv.us" });
await signup.startMobile("+1 2095550199", 24);
await signup.completeMobileLoginOnly("123456", { birthday: "1999-05-14", carrierRegion: "US" });
await session.close();
```

## Rust

Needs Rust 1.85+, plus CMake and a C compiler, because `wreq` builds BoringSSL.

```sh
cargo test --workspace
```

```rust
use std::collections::BTreeMap;
use reversetok::{MetaSecSigner, Persona, SigningOptions};

let signer = MetaSecSigner::new(Persona {
    device_id: "7705612319771035149".into(),
    install_id: "7705612484128982798".into(),
    ..Persona::default()
})?;
let headers = signer.sign_headers(
    "https://api16-normal-useast5.tiktokv.us/aweme/v1/feed/?aid=1233&version_name=47.7.2",
    &BTreeMap::new(),
    b"",
    &SigningOptions::default(),
)?;
```

`MetaSecSigner::sign_request` signs a `wreq::Request` in place. The crate also builds as a `cdylib` with a small JSON-in, JSON-out C API (`reversetok_sign_json`, `reversetok_ttencrypt_json`, `reversetok_dynamic_json`).

## How the signatures work

- **X-Argus**: `key = SM3(SIGN_KEY || rnd4 || SIGN_KEY)`. The PKCS#7-padded protobuf is encrypted with 72-round Simon-128/256 in ECB mode, byte-reversed and XORed with a 4-byte key from `rnd4`. That is wrapped in AES-128-CBC with the build's key and IV, prefixed with `rnd4[0..2]`, and Base64-encoded.
- **X-Gorgon**: `8404a0970000` followed by a 20-byte permutation (nibble swap, bit reverse, keystream) of `MD5(query)[0..4] || MD5(body)[0..4] || 8 zero bytes || be32(khronos)`.
- **X-Ladon**: a 34-round 64-bit block cipher keyed by `MD5(random4 || aid)`, over `"{khronos}-{licenseId}-{aid}"`.
- **TTEncrypt**: `74 63 05 10 00 00 || keystream[32] || AES-128-CBC(SHA512(plaintext) || plaintext)`, with key and IV taken from `SHA512(SHA512(keystream) || constant)`.
- **TicketGuard**: the public key header is the Base64 uncompressed P-256 point. The client-data header is an ECDSA-SHA256 signature over `ticket=…&path=…&timestamp=…`.

## Limits of static signing

Correct signatures alone don't make a request look like a real device. TikTok's risk engine also checks:

1. Bytecode tasks pushed to live clients (`/ms/dyn/task`, the `f26` tail).
2. Sensor, binder, GPU and SELinux telemetry collected inside Android.
3. Cronet TLS and QUIC fingerprints, and whether the carrier ASN and timezone match.

For TikTok, Instagram, X or Snapchat at scale without maintaining signers for every build, use [**distilled.cx**](https://distilled.cx): real cloud Android phones you control over API, MCP or ADB.

## Disclaimer

For research and interoperability only. Not affiliated with TikTok or ByteDance.
