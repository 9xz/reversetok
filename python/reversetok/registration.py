"""Register a device through TikTok's encrypted AppLog transport."""
from __future__ import annotations

import gzip
import json
import time
from typing import Any, Mapping

from .profiles import build_registration_header, with_common_params
from .ttencrypt import tt_encrypt_gzip
from .wreq_client import WreqResponse, WreqSession


class RegistrationResponseError(RuntimeError):
    """Raised when the registration service returns an invalid response."""


DEFAULT_REGISTRATION_URL = "https://log-va.tiktokv.com/service/2/device_register/"
_RESPONSE_IDENTITIES = {
    "bd_did": "bdDid",
    "ssid": "ssid",
    "device_token": "deviceToken",
}


def _decode_json(response: WreqResponse) -> Any:
    text = response.text
    try:
        if text.startswith("\x1f\x8b"):
            text = gzip.decompress(text.encode("latin1")).decode("utf-8")
        return json.loads(text)
    except (UnicodeError, EOFError, gzip.BadGzipFile, json.JSONDecodeError) as exc:
        raise RegistrationResponseError("device registration returned invalid JSON") from exc


def _required_identity(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, (str, int)) or value == "":
        raise RegistrationResponseError(f"device registration response requires {key}")
    return str(value)


def _parse_identity(payload: Any) -> dict[str, str]:
    if not isinstance(payload, dict):
        raise RegistrationResponseError("device registration response must be a JSON object")
    if "device_id" in payload and payload["device_id"] not in (None, ""):
        device_id = _required_identity(payload, "device_id")
    else:
        device_id = _required_identity(payload, "device_id_str")
    result = {
        "deviceId": device_id,
        "installId": _required_identity(payload, "install_id"),
    }
    if result["deviceId"] == "0" or result["installId"] == "0":
        raise RegistrationResponseError("device registration returned a placeholder identity")
    for wire_key, result_key in _RESPONSE_IDENTITIES.items():
        if wire_key not in payload or payload[wire_key] is None:
            continue
        value = payload[wire_key]
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise RegistrationResponseError(f"device registration response field {wire_key} must be a string or integer")
        result[result_key] = str(value)
    return result


class DeviceRegistrationClient:
    def __init__(
        self,
        session: WreqSession,
        persona: Mapping[str, Any],
        common_headers: Mapping[str, str] | None = None,
        overrides: Mapping[str, Any] | None = None,
        query_params: Mapping[str, Any] | None = None,
        *,
        endpoint: str = DEFAULT_REGISTRATION_URL,
    ):
        self.session = session
        self.persona = {
            "appId": "1233",
            "appVersion": "47.7.2",
            "versionCode": "2024707020",
            "model": "Pixel 7",
            "device": "panther",
            "build": "TQ3A.230805.001",
            "release": "13",
            "securityPatch": "2023-08-05",
            "fingerprint": "google/panther/panther:13/TQ3A.230805.001/10216780:user/release-keys",
            "channel": "googleplay",
            "resolution": "1080x2400",
            "dpi": 420,
            **dict(persona),
        }
        self.common_headers = dict(common_headers or {})
        raw_overrides = dict(overrides or {})
        lang = str(raw_overrides.get("language") or str(raw_overrides.get("locale", "en_US")).split("_")[0])
        self.overrides = {
            "app_language": lang,
            "language": lang,
            "locale": "en_US",
            "os_api": 33,
            "region": "US",
            **raw_overrides,
        }
        self.query_params = dict(query_params or {})
        self.endpoint = endpoint
    def register(
        self,
        *,
        now_ms: int | None = None,
        replay: Mapping[str, Any] | None = None,
        update_session_persona: bool = True,
    ) -> dict[str, str]:
        if self.persona.get("allowEmptyIdentity") is not True:
            if not self.persona.get("deviceId") or not self.persona.get("installId"):
                raise ValueError(
                    "deviceId and installId are required unless persona allowEmptyIdentity is true"
                )
        if now_ms is None:
            now_ms = time.time_ns() // 1_000_000
        if isinstance(now_ms, bool) or not isinstance(now_ms, int) or now_ms < 0:
            raise ValueError("now_ms must be a nonnegative integer")

        envelope = {
            "magic_tag": "ss_app_log",
            "header": build_registration_header(self.persona, self.overrides),
            "time_sync": {},
            "_gen_time": now_ms,
        }
        plaintext = json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        encrypted = tt_encrypt_gzip(plaintext)
        headers = {str(name).lower(): str(value) for name, value in self.common_headers.items()}
        headers.update({
            "content-type": "application/octet-stream;tt-data=a",
            "accept-encoding": "gzip",
        })
        response = self.session.post(
            with_common_params(self.endpoint, self.query_params),
            headers=headers,
            body=encrypted,
            replay=replay,
        )
        if not response.ok:
            raise RuntimeError(f"device registration failed with HTTP {response.status}: {response.text}")
        identity = _parse_identity(_decode_json(response))
        self.persona.update({
            "deviceId": identity["deviceId"],
            "installId": identity["installId"],
            "allowEmptyIdentity": False,
        })
        if update_session_persona and hasattr(self.session, "update_persona"):
            self.session.update_persona(
                deviceId=identity["deviceId"],
                installId=identity["installId"],
                allowEmptyIdentity=False,
            )
        return identity
