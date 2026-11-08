"""Pure-Python request signing facade."""
from __future__ import annotations

from typing import Any, Mapping

from .crypto import SignOutputDict, sign_request


class MetaSecSigner:
    def __init__(self, persona: Mapping[str, Any]):
        self.persona = dict(persona)

    def sign_request(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: Mapping[str, str] | None = None,
        body: bytes = b"",
        **options: Any,
    ) -> SignOutputDict:
        return sign_request(
            self.persona,
            url,
            method=method,
            headers=headers,
            body=body,
            **options,
        )

    def sign_headers(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes = b"",
        **options: Any,
    ) -> dict[str, str]:
        return self.sign_request(url, headers=headers, body=body, **options)["headers"]
