"""Language-native wreq HTTP transport for signed requests."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

from wreq import Cookie, Method
from wreq.blocking import Client
from wreq.redirect import Policy
from .signer import MetaSecSigner


@dataclass(frozen=True)
class WreqResponse:
    status: int
    url: str
    headers: Mapping[str, str]
    text: str

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self) -> Any:
        return json.loads(self.text)


def _text(value: Any) -> str:
    return str(value, "ascii") if isinstance(value, memoryview) else str(value)


def _read_response(response: Any) -> WreqResponse:
    text = response.text()
    response_headers = {}
    for name in response.headers.keys():
        key = _text(name)
        response_headers[key] = _text(response.headers.get(key))
    return WreqResponse(
        status=response.status.as_int(),
        url=str(response.url),
        headers=response_headers,
        text=text,
    )


class _SignedTransport(MetaSecSigner):
    def __init__(self, persona: Mapping[str, Any], **client_options: Any):
        super().__init__(persona)
        self.client_options = dict(client_options)
        self.client_options.setdefault("redirect", Policy.limited(5))
        self.default_headers = {
            str(name).lower(): str(value)
            for name, value in dict(self.client_options.pop("headers", None) or {}).items()
        }

    def _execute(
        self,
        client: Client,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None,
        body: bytes,
        replay: Mapping[str, Any] | None,
        request_options: Mapping[str, Any],
    ) -> WreqResponse:
        merged_headers = dict(self.default_headers)
        merged_headers.update({str(name).lower(): str(value) for name, value in dict(headers or {}).items()})
        signed = self.sign_request(url, method=method, headers=merged_headers, body=body, **dict(replay or {}))
        request_headers = dict(merged_headers)
        request_headers.update(signed["headers"])
        with client.request(
            getattr(Method, method.upper()),
            url,
            headers=request_headers,
            body=body,
            **dict(request_options),
        ) as response:
            return _read_response(response)


class WreqClient(_SignedTransport):
    """Sign and send isolated requests through wreq.blocking.Client."""

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes = b"",
        replay: Mapping[str, Any] | None = None,
        **request_options: Any,
    ) -> WreqResponse:
        with Client(**self.client_options) as client:
            return self._execute(
                client,
                method,
                url,
                headers=headers,
                body=body,
                replay=replay,
                request_options=request_options,
            )

    def get(self, url: str, **options: Any) -> WreqResponse:
        return self.request("GET", url, **options)

    def post(self, url: str, **options: Any) -> WreqResponse:
        return self.request("POST", url, **options)


class WreqSession(_SignedTransport):
    """Keep cookies, proxy settings, and connections for a multi-request flow."""

    def __init__(self, persona: Mapping[str, Any], **client_options: Any):
        super().__init__(persona, **client_options)
        self.client_options.setdefault("cookie_store", True)
        self._client = Client(**self.client_options)
        self._closed = False
    def update_persona(self, updates: Mapping[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        if updates:
            self.persona.update(updates)
        if kwargs:
            self.persona.update(kwargs)
        return dict(self.persona)

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def cookie_jar(self) -> Any:
        self._ensure_active()
        jar = self._client.cookie_jar
        if jar is None:
            raise RuntimeError("wreq cookie store is unavailable")
        return jar

    def _ensure_active(self) -> None:
        if self._closed:
            raise RuntimeError("WreqSession is closed")

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes = b"",
        replay: Mapping[str, Any] | None = None,
        **request_options: Any,
    ) -> WreqResponse:
        self._ensure_active()
        return self._execute(
            self._client,
            method,
            url,
            headers=headers,
            body=body,
            replay=replay,
            request_options=request_options,
        )

    def get(self, url: str, **options: Any) -> WreqResponse:
        return self.request("GET", url, **options)

    def post(self, url: str, **options: Any) -> WreqResponse:
        return self.request("POST", url, **options)

    def get_cookies(self, url: str) -> dict[str, str]:
        parts = urlsplit(url)
        host = parts.hostname
        if host is None:
            raise ValueError("cookie URL must include a host")
        host = host.lower()
        request_path = parts.path or "/"
        cookies = {}
        for cookie in self.get_all_cookies():
            cookie_path = cookie.path or "/"
            if request_path != cookie_path and not request_path.startswith(cookie_path.rstrip("/") + "/"):
                continue
            if cookie.secure and parts.scheme != "https":
                continue
            if cookie.domain is None:
                lookup = urlunsplit((parts.scheme, parts.netloc, cookie_path, "", ""))
                if self.cookie_jar.get(cookie.name, lookup) is None:
                    continue
            else:
                domain = cookie.domain.lstrip(".").lower()
                if host != domain and not host.endswith("." + domain):
                    continue
            cookies[cookie.name] = cookie.value
        return cookies

    def get_all_cookies(self) -> list[Cookie]:
        return list(self.cookie_jar.get_all())

    def set_cookie(self, name: str, value: str, url: str) -> None:
        self.cookie_jar.add(Cookie(name, value, path="/"), url)

    def clear_cookies(self) -> None:
        self.cookie_jar.clear()

    def close(self) -> None:
        if not self._closed:
            self._client.close()
            self._closed = True

    def __enter__(self) -> WreqSession:
        self._ensure_active()
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()
