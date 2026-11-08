"""Serialize wreq cookie jars without losing host-only origins."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit

from wreq import Cookie, Jar, SameSite


def _origin(url: str, path: str = "/") -> str:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or parts.hostname is None:
        raise ValueError(f"cookie origin must be an HTTP(S) URL: {url!r}")
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def dump_cookie_jar(jar: Jar, origins: Iterable[str]) -> list[dict[str, Any]]:
    origins = [_origin(origin) for origin in origins]
    snapshots = []
    for cookie in jar.get_all():
        path = cookie.path or "/"
        if cookie.domain is not None:
            origin = _origin(f"https://{cookie.domain.lstrip('.')}", path)
        else:
            candidates = [_origin(item, path) for item in origins]
            origin = next((candidate for candidate in candidates if jar.get(cookie.name, candidate) is not None), None)
            if origin is None:
                raise RuntimeError(f"cannot determine host-only origin for cookie {cookie.name!r}")
        snapshots.append({
            "name": cookie.name,
            "value": cookie.value,
            "domain": cookie.domain,
            "path": cookie.path,
            "maxAge": cookie.max_age.total_seconds() if cookie.max_age is not None else None,
            "expires": cookie.expires.isoformat() if cookie.expires is not None else None,
            "httpOnly": cookie.http_only,
            "secure": cookie.secure,
            "sameSite": "lax" if cookie.same_site_lax else "strict" if cookie.same_site_strict else None,
            "url": origin,
        })
    return snapshots


def restore_cookie_jar(jar: Jar, snapshots: Iterable[Mapping[str, Any]]) -> None:
    jar.clear()
    for snapshot in snapshots:
        same_site = snapshot.get("sameSite")
        cookie = Cookie(
            snapshot["name"],
            snapshot["value"],
            domain=snapshot.get("domain"),
            path=snapshot.get("path"),
            max_age=timedelta(seconds=snapshot["maxAge"]) if snapshot.get("maxAge") is not None else None,
            expires=datetime.fromisoformat(snapshot["expires"]) if snapshot.get("expires") is not None else None,
            http_only=snapshot.get("httpOnly"),
            secure=snapshot.get("secure"),
            same_site=SameSite.Lax if same_site == "lax" else SameSite.Strict if same_site == "strict" else None,
        )
        jar.add(cookie, _origin(snapshot["url"], cookie.path or "/"))
