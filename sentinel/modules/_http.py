"""Shared HTTP helper for the web-audit modules.

Deliberately uses an *unverified* TLS context: the goal is to read a server's
configuration and content, not to trust it. All requests are plain GET/HEAD —
Sentinel never submits payloads or attempts exploitation.
"""
from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass
class HttpResponse:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    error: str | None = None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def header(self, name: str) -> str | None:
        low = name.lower()
        for k, v in self.headers.items():
            if k.lower() == low:
                return v
        return None


def _unverified_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch(url: str, timeout: float = 5.0, method: str = "GET",
          max_bytes: int = 262_144, headers: dict | None = None,
          allow_redirects: bool = True) -> HttpResponse:
    """Fetch a URL. 4xx/5xx come back as a normal response, not an exception."""
    req_headers = {"User-Agent": "sentinel-audit/0.2 (authorized-audit)"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, method=method, headers=req_headers)

    handlers = [urllib.request.HTTPSHandler(context=_unverified_ctx())]
    if not allow_redirects:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)

    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(max_bytes) if method != "HEAD" else b""
            return HttpResponse(url, resp.status, dict(resp.headers.items()), body)
    except urllib.error.HTTPError as exc:
        # HTTPError *is* a response: capture its status/headers/body.
        try:
            body = exc.read(max_bytes)
        except Exception:
            body = b""
        return HttpResponse(url, exc.code, dict(exc.headers.items()) if exc.headers else {}, body)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return HttpResponse(url, 0, {}, b"", error=str(exc))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None
