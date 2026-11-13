"""Tests for the web-audit modules using a local throwaway HTTP server.

These exercise the real request/parse paths against a controlled server, so no
external network or authorization is involved — everything is 127.0.0.1.
"""
from __future__ import annotations

import http.server
import socketserver
import threading
import time

import pytest

from sentinel.core.scope import Scope
from sentinel.modules.base import ModuleContext
from sentinel.modules.base import get_module
from sentinel.core.models import Target


class _App(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, PUT, DELETE, OPTIONS")
        self.end_headers()

    def do_GET(self):
        if self.path == "/.env":
            body = b"SECRET_KEY=supersecret\nDB_PASSWORD=hunter2\n"
            self.send_response(200); self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body); return
        if self.path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /admin\n"
            self.send_response(200); self.end_headers(); self.wfile.write(body); return
        # default HTML page with a form and a link
        body = (b"<html><body><a href='/page2'>next</a>"
                b"<form action='/login' method='post'><input name='user'></form>"
                b"</body></html>")
        self.send_response(200); self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def server():
    srv = socketserver.TCPServer(("127.0.0.1", 0), _App)
    srv.allow_reuse_address = True
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    yield port
    srv.shutdown()


def _ctx():
    scope = Scope.from_dict({
        "engagement": "t", "authorized_by": "me",
        "authorized_until": "2999-01-01", "targets": ["127.0.0.1"],
    })
    return ModuleContext(scope=scope, timeout=2.0)


def _patch_webports(port, monkeypatch):
    # Point the web modules' port map at our ephemeral test port.
    import sentinel.modules.http_audit as ha
    monkeypatch.setattr(ha, "WEB_PORTS", {port: "http"})
    import sentinel.modules.webcrawl as wc
    monkeypatch.setattr(wc, "WEB_PORTS", {port: "http"})
    import sentinel.modules.exposure as ex
    monkeypatch.setattr(ex, "WEB_PORTS", {port: "http"})


def test_exposure_finds_env_file(server, monkeypatch):
    _patch_webports(server, monkeypatch)
    findings = get_module("exposure").run(Target("127.0.0.1", "127.0.0.1"), _ctx())
    titles = [f.title for f in findings]
    assert any(".env" in t for t in titles)
    # risky methods advertised via OPTIONS should be caught too
    assert any("risky HTTP methods" in t for t in titles)


def test_webcrawl_finds_form_and_robots(server, monkeypatch):
    _patch_webports(server, monkeypatch)
    findings = get_module("webcrawl").run(Target("127.0.0.1", "127.0.0.1"), _ctx())
    titles = " | ".join(f.title for f in findings)
    assert "form(s) found" in titles
    assert "robots.txt present" in titles
