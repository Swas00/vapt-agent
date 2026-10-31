"""Exercises the REAL HTTP control flow in adapters/web.py:Zap.run() (polling spider status,
passive-scan queue, then fetching alerts) against a tiny local stub that implements ZAP's own
documented REST contract on 127.0.0.1. This proves the live-wiring code path end-to-end without
downloading or running the actual ZAP application (which this environment cannot install).
A real ZAP daemon is a drop-in replacement: same endpoints, same JSON shapes.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

import pytest

from vapt_agent.adapters.web import Zap

ALERTS = [{
    "pluginid": "40012", "alert": "Cross Site Scripting (Reflected)", "riskcode": "3", "confidence": "2",
    "cweid": "79", "url": "http://127.0.0.1:9321/search?q=x", "method": "GET", "param": "q",
    "desc": "<p>Reflected XSS.</p>", "solution": "<p>Encode output.</p>", "reference": "",
}]


class FakeZapHandler(BaseHTTPRequestHandler):
    status_calls = {"spider": 0, "pscan": 0}

    def _json(self, payload: dict):
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - http.server API
        path = urlparse(self.path).path
        if path == "/JSON/core/view/version/":
            self._json({"version": "fake-2.0"})
        elif path == "/JSON/spider/action/scan/":
            self._json({"scan": "0"})
        elif path == "/JSON/spider/view/status/":
            FakeZapHandler.status_calls["spider"] += 1
            done = FakeZapHandler.status_calls["spider"] >= 2
            self._json({"status": "100" if done else "40"})
        elif path == "/JSON/pscan/view/recordsToScan/":
            FakeZapHandler.status_calls["pscan"] += 1
            left = 0 if FakeZapHandler.status_calls["pscan"] >= 2 else 3
            self._json({"recordsToScan": str(left)})
        elif path == "/JSON/core/view/alerts/":
            self._json({"alerts": ALERTS})
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):  # silence
        pass


@pytest.fixture
def fake_zap():
    FakeZapHandler.status_calls = {"spider": 0, "pscan": 0}
    server = HTTPServer(("127.0.0.1", 0), FakeZapHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


def test_zap_live_run_against_real_rest_contract(fake_zap, tmp_path, monkeypatch):
    monkeypatch.setenv("ZAP_URL", fake_zap)
    monkeypatch.setenv("ZAP_API_KEY", "test-key")
    z = Zap()
    assert z.available()  # real GET against the fake daemon's version endpoint

    run = z.run("http://127.0.0.1:9321", "baseline", tmp_path, timeout=10)
    assert run.status == "ok", run.error
    assert run.raw_path and Path_exists(run.raw_path)

    parsed = z.parse(run.raw_path)
    assert len(parsed.findings) == 1
    assert parsed.findings[0].title == "Cross Site Scripting (Reflected)"
    assert parsed.findings[0].severity == "high"


def Path_exists(p: str) -> bool:
    from pathlib import Path
    return Path(p).exists()
