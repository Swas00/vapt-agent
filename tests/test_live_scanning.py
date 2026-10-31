"""Live subprocess wiring for Nmap + Nikto against 127.0.0.1 only (never a third-party/public host).
Skipped automatically when the binaries aren't installed, so the rest of the suite stays portable.
"""
from __future__ import annotations

import http.server
import shutil
import socketserver
import threading
import time

import pytest

from vapt_agent.adapters.nmap import Nmap
from vapt_agent.adapters.web import Nikto

HAVE_NMAP = shutil.which("nmap") is not None
HAVE_NIKTO = shutil.which("nikto") is not None


TEST_PORT = 8080  # must be inside nmap's --top-ports 1000 list for the discovery preset to see it


@pytest.fixture(scope="module")
def local_http_server():
    class ReusableServer(socketserver.TCPServer):
        allow_reuse_address = True

    httpd = ReusableServer(("127.0.0.1", TEST_PORT), http.server.SimpleHTTPRequestHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    time.sleep(0.2)
    yield TEST_PORT
    httpd.shutdown()


@pytest.mark.skipif(not HAVE_NMAP, reason="nmap not installed")
def test_live_nmap_discovers_loopback_service(local_http_server, tmp_path):
    run = Nmap().run("127.0.0.1", "discovery", tmp_path, timeout=60)
    assert run.status == "ok", run.error
    parsed = Nmap().parse(run.raw_path)
    assert any(s.port == local_http_server for s in parsed.services)


@pytest.mark.skipif(not HAVE_NIKTO, reason="nikto not installed")
def test_live_nikto_scans_loopback_http(local_http_server, tmp_path):
    target = f"http://127.0.0.1:{local_http_server}"
    run = Nikto().run(target, "default", tmp_path, timeout=60)
    assert run.status == "ok", run.error
    parsed = Nikto().parse(run.raw_path)
    assert len(parsed.findings) > 0
