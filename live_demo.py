#!/usr/bin/env python3
"""LIVE scanning demo. Runs real Nmap + real Nikto subprocesses against 127.0.0.1 only
(this machine's own loopback interface, serving a throwaway local HTTP server started below) --
never against any third-party or public host. This exercises the actual subprocess wiring in
vapt_agent/adapters/{nmap,web}.py, not just the parsers.

Usage: .venv/bin/python live_demo.py
"""
import http.server
import socketserver
import threading
import time
from pathlib import Path

from vapt_agent.audit import AuditLog
from vapt_agent.models import ScopeModel
from vapt_agent.orchestrator import Orchestrator

ROOT = Path(__file__).parent
DATA = ROOT / "data"
PORT = 8080


def start_local_http_server() -> socketserver.TCPServer:
    """A throwaway static file server on 127.0.0.1 so there is a real, local, owned HTTP
    service to scan -- not scanme.nmap.org or any other third-party system."""
    handler = http.server.SimpleHTTPRequestHandler
    httpd = socketserver.TCPServer(("127.0.0.1", PORT), handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd


def main():
    httpd = start_local_http_server()
    time.sleep(0.3)
    print(f"[+] Local test HTTP server up on http://127.0.0.1:{PORT}/ (this machine only)")

    audit = AuditLog(DATA / "live_audit.log")
    orch = Orchestrator(DATA, audit)

    scope = ScopeModel(
        targets=["127.0.0.1"],
        lab_attestation=True,            # scanning only this machine's own loopback interface
        allow_active_validation=False,   # no Metasploit in this live demo
        allowed_tools=["nmap", "nikto"],
        permissions_note="Self-test: scanning only 127.0.0.1 (this machine's loopback).",
    )
    a = orch.create("Run a live discovery and web-server check against the local test service.", scope)
    print(f"[+] Assessment {a.id}: {len(a.plan)} initial step(s)")

    discovery = next(s for s in a.plan if s.tool == "nmap")
    orch.approve_step(a, discovery.id, True)
    run = orch.run_step(a, discovery.id)
    print(f"[+] LIVE nmap run: status={run.status} command={' '.join(run.command)}")
    if run.status != "ok":
        print(f"    error: {run.error}")
        return
    print(f"    -> {run.services} service(s), {run.findings} finding(s) discovered on 127.0.0.1")

    web_steps = [s for s in a.plan if s.tool == "nikto" and s.status == "proposed"]
    if not web_steps:
        print("[!] nmap did not identify the local HTTP port as a web service; adjust PORT/presets.")
    for s in web_steps:
        orch.approve_step(a, s.id, True)
        run2 = orch.run_step(a, s.id)
        print(f"[+] LIVE nikto run against {s.target}: status={run2.status} "
              f"findings={run2.findings}" + (f" error={run2.error}" if run2.error else ""))

    orch.analyse(a)
    print(f"[+] Correlated into {len(a.findings)} finding(s):")
    for f in a.findings:
        print(f"    [{f.priority} {f.severity:>8}] {f.title} (tools={','.join(f.source_tools)})")

    ok, msg = audit.verify()
    print(f"[+] Audit trail: {msg}")
    httpd.shutdown()


if __name__ == "__main__":
    main()
