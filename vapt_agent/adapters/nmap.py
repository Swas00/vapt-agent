"""Nmap: LIVE (subprocess, -oX) and XML import. Only non-intrusive NSE scripts are allow-listed."""
from __future__ import annotations

import re
from pathlib import Path

from defusedxml import ElementTree as ET

from ..models import Finding, Service
from .base import Adapter, Parsed

CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})\s+([0-9]\.[0-9])")
CLEARTEXT = {"telnet": "CWE-319", "ftp": "CWE-319", "rsh": "CWE-319", "rlogin": "CWE-319", "tftp": "CWE-319"}


class Nmap(Adapter):
    name = "nmap"
    live = True
    binary = "nmap"
    live_status = "live"
    out_ext = "xml"
    import_extensions = {"xml"}
    note = "Subprocess execution with -oX; also imports Nmap XML. NSE restricted to non-intrusive allow-list."
    presets = {
        "discovery": ["-sV", "-Pn", "--top-ports", "1000", "--open", "-T3", "--version-light"],
        "vuln_http": ["-sV", "-Pn", "--script", "http-headers,http-methods,http-title,vulners", "-p", "{ports}"],
        "ssl": ["-Pn", "--script", "ssl-enum-ciphers,ssl-cert", "-p", "{ports}"],
        "smb_safe": ["-Pn", "--script", "smb-protocols,smb2-security-mode,smb-vuln-ms17-010", "-p", "{ports}"],
        "ftp_safe": ["-Pn", "--script", "ftp-anon,ftp-syst", "-p", "{ports}"],
        "vulners": ["-sV", "-Pn", "--script", "vulners", "-p", "{ports}"],
        # FS-7: safe, read-only NSE scripts for two services that are high-value for an attacker
        # but easy to under-prioritize in a port-count-driven plan -- DNS recursion/zone-transfer
        # misconfiguration and SNMP default/weak community strings. Neither script writes anything
        # or attempts a default-credential login; both only ask the service to describe itself.
        "dns_safe": ["-Pn", "-sU", "--script", "dns-nsid,dns-recursion", "-p", "53"],
        "snmp_safe": ["-Pn", "-sU", "--script", "snmp-info,snmp-sysdescr", "-p", "161"],
    }
    ports_default = "21,22,23,25,80,110,139,443,445,3306,5432,8080,8443"

    def command(self, target: str, preset: str, out: Path, ports: str | None = None, rate: int = 100) -> list[str]:
        if preset not in self.presets:
            raise ValueError(f"unknown nmap preset {preset}")
        args = [a.replace("{ports}", ports or self.ports_default) for a in self.presets[preset]]
        host = target.split("://")[-1].split("/")[0].split(":")[0]
        return ["nmap", *args, "--max-rate", str(rate), "-oX", str(out), host]

    def parse(self, raw_path: Path) -> Parsed:
        raw_path = Path(raw_path)
        root = ET.parse(str(raw_path)).getroot()
        out = Parsed()
        for h in root.findall("host"):
            st = h.find("status")
            if st is not None and st.get("state") != "up":
                continue
            addr = next((a.get("addr") for a in h.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
            if not addr:
                continue
            host_label = addr
            for p in h.findall("ports/port"):
                state = p.find("state")
                if state is None or state.get("state") != "open":
                    continue
                port, proto = int(p.get("portid")), p.get("protocol", "tcp")
                s = p.find("service")
                svc = Service(host=host_label, port=port, proto=proto, source_tool=self.name,
                              name=(s.get("name") if s is not None else "") or "",
                              product=(s.get("product") if s is not None else "") or "",
                              version=(s.get("version") if s is not None else "") or "",
                              tunnel=(s.get("tunnel") if s is not None else "") or "")
                out.services.append(svc)
                loc = f"host={addr}/port={port}"
                banner = " ".join(x for x in (svc.name, svc.product, svc.version) if x)
                out.findings.append(Finding(
                    title=f"Exposed network service: {banner or 'unknown'} on {port}/{proto}",
                    asset=host_label, port=port, proto=proto, service=svc.name, source_tools=[self.name],
                    severity="info", confidence=0.95, status="confirmed",
                    description=f"Port {port}/{proto} is open and responded as {banner or 'an unidentified service'}.",
                    evidence=[self.ev(raw_path, loc, f"{port}/{proto} open {banner}")]))
                if svc.name in CLEARTEXT:
                    out.findings[-1].inference.append(
                        f"[inference] {svc.name} transmits credentials in cleartext (CWE-319); "
                        "an encrypted alternative should be used.")
                    out.findings[-1].cwe.append(CLEARTEXT[svc.name])
                    out.findings[-1].severity = "low"
                for sc in p.findall("script"):
                    sid, sout = sc.get("id", ""), sc.get("output", "")
                    seen = set()
                    for cve, cvss in CVE_RE.findall(sout):
                        if cve in seen:
                            continue
                        seen.add(cve)
                        c = float(cvss)
                        out.findings.append(Finding(
                            title=f"{cve} reported against {banner or svc.name}",
                            asset=host_label, port=port, proto=proto, service=svc.name, source_tools=[self.name],
                            cve=[cve], cvss=c, severity=self.sev_from(c), confidence=0.55, status="suspected",
                            description=(f"NSE script '{sid}' associated {cve} with the detected service "
                                         f"version ({banner}). This is version-based matching; the vulnerable code path was not exercised."),
                            evidence=[self.ev(raw_path, f"{loc}/script={sid}", f"{cve} {cvss} ({sid})")],
                            inference=["[inference] Version-based match: the vendor may have back-ported a fix."]))
                    if sid in ("ftp-anon",) and "Anonymous FTP login allowed" in sout:
                        out.findings.append(Finding(
                            title="Anonymous FTP login allowed", asset=host_label, port=port, service=svc.name,
                            source_tools=[self.name], severity="medium", cwe=["CWE-287"], confidence=0.9,
                            status="confirmed", description="The FTP server accepts anonymous logins.",
                            solution="Disable anonymous access unless explicitly required.",
                            evidence=[self.ev(raw_path, f"{loc}/script={sid}", sout)]))
                    if sid == "smb-vuln-ms17-010" and "VULNERABLE" in sout:
                        out.findings.append(Finding(
                            title="MS17-010 (EternalBlue) SMB vulnerability", asset=host_label, port=port,
                            service=svc.name, source_tools=[self.name], severity="critical", cvss=8.1,
                            cve=["CVE-2017-0143"], confidence=0.85, status="suspected",
                            description="Nmap script smb-vuln-ms17-010 reports the host as vulnerable.",
                            solution="Apply Microsoft security update MS17-010; disable SMBv1.",
                            evidence=[self.ev(raw_path, f"{loc}/script={sid}", sout)]))
                    if sid == "ssl-enum-ciphers" and re.search(r"SSLv3|TLSv1\.0|TLSv1\.1|least strength: [DEF]", sout):
                        out.findings.append(Finding(
                            title="Weak TLS protocol or cipher configuration", asset=host_label, port=port,
                            service=svc.name, source_tools=[self.name], severity="medium", cwe=["CWE-326"],
                            confidence=0.85, status="confirmed",
                            description="The server accepts deprecated TLS/SSL protocol versions or weak ciphers.",
                            solution="Disable SSLv3/TLS1.0/TLS1.1 and weak ciphers; prefer TLS 1.2+ with AEAD suites.",
                            evidence=[self.ev(raw_path, f"{loc}/script={sid}", sout)]))
        return out
