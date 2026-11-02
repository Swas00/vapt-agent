"""Infrastructure vulnerability scanners (Nessus, OpenVAS/Greenbone: import-only) and gated Metasploit."""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from defusedxml import ElementTree as ET

from ..models import Approval, Finding, ToolRun, now
from .base import Adapter, Parsed, clip, sha256_file


class Nessus(Adapter):
    name = "nessus"
    live = False
    live_status = "import-only"
    out_ext = "nessus"
    import_extensions = {"nessus", "xml"}   # a .nessus file IS XML; some exporters keep the .xml name
    note = ("Imports .nessus (NessusClientData_v2) exports. Live API control needs a licensed Nessus "
            "(Essentials/Pro/Expert) instance and is NOT implemented.")

    def parse(self, raw_path: Path) -> Parsed:
        raw_path = Path(raw_path)
        root = ET.parse(str(raw_path)).getroot()
        out = Parsed()
        for rh in root.iter("ReportHost"):
            host = rh.get("name")
            for it in rh.findall("ReportItem"):
                sev_i = int(it.get("severity", "0"))
                if sev_i == 0 and it.get("pluginFamily") == "Settings":
                    continue
                g = lambda t: (it.findtext(t) or "").strip()
                cvss = g("cvss3_base_score") or g("cvss_base_score")
                cvss_f = float(cvss) if cvss else None
                sev = ["info", "low", "medium", "high", "critical"][min(sev_i, 4)]
                out.findings.append(Finding(
                    title=it.get("pluginName", "Nessus finding"), asset=host,
                    port=int(it.get("port")) or None, proto=it.get("protocol", "tcp"), service=it.get("svc_name", ""),
                    source_tools=[self.name], severity=sev, cvss=cvss_f, cvss_vector=g("cvss3_vector") or g("cvss_vector") or None,
                    cve=sorted({c.text.strip() for c in it.findall("cve") if c.text}),
                    cwe=sorted({f"CWE-{re.sub(r'[^0-9]', '', c.text)}" for c in it.findall("cwe") if c.text}),
                    exploit_available=(g("exploit_available").lower() == "true") if g("exploit_available") else None,
                    description=clip(g("description") or g("synopsis"), 700), solution=clip(g("solution"), 400),
                    references=[x.strip() for x in g("see_also").splitlines() if x.strip()][:4],
                    confidence=0.7 if sev_i else 0.6, status="suspected",
                    evidence=[self.ev(raw_path, f"host={host}/plugin={it.get('pluginID')}",
                                      g("plugin_output") or g("synopsis") or it.get("pluginName", ""))]))
        return out


class OpenVAS(Adapter):
    name = "openvas"
    live = False
    live_status = "import-only"
    out_ext = "xml"
    import_extensions = {"xml"}
    note = ("Imports Greenbone/OpenVAS XML reports (get_reports). Live control via GMP (python-gvm) "
            "is planned, NOT implemented.")

    def parse(self, raw_path: Path) -> Parsed:
        raw_path = Path(raw_path)
        root = ET.parse(str(raw_path)).getroot()
        out = Parsed()
        for i, r in enumerate(root.iter("result")):
            g = lambda t: (r.findtext(t) or "").strip()
            host = (r.findtext("host") or "").split("\n")[0].strip()
            m = re.match(r"(\d+)/(\w+)", g("port"))
            port, proto = (int(m.group(1)), m.group(2)) if m else (None, "tcp")
            nvt = r.find("nvt")
            cvss = None
            if nvt is not None:
                cb = nvt.findtext("cvss_base") or ""
                cvss = float(cb) if re.match(r"^[0-9.]+$", cb) else None
            if cvss is None and re.match(r"^[0-9.]+$", g("severity")):
                cvss = float(g("severity"))
            threat = g("threat").lower()
            sev = {"high": "high", "medium": "medium", "low": "low", "log": "info", "alarm": "high"}.get(threat, "info")
            if cvss is not None and threat in ("high", "medium", "low"):
                sev = self.sev_from(cvss, sev)
            cves = sorted({x.get("id") for x in (nvt.iter("ref") if nvt is not None else []) if x.get("type") == "cve"})
            if not cves and nvt is not None:
                cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", ET.tostring(nvt, encoding="unicode"))))
            qod = r.findtext("qod/value")
            conf = min(0.95, int(qod) / 100) if qod and qod.isdigit() else 0.6
            out.findings.append(Finding(
                title=g("name") or (nvt.findtext("name") if nvt is not None else "OpenVAS result"),
                asset=host, port=port, proto=proto, service="", source_tools=[self.name], severity=sev, cvss=cvss,
                cve=cves, description=clip(g("description"), 700),
                solution=clip((nvt.findtext("solution") if nvt is not None else "") or "", 400),
                confidence=conf, status="suspected",
                evidence=[self.ev(raw_path, f"result={r.get('id') or i}", g("description") or g("name"))]))
        return out


class Metasploit(Adapter):
    """Controlled validation ONLY. Never runs without a recorded human approval. Module chosen by the analyst."""
    name = "metasploit"
    live = True
    binary = "msfconsole"
    live_status = "live"
    out_ext = "txt"
    note = ("Human-approved, lab-only. Executes only the analyst-named module in `check` mode (non-exploitative "
            "where the module supports it). No autonomous module selection.")

    MODULE_RE = re.compile(r"^(auxiliary|exploit|post)/[a-z0-9_/]+$")

    def validate(self, approval: Approval, target_host: str, port: int | None, workdir: Path, timeout: int = 300) -> ToolRun:
        run = ToolRun(tool=self.name, mode="live", target=target_host, preset="check", started=now(), status="running")
        if approval.state != "approved":
            run.status, run.error, run.finished = "skipped", f"approval {approval.id} is '{approval.state}'", now()
            return run
        if not self.MODULE_RE.match(approval.module):
            run.status, run.error, run.finished = "failed", "module name missing or not a valid module path", now()
            return run
        if not shutil.which(self.binary):
            run.status, run.error, run.finished = "unavailable", "msfconsole not found on PATH", now()
            return run
        workdir.mkdir(parents=True, exist_ok=True)
        out = workdir / f"metasploit-{approval.id}.txt"
        script = f"use {approval.module}; set RHOSTS {target_host};" + (f" set RPORT {port};" if port else "") + " check; exit"
        cmd = [self.binary, "-q", "-x", script]
        run.command = cmd
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)
            out.write_text(p.stdout + p.stderr)
            run.status = "ok"
        except subprocess.TimeoutExpired:
            run.status, run.error = "timeout", f"exceeded {timeout}s"
        except OSError as e:
            run.status, run.error = "failed", str(e)
        run.finished = now()
        if out.exists():
            run.raw_path, run.raw_sha256 = str(out), sha256_file(out)
        return run

    @staticmethod
    def interpret(output: str) -> str:
        t = output.lower()
        if "the target is vulnerable" in t or "appears to be vulnerable" in t:
            return "validated"
        if "is not exploitable" in t or "not vulnerable" in t or "the target is not" in t:
            return "not_reproducible"
        return "inconclusive"

    def parse(self, raw_path: Path) -> Parsed:      # validation output is not a source of new findings
        return Parsed()
