"""Web-focused adapters: Nikto (live + JSON import), OWASP ZAP (live REST API + JSON import), Burp (XML import)."""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx
from defusedxml import ElementTree as ET

from ..models import Finding, ToolRun, now
from .base import Adapter, Parsed, clip, sha256_file

CWE_RE = re.compile(r"(\d+)")


def _host_port(url: str) -> tuple[str, int | None]:
    u = urlparse(url if "://" in url else "http://" + url)
    return u.hostname or url, u.port or (443 if u.scheme == "https" else 80 if u.scheme == "http" else None)


class Nikto(Adapter):
    name = "nikto"
    live = True
    binary = "nikto"
    live_status = "live"
    out_ext = "json"
    import_extensions = {"json"}
    note = "Subprocess execution with -Format json; also imports Nikto JSON."
    presets = {"default": []}

    def command(self, target: str, preset: str, out: Path) -> list[str]:
        return ["nikto", "-h", target, "-Format", "json", "-output", str(out), "-ask", "no", "-nointeractive"]

    def parse(self, raw_path: Path) -> Parsed:
        raw_path = Path(raw_path)
        txt = raw_path.read_text()
        data = json.loads(txt)
        entries = data if isinstance(data, list) else [data]
        out = Parsed()
        for e in entries:
            host, port = e.get("ip") or e.get("host"), int(e.get("port") or 0) or None
            for i, v in enumerate(e.get("vulnerabilities", [])):
                msg = v.get("msg", "")
                sev = "low" if re.search(r"header|cookie|allowed methods|may be|banner|index", msg, re.I) else "medium"
                f = Finding(
                    title=clip(msg.split(".")[0], 110) or "Nikto finding", asset=host, port=port, service="http",
                    source_tools=[self.name], severity=sev, confidence=0.4, status="suspected",
                    location=v.get("url", ""), description=msg,
                    references=[f"Nikto test id {v.get('id')}"] + ([f"OSVDB-{v['OSVDB']}"] if v.get("OSVDB") not in (None, "", "0", 0) else []),
                    evidence=[self.ev(raw_path, f"host={host}/vuln={i}", f"{v.get('method','GET')} {v.get('url','')}: {msg}")])
                if re.search(r"X-Frame-Options|X-Content-Type|Strict-Transport|Content-Security", msg, re.I):
                    f.cwe, f.owasp = ["CWE-693"], ["A05:2021-Security Misconfiguration"]
                    f.solution = "Add the missing security response header at the web server or reverse proxy."
                out.findings.append(f)
        return out


ZAP_RISK = {"0": "info", "1": "low", "2": "medium", "3": "high"}
ZAP_CONF = {"0": 0.2, "1": 0.4, "2": 0.65, "3": 0.85, "4": 0.95}    # FalsePositive,Low,Medium,High,Confirmed
OWASP_BY_CWE = {"79": "A03:2021-Injection", "89": "A03:2021-Injection", "22": "A01:2021-Broken Access Control",
                "352": "A01:2021-Broken Access Control", "693": "A05:2021-Security Misconfiguration",
                "16": "A05:2021-Security Misconfiguration", "200": "A01:2021-Broken Access Control",
                "311": "A02:2021-Cryptographic Failures", "614": "A02:2021-Cryptographic Failures"}


class Zap(Adapter):
    name = "zap"
    live = True
    live_status = "live"
    out_ext = "json"
    import_extensions = {"json"}
    note = "Live via ZAP REST API (ZAP_URL, ZAP_API_KEY): spider + passive, optional active scan. Also imports JSON reports."
    presets = {"baseline": [], "active": []}
    intrusive_presets = {"active"}

    def __init__(self):
        self.url = os.environ.get("ZAP_URL", "http://127.0.0.1:8080")
        self.key = os.environ.get("ZAP_API_KEY", "")

    def available(self) -> bool:
        try:
            r = httpx.get(f"{self.url}/JSON/core/view/version/", params={"apikey": self.key}, timeout=3)
            return r.status_code == 200
        except httpx.HTTPError:
            return False

    def _api(self, path: str, **params):
        params["apikey"] = self.key
        r = httpx.get(f"{self.url}{path}", params=params, timeout=30)
        r.raise_for_status()
        return r.json()

    def run(self, target: str, preset: str, workdir: Path, timeout: int = 900) -> ToolRun:
        run = ToolRun(tool=self.name, mode="live", target=target, preset=preset, started=now(), status="running",
                      command=[f"ZAP REST {self.url}", "spider", "ascan" if preset == "active" else "passive"])
        if not self.available():
            run.status, run.error, run.finished = "unavailable", f"ZAP API not reachable at {self.url}", now()
            return run
        workdir.mkdir(parents=True, exist_ok=True)
        try:
            deadline = time.time() + timeout
            sid = self._api("/JSON/spider/action/scan/", url=target)["scan"]
            while int(self._api("/JSON/spider/view/status/", scanId=sid)["status"]) < 100:
                if time.time() > deadline:
                    raise TimeoutError("spider timed out")
                time.sleep(2)
            if preset == "active":
                aid = self._api("/JSON/ascan/action/scan/", url=target)["scan"]
                while int(self._api("/JSON/ascan/view/status/", scanId=aid)["status"]) < 100:
                    if time.time() > deadline:
                        raise TimeoutError("active scan timed out")
                    time.sleep(3)
            else:
                while int(self._api("/JSON/pscan/view/recordsToScan/")["recordsToScan"]) > 0 and time.time() < deadline:
                    time.sleep(1)
            alerts = self._api("/JSON/core/view/alerts/", baseurl=target)["alerts"]
            out = workdir / f"zap-{run.id}.json"
            out.write_text(json.dumps({"zap_api_alerts": alerts, "target": target}))
            run.raw_path, run.raw_sha256, run.status = str(out), sha256_file(out), "ok"
        except TimeoutError as e:
            run.status, run.error = "timeout", str(e)
        except (httpx.HTTPError, KeyError, ValueError) as e:
            run.status, run.error = "failed", clip(str(e), 300)
        run.finished = now()
        return run

    def parse(self, raw_path: Path) -> Parsed:
        raw_path = Path(raw_path)
        data = json.loads(raw_path.read_text())
        out = Parsed()
        items: list[tuple[str, dict]] = []
        if "zap_api_alerts" in data:                       # live API shape
            for a in data["zap_api_alerts"]:
                items.append((a.get("url", data.get("target", "")), a))
        for site in data.get("site", []):                 # traditional JSON report shape
            for a in site.get("alerts", []):
                insts = a.get("instances") or [{"uri": site.get("@name", "")}]
                for inst in insts:
                    items.append((inst.get("uri", ""), {**a, **inst}))
        for i, (uri, a) in enumerate(items):
            host, port = _host_port(uri)
            risk = ZAP_RISK.get(str(a.get("riskcode", a.get("risk_code", ""))), None)
            if risk is None:
                risk = {"informational": "info", "low": "low", "medium": "medium", "high": "high"}.get(
                    str(a.get("risk", "")).split(" ")[0].lower(), "info")
            conf = ZAP_CONF.get(str(a.get("confidence")) if str(a.get("confidence")).isdigit() else
                                {"falsepositive": "0", "low": "1", "medium": "2", "high": "3", "confirmed": "4"}.get(
                                    str(a.get("confidence", "")).split(" ")[0].lower(), "2"), 0.5)
            cwe = str(a.get("cweid", "")).strip()
            cwes = [f"CWE-{cwe}"] if cwe.isdigit() and int(cwe) > 0 else []
            ev_txt = a.get("evidence") or a.get("attack") or a.get("param") or a.get("alert", "")
            out.findings.append(Finding(
                title=a.get("alert") or a.get("name", "ZAP alert"), asset=host, port=port,
                service="https" if uri.startswith("https") else "http", source_tools=[self.name],
                severity=risk, confidence=conf, status="suspected", cwe=cwes,
                owasp=[OWASP_BY_CWE[cwe]] if cwe in OWASP_BY_CWE else [], location=uri,
                description=clip(re.sub(r"<[^>]+>", "", a.get("desc", a.get("description", ""))), 600),
                solution=clip(re.sub(r"<[^>]+>", "", a.get("solution", "")), 400),
                references=re.findall(r"https?://\S+", re.sub(r"<[^>]+>", " ", a.get("reference", "")))[:4],
                evidence=[self.ev(raw_path, f"alert={a.get('pluginid', a.get('pluginId', '?'))}/item={i}",
                                  f"{a.get('method','GET')} {uri} param={a.get('param','')} evidence={ev_txt}")]))
        return out


class Burp(Adapter):
    name = "burp"
    live = False
    live_status = "import-only"
    out_ext = "xml"
    import_extensions = {"xml"}
    note = ("Burp Suite issue-export XML import. Live scanning needs Burp Suite Professional's REST API "
            "(licensed) and is NOT implemented.")

    def parse(self, raw_path: Path) -> Parsed:
        raw_path = Path(raw_path)
        root = ET.parse(str(raw_path)).getroot()
        sev_map = {"high": "high", "medium": "medium", "low": "low", "information": "info", "info": "info"}
        conf_map = {"certain": 0.9, "firm": 0.7, "tentative": 0.35}
        out = Parsed()
        strip = lambda s: clip(re.sub(r"<[^>]+>", " ", s or ""), 600)
        for i, it in enumerate(root.findall("issue")):
            g = lambda tag: (it.findtext(tag) or "").strip()
            host_el = it.find("host")
            ip = (host_el.get("ip") if host_el is not None else None) or g("host")
            host_name = g("host")
            url = host_name + g("path")
            _, port = _host_port(host_name)
            cls = g("vulnerabilityClassifications")
            cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", cls)))
            cwes = sorted({f"CWE-{m}" for m in re.findall(r"CWE-(\d+)", cls)})
            out.findings.append(Finding(
                title=g("name"), asset=ip or host_name, port=port, service="http", source_tools=[self.name],
                severity=sev_map.get(g("severity").lower(), "info"), cve=cves, cwe=cwes, location=url,
                confidence=conf_map.get(g("confidence").lower(), 0.5), status="suspected",
                owasp=[OWASP_BY_CWE[c[4:]] for c in cwes if c[4:] in OWASP_BY_CWE],
                description=strip(g("issueBackground") + " " + g("issueDetail")),
                solution=strip(g("remediationBackground")),
                evidence=[self.ev(raw_path, f"issue={g('serialNumber') or i}", f"{g('name')} at {url} ({g('location')})")]))
        return out
