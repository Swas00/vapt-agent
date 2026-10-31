from pathlib import Path

from vapt_agent.adapters.infra import Nessus, OpenVAS
from vapt_agent.adapters.nmap import Nmap
from vapt_agent.adapters.web import Burp, Nikto, Zap

FIX = Path(__file__).parent / "fixtures"


def test_nmap_parses_services_and_vulns():
    parsed = Nmap().parse(FIX / "nmap_sample.xml")
    ports = {s.port for s in parsed.services}
    assert {21, 22, 80, 443, 445} <= ports
    titles = [f.title for f in parsed.findings]
    assert any("Anonymous FTP" in t for t in titles)
    assert any("MS17-010" in t or "EternalBlue" in t for t in titles)
    cves = {c for f in parsed.findings for c in f.cve}
    assert "CVE-2021-41773" in cves
    # every finding carries evidence pointing back to the raw file
    assert all(f.evidence for f in parsed.findings)


def test_nikto_parses_vulnerabilities():
    parsed = Nikto().parse(FIX / "nikto_sample.json")
    assert len(parsed.findings) == 3
    assert all(f.asset == "10.10.10.5" for f in parsed.findings)


def test_zap_parses_alerts_and_maps_owasp():
    parsed = Zap().parse(FIX / "zap_sample.json")
    titles = {f.title for f in parsed.findings}
    assert "Cross Site Scripting (Reflected)" in titles
    xss = next(f for f in parsed.findings if "Cross Site" in f.title)
    assert xss.severity == "high"
    assert xss.owasp and "A03" in xss.owasp[0]


def test_burp_parses_issue_xml():
    parsed = Burp().parse(FIX / "burp_sample.xml")
    assert len(parsed.findings) == 1
    f = parsed.findings[0]
    assert f.severity == "high"
    assert "CWE-89" in f.cwe


def test_nessus_parses_nessus_file():
    parsed = Nessus().parse(FIX / "nessus_sample.nessus")
    assert len(parsed.findings) == 1
    f = parsed.findings[0]
    assert f.cve == ["CVE-2017-0143"]
    assert f.cvss == 8.1
    assert f.exploit_available is True


def test_openvas_parses_xml():
    parsed = OpenVAS().parse(FIX / "openvas_sample.xml")
    assert len(parsed.findings) == 1
    assert parsed.findings[0].severity == "medium"
