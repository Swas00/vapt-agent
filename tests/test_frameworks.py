"""Tests for the MITRE ATT&CK tagging / NIST CSF alignment module.

The property under test that matters most: tagging is conservative. A finding with no CWE match
and no title match gets nothing -- there is no blanket "tag everything" fallback, and nothing here
ever claims exploitation was observed, only that a reference mapping exists.
"""
from __future__ import annotations

from vapt_agent import frameworks
from vapt_agent.models import Finding


def test_ms17_010_tagged_via_title():
    f = Finding(title="MS17-010 (EternalBlue) SMB vulnerability", asset="10.10.10.5", port=445,
               severity="critical", cve=["CVE-2017-0143"])
    tags = frameworks.tag_finding(f)
    assert any(t.startswith("T1210") for t in tags)


def test_sql_injection_tagged_via_cwe():
    f = Finding(title="SQL injection", asset="10.10.10.5", port=80, severity="high", cwe=["CWE-89"])
    tags = frameworks.tag_finding(f)
    assert any(t.startswith("T1190") for t in tags)


def test_sql_injection_tagged_via_title_without_cwe():
    f = Finding(title="Possible SQL Injection in login form", asset="10.10.10.5", severity="high")
    tags = frameworks.tag_finding(f)
    assert any(t.startswith("T1190") for t in tags)


def test_xss_tagged():
    f = Finding(title="Cross Site Scripting (Reflected)", asset="10.10.10.5", port=80, severity="high")
    tags = frameworks.tag_finding(f)
    assert any(t.startswith("T1190") for t in tags)


def test_anonymous_ftp_tagged_valid_accounts():
    f = Finding(title="Anonymous FTP login allowed", asset="10.10.10.5", port=21, severity="medium")
    tags = frameworks.tag_finding(f)
    assert any(t.startswith("T1078") for t in tags)


def test_unrelated_finding_gets_no_tag():
    f = Finding(title="Weak TLS protocol or cipher configuration", asset="10.10.10.5", port=443,
               severity="medium")
    assert frameworks.tag_finding(f) == []


def test_generic_info_finding_gets_no_tag():
    f = Finding(title="Exposed network service: ssh OpenSSH 7.2p2 on 22/tcp", asset="10.10.10.5",
               port=22, severity="info")
    assert frameworks.tag_finding(f) == []


def test_apply_sets_field_and_records_inference():
    f = Finding(title="SQL injection", asset="10.10.10.5", port=80, severity="high", cwe=["CWE-89"])
    frameworks.apply([f])
    assert f.mitre_attack and f.mitre_attack[0].startswith("T1190")
    assert any("[inference]" in i and "MITRE ATT&CK" in i for i in f.inference)


def test_apply_does_not_duplicate_or_overwrite_existing_tags():
    f = Finding(title="SQL injection", asset="10.10.10.5", severity="high", cwe=["CWE-89"],
               mitre_attack=["T9999 — Already tagged by something else"])
    frameworks.apply([f])
    assert f.mitre_attack == ["T9999 — Already tagged by something else"]


def test_apply_leaves_unrelated_findings_untouched():
    f = Finding(title="Weak TLS protocol or cipher configuration", asset="10.10.10.5", severity="medium")
    frameworks.apply([f])
    assert f.mitre_attack == []
    assert not any("MITRE" in i for i in f.inference)


def test_csf_alignment_note_mentions_all_five_functions():
    for fn in frameworks.CSF_FUNCTIONS:
        assert fn.upper() in frameworks.CSF_ALIGNMENT_NOTE.upper()
