# Integration Status Matrix (Transparency)

Status is computed by code (`vapt_agent.adapters.integration_matrix()`), not asserted in a slide —
`live_executable_now` reflects whether the live path is actually reachable on the machine running the
agent at report time, and it appears on every generated PDF report (section 7).

| Tool | Status | How it's integrated | Known limitations |
|---|---|---|---|
| **Nmap** | **Live** | Subprocess execution (`-oX`) with curated presets (`discovery`, `vuln_http`, `ssl`, `smb_safe`, `ftp_safe`, `vulners`). NSE scripts are allow-listed to non-intrusive checks. Also imports any Nmap XML. | Requires `nmap` on `PATH`. `--max-rate` is capped from `ScopeModel.max_rate_pps`. |
| **Nessus** | **Import-only** | Parses `.nessus` (`NessusClientData_v2`) exports: CVSS, CVE, CWE, exploit-availability flag, plugin output as evidence. | Live scan control requires a licensed Nessus instance (Essentials/Pro/Expert) and its REST API; **not implemented** in this prototype — we do not claim or demonstrate live Nessus scanning. |
| **OpenVAS / Greenbone** | **Import-only** | Parses Greenbone/OpenVAS XML `get_reports` output: threat level, CVSS base, QoD-derived confidence, CVE refs. | Live control via GMP (`python-gvm`) is **planned**, not implemented — flagged honestly rather than claimed. |
| **Nikto** | **Live** | Subprocess execution (`-Format json`); also imports Nikto JSON output. | Requires `nikto` on `PATH`. Findings default to low confidence (web-config heuristics) unless corroborated by another tool. |
| **OWASP ZAP** | **Live** | REST API (`ZAP_URL`, `ZAP_API_KEY`) driving spider + passive scan by default; an explicit `active` preset (marked intrusive) runs the active scanner. Also imports ZAP JSON reports. | Requires a running ZAP daemon. Active scanning is gated behind the `intrusive_presets` flag and the scope's `allow_active_validation`. |
| **Burp Suite** | **Import-only** | Parses Burp issue-export XML (name, severity, confidence, CWE, classification, remediation). | Live scanning requires Burp Suite **Professional**'s REST API, which is licensed and was not available for this build; **not implemented**, not misrepresented as available. |
| **Metasploit** | **Live, human-approved only** | `msfconsole -x "use <analyst-named module>; set RHOSTS ...; check; exit"` — runs only after a recorded `Approval` with `state=="approved"`, only the module the analyst explicitly named, and only in Metasploit's own `check` command (non-exploitative where the module supports it). The agent never selects a module or fires autonomously. | Requires `msfconsole` on `PATH` and a lab target. Interpretation of console output ("validated" / "not_reproducible" / "inconclusive") is a simple text match on Metasploit's own `check` phrasing, not an independent proof engine. |

## Honesty notes

- "Live" above means *this codebase* can invoke the tool as a subprocess or API call on the machine
  running it — it does not claim the tool is bundled, licensed, or pre-installed for the judges.
- Commercial tools (Nessus, Burp Pro) were integrated as **import-only** specifically because their live
  control planes are licensed products we do not redistribute; we show real parsing of their real export
  formats instead of fabricating a live-looking shim.
- No finding in this system carries a CVE, CVSS score, or "validated" status that was not produced by an
  actual tool run or an actual human-approved validation step — see `models.Finding.cvss_estimated` and
  `Finding.validation_status` for how estimated vs. observed values are distinguished everywhere,
  including in the PDF report.
