"""Client-ready VAPT PDF report covering every section the problem statement requires:
executive summary, methodology/RoE/assets/tool summary, severity distribution, detailed findings
with evidence, impact & remediation, and limitations/assumptions/approvals/timestamps.
"""
from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)

from .adapters import integration_matrix
from .llm import summarize_assessment
from .models import Assessment, Finding

SEV_COLOR = {"critical": colors.HexColor("#7f1d1d"), "high": colors.HexColor("#c2410c"),
             "medium": colors.HexColor("#a16207"), "low": colors.HexColor("#15803d"),
             "info": colors.HexColor("#334155")}


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("H1", parent=ss["Heading1"], spaceAfter=10))
    ss.add(ParagraphStyle("H2", parent=ss["Heading2"], spaceBefore=14, spaceAfter=6))
    ss.add(ParagraphStyle("Body", parent=ss["BodyText"], spaceAfter=6, leading=14))
    ss.add(ParagraphStyle("Small", parent=ss["BodyText"], fontSize=8, leading=10, textColor=colors.HexColor("#475569")))
    ss.add(ParagraphStyle("Mono", parent=ss["BodyText"], fontName="Courier", fontSize=8, leading=10))
    return ss


def _finding_table_row(sev_counts: dict) -> Table:
    order = ["critical", "high", "medium", "low", "info"]
    data = [["Severity"] + [s.capitalize() for s in order],
            ["Count"] + [str(sev_counts.get(s, 0)) for s in order]]
    t = Table(data, colWidths=[2.6 * cm] + [2.2 * cm] * 5)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
    ]))
    return t


def _finding_block(f: Finding, ss) -> list:
    out = []
    color = SEV_COLOR.get(f.severity, colors.black)
    header = f'<font color="{color.hexval()}"><b>[{f.priority or "?"}] {f.severity.upper()}</b></font> — {f.title}'
    out.append(Paragraph(header, ss["H2"]))
    meta = (f"Finding ID: {f.id} &nbsp;|&nbsp; Asset: {f.asset}" +
            (f":{f.port}/{f.proto}" if f.port else "") +
            f" &nbsp;|&nbsp; Status: {f.status} &nbsp;|&nbsp; Validation: {f.validation_status} "
            f"&nbsp;|&nbsp; Confidence: {f.confidence:.2f}")
    out.append(Paragraph(meta, ss["Small"]))
    if f.cvss is not None:
        est = " (estimated from severity band, not tool-reported)" if f.cvss_estimated else ""
        out.append(Paragraph(f"CVSS: {f.cvss}{est}" + (f" ({f.cvss_vector})" if f.cvss_vector else ""), ss["Small"]))
    if f.cve or f.cwe or f.owasp:
        out.append(Paragraph("References: " + ", ".join(f.cve + f.cwe + f.owasp), ss["Small"]))
    out.append(Paragraph(f"Risk score: {f.risk_score} — " +
                         ", ".join(f"{k}={v}" for k, v in f.risk_breakdown.items() if not isinstance(v, dict)),
                         ss["Small"]))
    out.append(Paragraph(f.description or "(no description captured)", ss["Body"]))
    if f.inference:
        out.append(Paragraph("<b>AI-generated reasoning (not directly observed):</b>", ss["Body"]))
        for i in f.inference:
            out.append(Paragraph("• " + i, ss["Small"]))
    out.append(Paragraph(f"<b>Supporting evidence</b> (source tool(s): {', '.join(f.source_tools)}):", ss["Body"]))
    for e in f.evidence[:6]:
        out.append(Paragraph(f"[{e.tool} | {e.raw_ref} | {e.timestamp}]", ss["Small"]))
        out.append(Paragraph(e.snippet.replace("<", "&lt;").replace(">", "&gt;"), ss["Mono"]))
    if len(f.evidence) > 6:
        out.append(Paragraph(f"...and {len(f.evidence) - 6} more evidence item(s) in the audit log.", ss["Small"]))
    if f.solution:
        out.append(Paragraph(f"<b>Remediation:</b> {f.solution}", ss["Body"]))
    if f.references:
        out.append(Paragraph("References: " + "; ".join(f.references), ss["Small"]))
    if f.merged_from:
        out.append(Paragraph(f"(Deduplicated: merged {len(f.merged_from)} overlapping report(s) from "
                             f"{', '.join(f.source_tools)}.)", ss["Small"]))
    out.append(Spacer(1, 8))
    return out


def generate(a: Assessment, out_path: Path) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(str(out_path), pagesize=A4, topMargin=1.6 * cm, bottomMargin=1.6 * cm)
    ss = _styles()
    story = []

    story.append(Paragraph("Vulnerability Assessment &amp; Penetration Test Report", ss["H1"]))
    story.append(Paragraph(f"Assessment ID: {a.id} &nbsp;|&nbsp; Generated: {a.created}", ss["Small"]))
    story.append(Spacer(1, 10))

    story.append(Paragraph("1. Executive Summary", ss["H2"]))
    story.append(Paragraph(summarize_assessment(a, a.findings), ss["Body"]))
    story.append(Paragraph(f"Scope: {', '.join(a.scope.targets)}", ss["Small"]))
    story.append(Paragraph(f"Original request: “{a.request}”", ss["Small"]))

    story.append(Paragraph("2. Assessment Methodology", ss["H2"]))
    story.append(Paragraph(
        "This assessment followed a conversational, evidence-driven workflow: analyst request, scope "
        "validation, agent-generated and analyst-approved scan plan, scan orchestration, result "
        "ingestion, cross-tool correlation, risk prioritization, human-approved active validation where "
        "applicable, and report generation. Methodology is informed by NIST SP 800-115, OWASP Top 10, "
        "CVE/CVSS/CWE, and MITRE ATT&CK where applicable.", ss["Body"]))
    story.append(Paragraph("Rules of engagement:", ss["Body"]))
    roe = (f"Authorized targets: {', '.join(a.scope.targets)}. Exclusions: "
          f"{', '.join(a.scope.exclusions) or 'none'}. Active validation permitted: "
          f"{a.scope.allow_active_validation}. {a.scope.permissions_note}")
    story.append(Paragraph(roe, ss["Small"]))
    story.append(Paragraph("Tool execution summary:", ss["Body"]))
    rows = [["Tool", "Mode", "Target", "Status", "Services", "Findings"]]
    for r in a.runs:
        rows.append([r.tool, r.mode, r.target[:40], r.status, str(r.services), str(r.findings)])
    t = Table(rows, colWidths=[2.3 * cm, 1.6 * cm, 6.5 * cm, 2 * cm, 1.8 * cm, 1.8 * cm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                          ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                          ("FONTSIZE", (0, 0), (-1, -1), 7.5)]))
    story.append(t)

    story.append(Paragraph("3. Severity Distribution and Prioritized Findings", ss["H2"]))
    counts: dict[str, int] = {}
    for f in a.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    story.append(_finding_table_row(counts))
    story.append(Spacer(1, 6))
    prio_rows = [["Priority", "Severity", "Title", "Asset", "Risk score"]]
    for f in a.findings[:25]:
        prio_rows.append([f.priority or "-", f.severity, f.title[:46], f.asset, str(f.risk_score)])
    pt = Table(prio_rows, colWidths=[1.6 * cm, 2 * cm, 7.5 * cm, 3.5 * cm, 2 * cm])
    pt.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                           ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                           ("FONTSIZE", (0, 0), (-1, -1), 7.5)]))
    story.append(pt)
    story.append(PageBreak())

    story.append(Paragraph("4. Detailed Vulnerability Findings", ss["H2"]))
    for f in a.findings:
        story.extend(_finding_block(f, ss))

    story.append(Paragraph("5. Impact and Remediation Summary", ss["H2"]))
    crit_high = [f for f in a.findings if f.severity in ("critical", "high")]
    if crit_high:
        story.append(Paragraph(
            f"{len(crit_high)} finding(s) rated critical/high pose immediate business risk (data exposure, "
            "service compromise, or unauthorized access) and should be remediated before the system handles "
            "production or sensitive data.", ss["Body"]))
        for f in crit_high[:15]:
            story.append(Paragraph(f"• <b>{f.title}</b> ({f.asset}): {f.solution or 'See detailed finding above.'}",
                                   ss["Small"]))
    else:
        story.append(Paragraph("No critical or high severity findings were identified in this assessment.",
                               ss["Body"]))

    story.append(Paragraph("6. Assessment Limitations", ss["H2"]))
    for lim in (a.limitations or ["None recorded."]):
        story.append(Paragraph("• " + lim, ss["Small"]))
    story.append(Paragraph("Assumptions:", ss["Body"]))
    story.append(Paragraph(f"• LLM reasoning mode: {a.llm_mode}. " +
                           (" ".join(a.llm_notes) if a.llm_notes else ""), ss["Small"]))
    story.append(Paragraph("• CVSS scores marked 'estimated' were derived from the source tool's severity "
                          "band, not independently calculated.", ss["Small"]))
    story.append(Paragraph("Human approvals and outcomes:", ss["Body"]))
    if a.approvals:
        for ap in a.approvals:
            story.append(Paragraph(f"• [{ap.state}] {ap.action} — decided by {ap.decided_by or 'n/a'} "
                                   f"at {ap.decided_at or 'n/a'}; outcome: {ap.outcome or 'n/a'}", ss["Small"]))
    else:
        story.append(Paragraph("• No active validation was requested or approved in this assessment.", ss["Small"]))
    story.append(Paragraph(f"Assessment timestamps: created {a.created}; report generated at report time.",
                          ss["Small"]))

    story.append(Paragraph("7. Tool Integration Status (Transparency Matrix)", ss["H2"]))
    im_rows = [["Tool", "Status", "Executable now", "Note"]]
    for row in integration_matrix():
        im_rows.append([row["tool"], row["status"], str(row["live_executable_now"]), row["note"][:70]])
    imt = Table(im_rows, colWidths=[2.2 * cm, 2.2 * cm, 2.4 * cm, 10 * cm])
    imt.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                            ("FONTSIZE", (0, 0), (-1, -1), 7)]))
    story.append(imt)

    doc.build(story)
    return out_path
