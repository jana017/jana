"""PDF (ReportLab) + Markdown + CSV + JSON export for CyberLab reports."""
from __future__ import annotations
import io
import csv
import json as _json
from datetime import datetime
from typing import Dict, Any, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_LEFT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether,
)


VERDICT_COLOR = {
    "malicious":  colors.HexColor("#DC2626"),
    "suspicious": colors.HexColor("#D97706"),
    "clean":      colors.HexColor("#059669"),
}

SEVERITY_COLOR = {
    "critical": colors.HexColor("#DC2626"),
    "high":     colors.HexColor("#EA580C"),
    "medium":   colors.HexColor("#CA8A04"),
    "low":      colors.HexColor("#2563EB"),
    "info":     colors.HexColor("#475569"),
}


def _mk_styles():
    ss = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("Title", parent=ss["Title"], fontSize=20, textColor=colors.HexColor("#0F172A"), spaceAfter=6),
        "sub":   ParagraphStyle("Sub", parent=ss["Normal"], fontSize=10, textColor=colors.HexColor("#64748B"), spaceAfter=12),
        "h2":    ParagraphStyle("H2", parent=ss["Heading2"], fontSize=13, textColor=colors.HexColor("#0F172A"), spaceBefore=14, spaceAfter=6),
        "body":  ParagraphStyle("Body", parent=ss["BodyText"], fontSize=9.5, textColor=colors.HexColor("#334155"), leading=13, alignment=TA_LEFT),
        "code":  ParagraphStyle("Code", parent=ss["Code"], fontSize=8, textColor=colors.HexColor("#0F172A"), backColor=colors.HexColor("#F1F5F9"), leading=11),
        "small": ParagraphStyle("Small", parent=ss["Normal"], fontSize=8, textColor=colors.HexColor("#64748B")),
    }


def render_pdf(report: Dict[str, Any]) -> bytes:
    """Return the analysis report as a PDF (bytes)."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm, topMargin=18*mm, bottomMargin=18*mm,
        title="NivX Forge Report",
    )
    styles = _mk_styles()
    story: List[Any] = []

    # Header
    story.append(Paragraph("NivX Machines · NivX Forge Report", styles["title"]))
    story.append(Paragraph(
        f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} · "
        f"nivxmachines.com/cyberlab",
        styles["sub"],
    ))

    # Verdict bar
    verdict = (report.get("analysis") or {}).get("verdict", "clean")
    risk = (report.get("analysis") or {}).get("risk_score", 0)
    summary = (report.get("analysis") or {}).get("summary", "No indicators observed.")
    vcolor = VERDICT_COLOR.get(verdict, colors.HexColor("#475569"))
    verdict_tbl = Table([[
        Paragraph(f"<b>Verdict · {verdict.upper()}</b>", ParagraphStyle("v", fontSize=12, textColor=colors.white)),
        Paragraph(f"<b>Risk score</b><br/><font size=18>{risk}</font><font size=8>/100</font>", ParagraphStyle("r", fontSize=10, textColor=colors.white, alignment=2)),
    ]], colWidths=[130*mm, 40*mm])
    verdict_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), vcolor),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(verdict_tbl)
    story.append(Spacer(1, 6))
    story.append(Paragraph(summary, styles["body"]))

    # AI summary if present
    ai = report.get("ai") or {}
    if ai.get("summary"):
        story.append(Paragraph("AI Analyst Summary (Claude Sonnet 4.5)", styles["h2"]))
        story.append(Paragraph(_escape(ai["summary"]), styles["body"]))

    # Input / output snippets
    if report.get("input"):
        story.append(Paragraph("Input Payload", styles["h2"]))
        story.append(Paragraph(f"<font face='Courier'>{_escape(report['input'][:2000])}</font>", styles["code"]))
    if report.get("output"):
        story.append(Paragraph("Decoded Output", styles["h2"]))
        story.append(Paragraph(f"<font face='Courier'>{_escape(report['output'][:2000])}</font>", styles["code"]))

    # Pipeline
    trace = report.get("trace") or []
    if trace:
        story.append(Paragraph("Decoding Chain", styles["h2"]))
        rows = [["#", "Operation", "Category", "Confidence", "Duration"]]
        for i, s in enumerate(trace, 1):
            rows.append([str(i), s.get("name", ""), s.get("category", ""),
                         f"{s.get('confidence','')}" if s.get("confidence") else "—",
                         f"{s.get('duration_ms',0):.1f} ms"])
        tbl = _tbl(rows, [10, 60, 40, 30, 30])
        story.append(tbl)

    # MITRE
    mitre = (report.get("analysis") or {}).get("mitre") or []
    if mitre:
        story.append(Paragraph("MITRE ATT&amp;CK Techniques", styles["h2"]))
        rows = [["ID", "Name", "Tactic"]]
        for m in mitre:
            rows.append([m["id"], m["name"], m["tactic"]])
        story.append(_tbl(rows, [25, 90, 55]))

    # Rules
    rules = (report.get("analysis") or {}).get("rules") or []
    if rules:
        story.append(Paragraph("Rule Matches", styles["h2"]))
        for r in rules:
            sev_color = SEVERITY_COLOR.get(r.get("severity"), colors.HexColor("#475569"))
            block = KeepTogether([
                Paragraph(
                    f"<b>{_escape(r['rule'])}</b>  "
                    f"<font color='{sev_color.hexval()}'>[{r.get('severity','').upper()}]</font>",
                    styles["body"],
                ),
                Paragraph(_escape(r.get("description", "")), styles["small"]),
                Spacer(1, 4),
            ])
            story.append(block)

    # IOCs
    iocs = (report.get("analysis") or {}).get("iocs") or []
    if iocs:
        story.append(Paragraph("Indicators of Compromise", styles["h2"]))
        rows = [["Type", "Value"]]
        for i in iocs[:80]:
            rows.append([i["type"].upper(), i["value"][:80]])
        story.append(_tbl(rows, [30, 140]))

    # OSINT-enriched IOCs (from CyberLab in-page enrichment)
    enriched = report.get("enriched_iocs") or []
    if enriched:
        story.append(PageBreak())
        story.append(Paragraph("OSINT Enrichment Report", styles["h2"]))
        story.append(Paragraph(
            f"{len(enriched)} indicator{'s' if len(enriched) != 1 else ''} enriched via VirusTotal, "
            "AbuseIPDB, Shodan, urlscan.io, CIRCL hashlookup, Hybrid Analysis & MalwareBazaar.",
            styles["small"],
        ))
        story.append(Spacer(1, 4))
        rows = [["IOC", "Type", "VT", "Abuse", "Geo/Host", "Verdict"]]
        for r in enriched[:80]:
            rep = r.get("reputation") or {}
            vt = rep.get("vt") or {}
            ab = rep.get("abuseipdb") or {}
            en = r.get("enrichment") or {}
            vt_txt = "—"
            if vt and not vt.get("error"):
                if vt.get("found") is False:
                    vt_txt = "0/0"
                else:
                    vt_txt = f"{vt.get('malicious', 0) or 0}/{vt.get('total', 0) or 0}"
            ab_txt = "—"
            if ab and not ab.get("error") and ab.get("score") is not None:
                ab_txt = f"{ab.get('score')}%"
            geo_txt = ""
            if en.get("kind") == "ip":
                g = en.get("geo") or {}
                geo_txt = f"{g.get('country', '')} · {g.get('isp', '')}"[:32]
            elif en.get("kind") == "web":
                geo_txt = f"{en.get('resolved_ip', '') or ''}"[:32]
            elif en.get("kind") == "hash":
                geo_txt = "known-file DB" if en.get("found") else "unknown"
            # Verdict inference
            vt_hits = (vt.get("malicious", 0) or 0) + (vt.get("suspicious", 0) or 0) if not vt.get("error") else 0
            ab_score = (ab.get("score", 0) or 0) if not ab.get("error") else 0
            if vt.get("malicious", 0) >= 5 or ab_score >= 75:
                verdict = "CRITICAL"
            elif vt_hits > 0 or ab_score >= 50:
                verdict = "HIGH"
            elif vt_hits > 0 or ab_score > 0:
                verdict = "SUSPECT"
            else:
                verdict = "CLEAN"
            rows.append([
                r.get("value", "")[:36],
                (r.get("type", "unknown") or "unknown").upper(),
                vt_txt, ab_txt, geo_txt, verdict,
            ])
        story.append(_tbl(rows, [55, 18, 18, 18, 42, 20]))

        # Per-IOC AI verdicts (if the depth included AI)
        with_ai = [r for r in enriched if (r.get("ai_summary") or "").strip()]
        if with_ai:
            story.append(Paragraph("AI Verdicts (per IOC)", styles["h2"]))
            for r in with_ai[:20]:
                block = KeepTogether([
                    Paragraph(f"<b>{_escape(r.get('value', ''))}</b>", styles["body"]),
                    Paragraph(_escape((r.get("ai_summary") or "")[:600]), styles["small"]),
                    Spacer(1, 4),
                ])
                story.append(block)

    # Draft rules from AI
    if ai.get("sigma_rule"):
        story.append(PageBreak())
        story.append(Paragraph("Draft Sigma Rule", styles["h2"]))
        story.append(Paragraph(f"<font face='Courier'>{_escape(ai['sigma_rule'])}</font>", styles["code"]))
    if ai.get("yara_rule"):
        story.append(Paragraph("Draft YARA Rule", styles["h2"]))
        story.append(Paragraph(f"<font face='Courier'>{_escape(ai['yara_rule'])}</font>", styles["code"]))

    # Footer
    story.append(Spacer(1, 20))
    story.append(Paragraph(
        "Report generated by NivX Machines · NivX Forge · This is a machine-assisted triage report — always human-review before production deployment.",
        styles["small"],
    ))

    doc.build(story)
    return buf.getvalue()


def _tbl(rows, widths_mm):
    tbl = Table(rows, colWidths=[w*mm for w in widths_mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E2E8F0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return tbl


def _escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>")


# --------------------------- Markdown export ---------------------------

def render_markdown(report: Dict[str, Any]) -> str:
    """Return the analysis as a Markdown document."""
    analysis = report.get("analysis") or {}
    ai = report.get("ai") or {}
    lines: List[str] = []
    lines.append("# NivX Forge Analysis Report")
    lines.append(f"_Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} · nivxmachines.com/cyberlab_")
    lines.append("")

    verdict = analysis.get("verdict", "clean").upper()
    risk = analysis.get("risk_score", 0)
    lines.append(f"## Verdict: **{verdict}** — Risk score `{risk}/100`")
    lines.append("")
    if analysis.get("summary"):
        lines.append(f"> {analysis['summary']}")
        lines.append("")

    if ai.get("summary"):
        lines.append("## AI Analyst Summary (Claude Sonnet 4.5)")
        lines.append(ai["summary"])
        lines.append("")

    if report.get("input"):
        lines.append("## Input Payload")
        lines.append("```")
        lines.append(report["input"][:4000])
        lines.append("```")
        lines.append("")

    if report.get("output"):
        lines.append("## Decoded Output")
        lines.append("```")
        lines.append(report["output"][:4000])
        lines.append("```")
        lines.append("")

    trace = report.get("trace") or []
    if trace:
        lines.append("## Decoding Chain")
        lines.append("| # | Operation | Category | Confidence | Duration |")
        lines.append("|---|-----------|----------|-----------|----------|")
        for i, s in enumerate(trace, 1):
            lines.append(f"| {i} | {s.get('name','')} | {s.get('category','')} | "
                         f"{s.get('confidence','—')} | {s.get('duration_ms', 0):.1f} ms |")
        lines.append("")

    mitre = analysis.get("mitre") or []
    if mitre:
        lines.append("## MITRE ATT&CK Techniques")
        for m in mitre:
            lines.append(f"- **[{m['id']}]({'https://attack.mitre.org/techniques/' + m['id'].replace('.','/') + '/'})**"
                         f" — {m['name']} · _{m['tactic']}_")
            for ev in (m.get("evidence") or [])[:3]:
                lines.append(f"   - `{ev}`")
        lines.append("")

    rules = analysis.get("rules") or []
    if rules:
        lines.append("## Rule Matches")
        for r in rules:
            lines.append(f"- **{r['rule']}** — _{r.get('severity','').upper()}_ · tags: `{', '.join(r.get('tags', []))}`")
            if r.get("description"):
                lines.append(f"  - {r['description']}")
        lines.append("")

    iocs = analysis.get("iocs") or []
    if iocs:
        lines.append("## Indicators of Compromise")
        lines.append("| Type | Value |")
        lines.append("|------|-------|")
        for i in iocs[:100]:
            v = i["value"].replace("|", "\\|")
            lines.append(f"| `{i['type']}` | `{v}` |")
        lines.append("")

    enriched = report.get("enriched_iocs") or []
    if enriched:
        lines.append("## OSINT Enrichment Report")
        lines.append(f"_{len(enriched)} IOC(s) enriched via VirusTotal, AbuseIPDB, Shodan, urlscan.io, "
                     "CIRCL hashlookup, Hybrid Analysis & MalwareBazaar._")
        lines.append("")
        lines.append("| IOC | Type | VT (mal/total) | Abuse | Geo/Host | Verdict |")
        lines.append("|-----|------|----------------|-------|----------|---------|")
        for r in enriched[:100]:
            rep = r.get("reputation") or {}
            vt = rep.get("vt") or {}
            ab = rep.get("abuseipdb") or {}
            en = r.get("enrichment") or {}
            vt_txt = "—"
            if vt and not vt.get("error"):
                vt_txt = "0/0" if vt.get("found") is False else f"{vt.get('malicious', 0) or 0}/{vt.get('total', 0) or 0}"
            ab_txt = "—"
            if ab and not ab.get("error") and ab.get("score") is not None:
                ab_txt = f"{ab.get('score')}%"
            geo_txt = ""
            if en.get("kind") == "ip":
                g = en.get("geo") or {}
                geo_txt = f"{g.get('country', '')} · {g.get('isp', '')}"
            elif en.get("kind") == "web":
                geo_txt = f"{en.get('resolved_ip', '') or ''}"
            elif en.get("kind") == "hash":
                geo_txt = "known-file DB" if en.get("found") else "unknown"
            vt_hits = (vt.get("malicious", 0) or 0) + (vt.get("suspicious", 0) or 0) if not vt.get("error") else 0
            ab_score = (ab.get("score", 0) or 0) if not ab.get("error") else 0
            if vt.get("malicious", 0) >= 5 or ab_score >= 75:
                verdict = "CRITICAL"
            elif vt_hits > 0 or ab_score >= 50:
                verdict = "HIGH"
            elif vt_hits > 0 or ab_score > 0:
                verdict = "SUSPECT"
            else:
                verdict = "CLEAN"
            val = (r.get("value", "") or "").replace("|", "\\|")
            lines.append(f"| `{val}` | {(r.get('type', 'unknown') or 'unknown').upper()} | {vt_txt} | {ab_txt} | {geo_txt} | **{verdict}** |")
        lines.append("")

        with_ai = [r for r in enriched if (r.get("ai_summary") or "").strip()]
        if with_ai:
            lines.append("### AI Verdicts (per IOC)")
            for r in with_ai[:30]:
                lines.append(f"- **`{r.get('value','')}`** — {r.get('ai_summary','').strip()}")
            lines.append("")

    if ai.get("sigma_rule"):
        lines.append("## Draft Sigma Rule")
        lines.append("```yaml")
        lines.append(ai["sigma_rule"])
        lines.append("```")
        lines.append("")
    if ai.get("yara_rule"):
        lines.append("## Draft YARA Rule")
        lines.append("```yara")
        lines.append(ai["yara_rule"])
        lines.append("```")
        lines.append("")

    lines.append("---")
    lines.append("_Machine-assisted triage report — always human-review before production deployment._")
    return "\n".join(lines)


# --------------------------- CSV export ---------------------------

def render_csv(report: Dict[str, Any]) -> str:
    """Return the CyberLab report as a CSV document.

    Sections are separated by blank rows. Includes verdict, MITRE, IOCs and
    (when present) full OSINT-enriched IOC data with reputation columns.
    """
    buf = io.StringIO()
    w = csv.writer(buf)
    analysis = report.get("analysis") or {}
    ai = report.get("ai") or {}

    # Summary header
    w.writerow(["NivX Forge Report"])
    w.writerow(["Generated (UTC)", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")])
    w.writerow(["Verdict", (analysis.get("verdict") or "").upper()])
    w.writerow(["Risk score", f"{analysis.get('risk_score', 0)}/100"])
    if analysis.get("summary"):
        w.writerow(["Summary", analysis["summary"]])
    if ai.get("summary"):
        w.writerow(["AI Summary", ai["summary"]])
    w.writerow([])

    # Decode chain
    trace = report.get("trace") or []
    if trace:
        w.writerow(["--- DECODE CHAIN ---"])
        w.writerow(["#", "Operation", "Category", "Confidence", "Duration (ms)"])
        for i, s in enumerate(trace, 1):
            w.writerow([i, s.get("name", ""), s.get("category", ""),
                        s.get("confidence") or "", s.get("duration_ms", 0)])
        w.writerow([])

    # MITRE
    mitre = analysis.get("mitre") or []
    if mitre:
        w.writerow(["--- MITRE ATT&CK ---"])
        w.writerow(["ID", "Name", "Tactic", "Evidence"])
        for m in mitre:
            w.writerow([m.get("id"), m.get("name"), m.get("tactic"),
                        " | ".join((m.get("evidence") or [])[:3])])
        w.writerow([])

    # Plain IOCs
    iocs = analysis.get("iocs") or []
    if iocs:
        w.writerow(["--- INDICATORS OF COMPROMISE ---"])
        w.writerow(["Type", "Value"])
        for i in iocs:
            w.writerow([i.get("type"), i.get("value")])
        w.writerow([])

    # OSINT-enriched IOCs — richest section
    enriched = report.get("enriched_iocs") or []
    if enriched:
        w.writerow(["--- OSINT ENRICHMENT ---"])
        w.writerow([
            "IOC", "Type", "Verdict",
            "VT malicious", "VT suspicious", "VT total", "VT threat_label",
            "AbuseIPDB score", "AbuseIPDB reports",
            "Geo country", "Geo city", "ISP",
            "Resolved IP", "Open ports", "urlscan scans",
            "Hybrid Analysis verdict", "MalwareBazaar signature",
            "In known-file DB", "Known malicious", "Filename",
            "AI verdict",
        ])
        for r in enriched:
            rep = r.get("reputation") or {}
            vt = rep.get("vt") or {}
            ab = rep.get("abuseipdb") or {}
            ha = rep.get("hybrid_analysis") or {}
            mb = rep.get("malwarebazaar") or {}
            en = r.get("enrichment") or {}
            g = en.get("geo") or {}
            vt_hits = (vt.get("malicious", 0) or 0) + (vt.get("suspicious", 0) or 0) if not vt.get("error") else 0
            ab_score = (ab.get("score", 0) or 0) if not ab.get("error") else 0
            if (vt.get("malicious", 0) or 0) >= 5 or ab_score >= 75:
                verdict = "CRITICAL"
            elif vt_hits > 0 or ab_score >= 50:
                verdict = "HIGH"
            elif vt_hits > 0 or ab_score > 0:
                verdict = "SUSPECT"
            else:
                verdict = "CLEAN"
            w.writerow([
                r.get("value", ""),
                (r.get("type", "unknown") or "unknown").upper(),
                verdict,
                vt.get("malicious", "") if not vt.get("error") else "",
                vt.get("suspicious", "") if not vt.get("error") else "",
                vt.get("total", "") if not vt.get("error") else "",
                vt.get("threat_label", "") if not vt.get("error") else "",
                ab.get("score", "") if not ab.get("error") else "",
                ab.get("reports", "") if not ab.get("error") else "",
                g.get("country", ""),
                g.get("city", ""),
                g.get("isp", ""),
                en.get("resolved_ip", "") if en.get("kind") == "web" else "",
                ",".join(str(p) for p in (en.get("open_ports") or [])[:8]),
                en.get("scan_count", "") if en.get("kind") == "web" else "",
                (ha.get("verdict", "") if isinstance(ha, dict) else "") or "",
                (mb.get("signature", "") if isinstance(mb, dict) else "") or "",
                en.get("found") if en.get("kind") == "hash" else "",
                en.get("known_malicious") if en.get("kind") == "hash" else "",
                en.get("filename", "") if en.get("kind") == "hash" else "",
                (r.get("ai_summary") or "").strip(),
            ])
    return buf.getvalue()


# --------------------------- JSON export ---------------------------

def render_json(report: Dict[str, Any]) -> str:
    """Return a machine-readable JSON dump of the report (pretty-printed)."""
    out = {
        "generated_utc": datetime.utcnow().isoformat() + "Z",
        "source": "NivX Machines · NivX Forge",
        "verdict": (report.get("analysis") or {}).get("verdict"),
        "risk_score": (report.get("analysis") or {}).get("risk_score"),
        "summary": (report.get("analysis") or {}).get("summary"),
        "input": report.get("input"),
        "decoded_output": report.get("output"),
        "trace": report.get("trace") or [],
        "analysis": report.get("analysis") or {},
        "ai": report.get("ai") or {},
        "enriched_iocs": report.get("enriched_iocs") or [],
        "enrichment_meta": report.get("enrichment_meta") or {},
    }
    return _json.dumps(out, indent=2, default=str, ensure_ascii=False)
