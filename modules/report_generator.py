from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime
import os


# ── Color Palette ──────────────────────────────────
C_BG        = colors.HexColor("#0e1117")
C_DARK      = colors.HexColor("#1e2130")
C_ACCENT    = colors.HexColor("#64ffda")
C_TEXT      = colors.HexColor("#ccd6f6")
C_MUTED     = colors.HexColor("#8892b0")
C_RED       = colors.HexColor("#ff4444")
C_ORANGE    = colors.HexColor("#ff8800")
C_YELLOW    = colors.HexColor("#ffcc00")
C_GREEN     = colors.HexColor("#00cc44")
C_WHITE     = colors.white
C_CRITICAL  = colors.HexColor("#cc0000")
C_HIGH      = colors.HexColor("#e65c00")
C_MEDIUM    = colors.HexColor("#ccaa00")
C_LOW       = colors.HexColor("#007700")


def _verdict_color(verdict):
    return {
        "CRITICAL": C_CRITICAL,
        "HIGH":     C_HIGH,
        "MEDIUM":   C_MEDIUM,
        "LOW":      C_LOW,
    }.get(verdict, C_DARK)


# ── Styles ─────────────────────────────────────────
def _styles():
    return {
        "h1": ParagraphStyle(
            "h1", fontSize=22, fontName="Helvetica-Bold",
            textColor=C_WHITE, spaceAfter=4, alignment=TA_LEFT
        ),
        "h2": ParagraphStyle(
            "h2", fontSize=13, fontName="Helvetica-Bold",
            textColor=C_ACCENT, spaceBefore=10, spaceAfter=4
        ),
        "body": ParagraphStyle(
            "body", fontSize=9, fontName="Helvetica",
            textColor=C_TEXT, spaceAfter=3
        ),
        "muted": ParagraphStyle(
            "muted", fontSize=8, fontName="Helvetica",
            textColor=C_MUTED
        ),
        "code": ParagraphStyle(
            "code", fontSize=8, fontName="Courier",
            textColor=C_ACCENT, spaceAfter=2
        ),
        "center": ParagraphStyle(
            "center", fontSize=9, fontName="Helvetica",
            textColor=C_TEXT, alignment=TA_CENTER
        ),
        "right": ParagraphStyle(
            "right", fontSize=8, fontName="Helvetica",
            textColor=C_MUTED, alignment=TA_RIGHT
        ),
    }


# ── Table Style ────────────────────────────────────
def _table_style(header_color=None):
    hc = header_color or C_DARK
    return TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  hc),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0),  9),
        ("BACKGROUND",    (0, 1), (-1, -1), C_DARK),
        ("TEXTCOLOR",     (0, 1), (-1, -1), C_TEXT),
        ("FONTSIZE",      (0, 1), (-1, -1), 8),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1),
         [C_DARK, colors.HexColor("#161a26")]),
        ("GRID",          (0, 0), (-1, -1), 0.3, C_MUTED),
        ("ALIGN",         (0, 0), (-1, -1), "LEFT"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
    ])


# ── Header ─────────────────────────────────────────
def _build_header(elements, report, S):
    # Top bar
    header_table = Table([[
        Paragraph("🛡️ PHISHING INCIDENT REPORT", S["h1"]),
        Paragraph(
            f"AMIT SOC — Blue Team Pipeline<br/>"
            f"<font size='8' color='#8892b0'>"
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
            f"</font>",
            S["right"]
        ),
    ]], colWidths=[10*cm, 7*cm])
    header_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), C_BG),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))
    elements.append(header_table)
    elements.append(HRFlowable(
        width="100%", thickness=2,
        color=C_ACCENT, spaceAfter=8
    ))


# ── Verdict Banner ──────────────────────────────────
def _build_verdict(elements, report, S):
    verdict      = report["verdict"]
    score        = report["final_score"]
    verdict_col  = _verdict_color(verdict)
    icons        = {
        "CRITICAL": "⛔",
        "HIGH":     "🔴",
        "MEDIUM":   "🟡",
        "LOW":      "🟢"
    }

    banner = Table([[
        Paragraph(
            f"<font size='14' color='white'><b>"
            f"{icons.get(verdict,'')} {verdict} THREAT"
            f"</b></font>",
            S["center"]
        ),
        Paragraph(
            f"<font size='22' color='white'><b>{score}</b></font>"
            f"<br/><font size='9' color='#cccccc'>/ 100</font>",
            S["center"]
        ),
        Paragraph(
            f"<font size='9' color='#cccccc'>"
            f"Alert ID<br/></font>"
            f"<font size='10' color='white'><b>"
            f"PHI-{datetime.utcnow().strftime('%Y%m%d')}"
            f"</b></font>",
            S["center"]
        ),
    ]], colWidths=[7*cm, 5*cm, 5*cm])

    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), verdict_col),
        ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("ROWHEIGHT",  (0, 0), (-1, -1), 45),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(banner)
    elements.append(Spacer(1, 0.3*cm))


# ── Score Breakdown ─────────────────────────────────
def _build_scores(elements, report, S):
    elements.append(Paragraph("📊 Score Breakdown", S["h2"]))

    bd = report["breakdown"]
    scores = [
        ("Header & Auth",  bd["header_score"],   "40% weight"),
        ("Content",        bd["content_score"],  "20% weight"),
        ("URL Analysis",   bd["url_score"],      "20% weight"),
        ("VirusTotal",     bd["vt_score"],       "15% weight"),
        ("URLhaus",        bd["urlhaus_score"],  "10% weight"),
        ("ML Classifier",  bd["ml_score"],       "10% weight"),
    ]

    rows = [["Component", "Score", "Weight", "Risk Bar"]]
    for name, score, weight in scores:
        bar_filled = int(score / 10)
        bar = "█" * bar_filled + "░" * (10 - bar_filled)
        rows.append([name, f"{score}/100", weight, bar])

    rows.append([
        Paragraph("<b>FINAL SCORE</b>", ParagraphStyle(
            "bold", fontSize=9, fontName="Helvetica-Bold",
            textColor=C_WHITE
        )),
        Paragraph(f"<b>{report['final_score']}/100</b>", ParagraphStyle(
            "bold", fontSize=9, fontName="Helvetica-Bold",
            textColor=C_ACCENT
        )),
        "—", "—"
    ])

    t = Table(rows, colWidths=[5*cm, 3*cm, 3*cm, 6*cm])
    style = _table_style(C_DARK)
    style.add("BACKGROUND", (0, len(rows)-1), (-1, len(rows)-1),
              _verdict_color(report["verdict"]))
    t.setStyle(style)
    elements.append(t)
    elements.append(Spacer(1, 0.3*cm))


# ── Email Info ──────────────────────────────────────
def _build_email_info(elements, report, S):
    elements.append(Paragraph("📧 Email Information", S["h2"]))

    auth   = report["auth_results"]
    sender = report["sender"]

    def auth_str(val):
        return "✅ PASS" if val == "pass" else "❌ FAIL" if val == "fail" else "⚠️ NONE"

    rows = [
        ["Field", "Value"],
        ["Sender",    sender["raw"]],
        ["Domain",    sender["domain"]],
        ["Subject",   report["subject"]],
        ["Timestamp", report["timestamp"][:19] + " UTC"],
        ["SPF",       auth_str(auth["spf"])],
        ["DKIM",      auth_str(auth["dkim"])],
        ["DMARC",     auth_str(auth["dmarc"])],
        ["Attachments", str(len(report.get("attachments", [])))],
    ]

    t = Table(rows, colWidths=[4*cm, 13*cm])
    t.setStyle(_table_style(C_DARK))
    elements.append(t)
    elements.append(Spacer(1, 0.3*cm))


# ── URLs ────────────────────────────────────────────
def _build_urls(elements, report, S):
    urls = report.get("urls_analyzed", [])
    if not urls:
        return

    elements.append(Paragraph("🔗 URLs Analyzed", S["h2"]))

    rows = [["URL", "Rule", "VT", "Engines", "URLhaus", "Verdict"]]
    for u in urls:
        url_short = (u["url"][:50] + "...") if len(u["url"]) > 50 else u["url"]
        urlhaus = "🔴 Listed" if u.get("urlhaus_listed") else "🟢 Clean"
        rows.append([
            url_short,
            f"{u['rule_score']}/100",
            f"{u['vt_score']}/100",
            str(u["malicious_engines"]),
            urlhaus,
            u["vt_verdict"],
        ])

    t = Table(rows, colWidths=[6*cm, 2*cm, 2*cm, 2*cm, 2.5*cm, 2.5*cm])
    t.setStyle(_table_style(C_DARK))
    elements.append(t)
    elements.append(Spacer(1, 0.3*cm))


# ── Flags ───────────────────────────────────────────
def _build_flags(elements, report, S):
    elements.append(Paragraph("🚩 Detection Flags", S["h2"]))

    flags = sorted(report.get("flags", []))
    rows  = [["#", "Flag", "Category"]]

    categories = {
        "spf": "Authentication", "dkim": "Authentication",
        "dmarc": "Authentication", "reply_to": "Authentication",
        "keyword": "Content", "urgency": "Content",
        "credential": "Content", "impersonation": "Content",
        "no_https": "URL", "ip_as": "URL",
        "lookalike": "URL", "special": "URL",
        "url": "URL",
    }

    for i, flag in enumerate(flags, 1):
        cat = "General"
        for key, val in categories.items():
            if key in flag:
                cat = val
                break
        rows.append([str(i), flag, cat])

    t = Table(rows, colWidths=[1*cm, 11*cm, 5*cm])
    t.setStyle(_table_style(C_DARK))
    elements.append(t)
    elements.append(Spacer(1, 0.3*cm))


# ── MITRE ───────────────────────────────────────────
def _build_mitre(elements, report, S):
    elements.append(Paragraph("🗺️ MITRE ATT&CK Mapping", S["h2"]))

    rows = [
        ["Technique ID", "Name", "Sub-technique", "Status"],
        ["T1566",     "Phishing",                "—",                          "✅ Detected"],
        ["T1566.001", "Spearphishing Link",       "URL in email body",          "✅ Detected"],
        ["T1566.002", "Spearphishing Attachment", "Malicious attachment",       "⚠️ Monitored"],
        ["T1598",     "Gather Victim Info",        "Credential harvesting page", "✅ Detected"],
    ]

    t = Table(rows, colWidths=[3*cm, 5*cm, 6*cm, 3*cm])
    t.setStyle(_table_style(C_DARK))
    elements.append(t)
    elements.append(Spacer(1, 0.3*cm))


# ── Recommendations ─────────────────────────────────
def _build_recommendations(elements, report, S):
    elements.append(Paragraph("✅ Recommended Actions", S["h2"]))

    verdict = report["verdict"]
    actions = [
        ["Priority", "Action", "Status"],
        ["🔴 HIGH",   "Block sender domain at email gateway",    "Immediate"],
        ["🔴 HIGH",   "Quarantine email from all mailboxes",     "Immediate"],
        ["🔴 HIGH",   "Block malicious URLs at firewall/proxy",  "Immediate"],
        ["🟠 MEDIUM", "Notify affected recipients",              "Within 1hr"],
        ["🟠 MEDIUM", "Submit IOCs to threat intel platform",    "Within 2hrs"],
        ["🟡 LOW",    "Update email filtering rules",            "Today"],
        ["🟡 LOW",    "Document incident in ticketing system",   "Today"],
    ]

    if verdict == "CRITICAL":
        actions.insert(1, ["⛔ CRITICAL",
                           "Escalate to Tier 2 SOC analyst",
                           "Immediate"])

    t = Table(actions, colWidths=[3*cm, 10*cm, 4*cm])
    t.setStyle(_table_style(C_DARK))
    elements.append(t)
    elements.append(Spacer(1, 0.3*cm))


# ── Footer ──────────────────────────────────────────
def _build_footer(elements, S):
    elements.append(Spacer(1, 0.5*cm))
    elements.append(HRFlowable(
        width="100%", thickness=1,
        color=C_MUTED, spaceAfter=6
    ))
    footer = Table([[
        Paragraph(
            "AMIT Graduate Project — Phishing Detection & Analysis System",
            S["muted"]
        ),
        Paragraph(
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            ParagraphStyle("fr", fontSize=8,
                           textColor=C_MUTED, alignment=TA_RIGHT)
        ),
    ]], colWidths=[10*cm, 7*cm])
    footer.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_BG),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
    ]))
    elements.append(footer)


# ── Main ────────────────────────────────────────────
def generate_report(report: dict,
                    output_path: str = "reports/incident_report.pdf") -> str:
    os.makedirs("reports", exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=1.5*cm,
        leftMargin=1.5*cm,
        topMargin=1.5*cm,
        bottomMargin=1.5*cm,
    )

    # Dark background
    def on_page(canvas, doc):
        canvas.setFillColor(C_BG)
        canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)

    S        = _styles()
    elements = []

    _build_header(elements, report, S)
    _build_verdict(elements, report, S)
    _build_scores(elements, report, S)
    _build_email_info(elements, report, S)
    _build_urls(elements, report, S)
    _build_flags(elements, report, S)
    _build_mitre(elements, report, S)
    _build_recommendations(elements, report, S)
    _build_footer(elements, S)

    doc.build(elements, onFirstPage=on_page, onLaterPages=on_page)
    return output_path


if __name__ == "__main__":
    from modules.risk_engine import run_analysis
    report = run_analysis("data/test.eml")
    path   = generate_report(report)
    print(f"✅ Report saved: {path}")