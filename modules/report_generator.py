from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, HRFlowable
)
from datetime import datetime
import os

# ── Palette ────────────────────────────────────────
BLUE    = colors.HexColor("#0071e3")
DARK    = colors.HexColor("#1d1d1f")
GRAY    = colors.HexColor("#f5f5f7")
MUTED   = colors.HexColor("#6e6e73")
WHITE   = colors.white
GREEN   = colors.HexColor("#34c759")
RED     = colors.HexColor("#ff3b30")
ORANGE  = colors.HexColor("#ff9500")
YELLOW  = colors.HexColor("#ffcc00")
LGRAY   = colors.HexColor("#e5e5ea")

def _vc(verdict):
    return {"CRITICAL": RED, "HIGH": ORANGE,
            "MEDIUM": YELLOW, "LOW": GREEN}.get(verdict, BLUE)

# ── Styles ─────────────────────────────────────────
H1 = ParagraphStyle("h1", fontSize=22, fontName="Helvetica-Bold",
                    textColor=DARK, spaceAfter=2)
H2 = ParagraphStyle("h2", fontSize=11, fontName="Helvetica-Bold",
                    textColor=BLUE, spaceBefore=14, spaceAfter=6)
BODY = ParagraphStyle("body", fontSize=9, fontName="Helvetica",
                      textColor=DARK, spaceAfter=2)
SMALL = ParagraphStyle("small", fontSize=8, fontName="Helvetica",
                       textColor=MUTED)
RIGHT = ParagraphStyle("right", fontSize=8, fontName="Helvetica",
                       textColor=MUTED, alignment=TA_RIGHT)
CENTER = ParagraphStyle("center", fontSize=9, fontName="Helvetica",
                        textColor=DARK, alignment=TA_CENTER)
BOLD = ParagraphStyle("bold", fontSize=9, fontName="Helvetica-Bold",
                      textColor=DARK)
CODE = ParagraphStyle("code", fontSize=8, fontName="Courier",
                      textColor=DARK)

# ── Table Style ────────────────────────────────────
def _ts(hdr_color=None):
    hc = hdr_color or DARK
    return TableStyle([
        # Header
        ("BACKGROUND",    (0,0), (-1,0),  hc),
        ("TEXTCOLOR",     (0,0), (-1,0),  WHITE),
        ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,0),  8),
        # Body
        ("FONTNAME",      (0,1), (-1,-1), "Helvetica"),
        ("FONTSIZE",      (0,1), (-1,-1), 8),
        ("TEXTCOLOR",     (0,1), (-1,-1), DARK),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, GRAY]),
        # Grid
        ("GRID",          (0,0), (-1,-1), 0.4, LGRAY),
        ("LINEBELOW",     (0,0), (-1,0),  1,   hc),
        # Padding
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("RIGHTPADDING",  (0,0), (-1,-1), 8),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ])

# ── Helpers ────────────────────────────────────────
def _auth(val):
    if val == "pass":  return "✓ PASS"
    if val == "fail":  return "✗ FAIL"
    return "— NONE"

def _bar(score):
    filled = int(score / 10)
    return "█" * filled + "░" * (10 - filled)

def _flag_cat(flag):
    for k,v in {
        "spf":"Auth","dkim":"Auth","dmarc":"Auth","reply_to":"Auth",
        "keyword":"Content","urgency":"Content",
        "credential":"Content","impersonation":"Content",
        "lookalike":"URL","no_https":"URL","ip_as":"URL",
        "special":"URL","redirect":"Redirect","domain":"Domain",
        "whois":"WHOIS","unicode":"Unicode","attachment":"Attachment",
        "ip":"IP","ssl":"SSL",
    }.items():
        if k in flag: return v
    return "General"

# ── Sections ───────────────────────────────────────
def _header(report):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    t = Table([[
        Paragraph("PhishGuard", ParagraphStyle(
            "pg", fontSize=20, fontName="Helvetica-Bold",
            textColor=DARK)),
        Paragraph(
            f"AMIT SOC — Blue Team Pipeline<br/>"
            f"<font size='7' color='#6e6e73'>Generated: {ts}</font>",
            RIGHT)
    ]], colWidths=[9*cm, 8*cm])
    t.setStyle(TableStyle([
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("LEFTPADDING",(0,0),(-1,-1),0),
        ("RIGHTPADDING",(0,0),(-1,-1),0),
    ]))
    return [
        t,
        HRFlowable(width="100%", thickness=1.5, color=BLUE, spaceAfter=8),
        Paragraph("PHISHING INCIDENT REPORT", ParagraphStyle(
            "rpt", fontSize=13, fontName="Helvetica-Bold",
            textColor=MUTED, spaceAfter=6)),
    ]

def _verdict_banner(report):
    v     = report["verdict"]
    score = report["final_score"]
    vc    = _vc(v)
    icons = {"CRITICAL":"⛔","HIGH":"🔴","MEDIUM":"🟡","LOW":"🟢"}
    aid   = f"PHI-{datetime.utcnow().strftime('%Y%m%d')}"

    t = Table([[
        Paragraph(f"{icons.get(v,'')}  {v} THREAT", ParagraphStyle(
            "vl", fontSize=13, fontName="Helvetica-Bold",
            textColor=WHITE, alignment=TA_LEFT)),
        Paragraph(f"<font size='24'><b>{score}</b></font>"
                  f"<font size='10' color='#ffffff'> / 100</font>",
                  ParagraphStyle("vs", fontSize=24,
                                 fontName="Helvetica-Bold",
                                 textColor=WHITE, alignment=TA_CENTER)),
        Paragraph(
            f"<font size='8' color='#ffffffcc'>Alert ID</font><br/>"
            f"<font size='10'><b>{aid}</b></font>",
            ParagraphStyle("va", fontSize=10, fontName="Helvetica-Bold",
                           textColor=WHITE, alignment=TA_RIGHT)),
    ]], colWidths=[7*cm, 5*cm, 5*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), vc),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",    (0,0), (-1,-1), 12),
        ("BOTTOMPADDING", (0,0), (-1,-1), 12),
        ("LEFTPADDING",   (0,0), (-1,-1), 14),
        ("RIGHTPADDING",  (0,0), (-1,-1), 14),
        ("ROUNDEDCORNERS",[6]),
    ]))
    return [t, Spacer(1, 0.3*cm)]

def _score_breakdown(report):
    bd = report.get("breakdown", {})
    rows = [["Component","Score","Weight","Risk Bar"]]
    items = [
        ("Header & Auth",  bd.get("header_score",0),   "22%"),
        ("Content",        bd.get("content_score",0),  "18%"),
        ("URL Analysis",   bd.get("url_score",0),      "18%"),
        ("VirusTotal",     bd.get("vt_score",0),       "14%"),
        ("URLhaus",        bd.get("urlhaus_score",0),  "8%"),
        ("ML Classifier",  bd.get("ml_score",0),       "10%"),
        ("Advanced",       bd.get("advanced_score",0), "10%"),
    ]
    for name, score, weight in items:
        rows.append([name, f"{score}/100", weight, _bar(score)])
    
    fs = report.get("final_score", 0)
    rows.append([
        Paragraph("<b>FINAL SCORE</b>", BOLD),
        Paragraph(f"<b>{fs}/100</b>", ParagraphStyle(
            "fs", fontSize=9, fontName="Helvetica-Bold",
            textColor=_vc(report["verdict"]))),
        "—", _bar(fs)
    ])

    t = Table(rows, colWidths=[5*cm, 2.5*cm, 2.5*cm, 7*cm])
    s = _ts()
    s.add("BACKGROUND", (0, len(rows)-1), (-1, len(rows)-1), GRAY)
    s.add("FONTNAME",   (0, len(rows)-1), (-1, len(rows)-1),
          "Helvetica-Bold")
    t.setStyle(s)
    return [Paragraph("Score Breakdown", H2), t, Spacer(1,0.2*cm)]

def _email_info(report):
    auth = report.get("auth_results", {})
    s    = report.get("sender", {})
    rows = [
        ["Field", "Value"],
        ["Sender",    s.get("raw","—")],
        ["Domain",    s.get("domain","—")],
        ["Subject",   report.get("subject","—")],
        ["Timestamp", report.get("timestamp","—")[:19] + " UTC"],
        ["SPF",       _auth(auth.get("spf","none"))],
        ["DKIM",      _auth(auth.get("dkim","none"))],
        ["DMARC",     _auth(auth.get("dmarc","none"))],
        ["Attachments", str(len(report.get("attachments",[])))],
    ]
    t = Table(rows, colWidths=[3.5*cm, 13.5*cm])
    t.setStyle(_ts())
    return [Paragraph("Email Information", H2), t, Spacer(1,0.2*cm)]

def _advanced_section(report):
    adv = report.get("advanced", {})
    if not adv:
        return []

    da = adv.get("domain_age",    {})
    ip = adv.get("ip_reputation", {})
    rd = adv.get("redirect",      {})
    uc = adv.get("unicode",       {})
    at = adv.get("attachment",    {})

    rows = [["Check","Result","Score","Flags"]]

    age_val = f"{da.get('age_days')} days" if da.get("age_days") \
              else "Unknown"
    rows.append([
        "Domain Age",
        f"{age_val} | Reg: {da.get('registrar') or '—'}",
        f"{da.get('score',0)}/100",
        ", ".join(da.get("flags",[])) or "None"
    ])

    rows.append([
        "IP Reputation",
        f"{ip.get('ip') or '—'} | {ip.get('reverse_dns') or '—'}",
        f"{ip.get('score',0)}/100",
        ", ".join(ip.get("flags",[])) or "None"
    ])

    hops = rd.get("hops", 0)
    rows.append([
        "Redirect Chain",
        f"{hops} hop(s) → {rd.get('final_url','—')[:40]}",
        f"{rd.get('score',0)}/100",
        ", ".join(rd.get("flags",[])) or "None"
    ])

    rows.append([
        "Unicode / Homograph",
        f"Punycode: {'Yes' if uc.get('is_punycode') else 'No'} | "
        f"Chars: {uc.get('suspicious_chars') or 'None'}",
        f"{uc.get('score',0)}/100",
        ", ".join(uc.get("flags",[])) or "None"
    ])

    att_files = at.get("scanned", [])
    att_val   = f"{len(att_files)} file(s)" if att_files else "None"
    rows.append([
        "Attachments",
        att_val,
        f"{at.get('score',0)}/100",
        ", ".join(at.get("flags",[])) or "None"
    ])

    t = Table(rows, colWidths=[3.5*cm, 7*cm, 2*cm, 4.5*cm])
    t.setStyle(_ts())
    return [Paragraph("Advanced Analysis", H2), t, Spacer(1,0.2*cm)]

def _urls_section(report):
    urls = report.get("urls_analyzed", [])
    if not urls:
        return []
    rows = [["URL","Rule","VT","Engines","URLhaus","Verdict"]]
    for u in urls:
        url_s = u["url"][:45] + "…" if len(u["url"]) > 45 else u["url"]
        uh    = "Listed" if u.get("urlhaus_listed") else "Clean"
        rows.append([
            Paragraph(url_s, CODE),
            f"{u.get('rule_score',0)}/100",
            f"{u.get('vt_score',0)}/100",
            str(u.get("malicious_engines",0)),
            uh,
            u.get("vt_verdict","—"),
        ])
    t = Table(rows, colWidths=[6*cm,2*cm,2*cm,2*cm,2*cm,3*cm])
    t.setStyle(_ts())
    return [Paragraph("URLs Analyzed", H2), t, Spacer(1,0.2*cm)]

def _flags_section(report):
    flags = sorted(report.get("flags", []))
    if not flags:
        return []
    rows = [["#","Flag","Category"]]
    for i, f in enumerate(flags, 1):
        rows.append([str(i), f, _flag_cat(f)])
    t = Table(rows, colWidths=[1*cm, 12*cm, 4*cm])
    t.setStyle(_ts())
    return [Paragraph("Detection Flags", H2), t, Spacer(1,0.2*cm)]

def _mitre_section():
    rows = [
        ["Technique ID","Name","Sub-technique","Status"],
        ["T1566",     "Phishing",                "—",
         "✓ Detected"],
        ["T1566.001", "Spearphishing Link",       "URL in body",
         "✓ Detected"],
        ["T1566.002", "Spearphishing Attachment", "Malicious file",
         "⚠ Monitored"],
        ["T1598",     "Gather Victim Info",        "Credential page",
         "✓ Detected"],
    ]
    t = Table(rows, colWidths=[3*cm,5.5*cm,5.5*cm,3*cm])
    t.setStyle(_ts())
    return [Paragraph("MITRE ATT&CK Mapping", H2), t, Spacer(1,0.2*cm)]

def _actions_section(report):
    verdict = report.get("verdict","")
    rows = [["Priority","Action","Timing"]]
    acts = [
        ("🔴 HIGH",   "Block sender domain at email gateway",   "Immediate"),
        ("🔴 HIGH",   "Quarantine from all mailboxes",          "Immediate"),
        ("🟠 MEDIUM", "Block malicious URLs at firewall/proxy", "Within 1hr"),
        ("🟠 MEDIUM", "Notify affected recipients",             "Within 1hr"),
        ("🟡 LOW",    "Submit IOCs to threat intel platform",   "Within 2hrs"),
        ("🟢 LOW",    "Update email filtering rules",           "Today"),
    ]
    if verdict == "CRITICAL":
        acts.insert(0,("⛔ CRITICAL",
                       "Escalate to Tier 2 SOC analyst","Immediate"))
    for p,a,ti in acts:
        rows.append([p, a, ti])
    t = Table(rows, colWidths=[3.5*cm,11*cm,2.5*cm])
    t.setStyle(_ts())
    return [Paragraph("Recommended Actions", H2), t, Spacer(1,0.2*cm)]

def _footer_section():
    t = Table([[
        Paragraph("PhishGuard — AMIT Graduate Project 2026", SMALL),
        Paragraph(
            datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            RIGHT),
    ]], colWidths=[10*cm, 7*cm])
    t.setStyle(TableStyle([
        ("LEFTPADDING", (0,0),(-1,-1), 0),
        ("RIGHTPADDING",(0,0),(-1,-1), 0),
    ]))
    return [
        Spacer(1, 0.4*cm),
        HRFlowable(width="100%", thickness=0.5, color=LGRAY, spaceAfter=6),
        t,
    ]

# ── Main ───────────────────────────────────────────
def generate_report(report: dict,
                    output_path: str = "reports/incident_report.pdf") -> str:
    os.makedirs("reports", exist_ok=True)

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=1.5*cm, rightMargin=1.5*cm,
        topMargin=1.5*cm,  bottomMargin=1.5*cm,
    )

    els = []
    els += _header(report)
    els += _verdict_banner(report)
    els += _score_breakdown(report)
    els += _email_info(report)
    els += _advanced_section(report)
    els += _urls_section(report)
    els += _flags_section(report)
    els += _mitre_section()
    els += _actions_section(report)
    els += _footer_section()

    doc.build(els)
    print(f"Report saved: {output_path}")
    return output_path


if __name__ == "__main__":
    import sys
    from modules.risk_engine import run_analysis
    path   = sys.argv[1] if len(sys.argv) > 1 else "data/test.eml"
    report = run_analysis(path)
    generate_report(report)