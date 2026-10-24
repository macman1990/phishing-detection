import streamlit as st
import json
import os
import tempfile
from modules.risk_engine import run_analysis
from modules.report_generator import generate_report
from modules.siem_integration import send_alert, get_all_alerts

st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

    * { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; }

    .stApp {
        background-color: #f5f5f7;
        max-width: 900px;
        margin: 0 auto;
    }

    section[data-testid="stMain"] > div {
        padding-top: 2rem;
        padding-bottom: 4rem;
    }

    /* Hide default streamlit elements */
    #MainMenu, footer, header { visibility: hidden; }
    .stDeployButton { display: none; }

    /* Hero */
    .hero {
        text-align: center;
        padding: 48px 0 32px;
    }
    .hero-badge {
        display: inline-block;
        background: #e8f5e9;
        color: #2e7d32;
        font-size: 12px;
        font-weight: 600;
        letter-spacing: 0.5px;
        padding: 4px 12px;
        border-radius: 20px;
        margin-bottom: 16px;
        text-transform: uppercase;
    }
    .hero h1 {
        font-size: 42px;
        font-weight: 700;
        color: #1d1d1f;
        margin: 0 0 12px;
        letter-spacing: -1px;
        line-height: 1.1;
    }
    .hero p {
        font-size: 17px;
        color: #6e6e73;
        margin: 0;
        font-weight: 400;
        line-height: 1.5;
    }

    /* Upload Zone */
    .upload-zone {
        background: white;
        border: 2px dashed #d2d2d7;
        border-radius: 18px;
        padding: 40px;
        text-align: center;
        margin: 24px 0;
        transition: all 0.2s;
    }
    .upload-zone:hover { border-color: #0071e3; }

    /* Cards */
    .card {
        background: white;
        border-radius: 18px;
        padding: 24px;
        margin: 12px 0;
        box-shadow: 0 2px 8px rgba(0,0,0,0.06);
        border: 1px solid rgba(0,0,0,0.04);
    }
    .card-title {
        font-size: 13px;
        font-weight: 600;
        color: #6e6e73;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 16px;
    }

    /* Verdict */
    .verdict-wrap {
        border-radius: 20px;
        padding: 32px;
        text-align: center;
        margin: 24px 0;
    }
    .verdict-critical { background: linear-gradient(135deg, #ff3b30, #c0392b); }
    .verdict-high     { background: linear-gradient(135deg, #ff9500, #e67e22); }
    .verdict-medium   { background: linear-gradient(135deg, #ffcc00, #f39c12); }
    .verdict-low      { background: linear-gradient(135deg, #34c759, #27ae60); }

    .verdict-label {
        font-size: 13px;
        font-weight: 600;
        letter-spacing: 1px;
        text-transform: uppercase;
        color: rgba(255,255,255,0.8);
        margin-bottom: 8px;
    }
    .verdict-main {
        font-size: 48px;
        font-weight: 700;
        color: white;
        letter-spacing: -2px;
        line-height: 1;
        margin-bottom: 8px;
    }
    .verdict-sub {
        font-size: 15px;
        color: rgba(255,255,255,0.75);
        font-weight: 400;
    }

    /* Score Grid */
    .score-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 12px;
        margin: 0;
    }
    .score-item {
        background: #f5f5f7;
        border-radius: 14px;
        padding: 16px;
        text-align: center;
    }
    .score-num {
        font-size: 28px;
        font-weight: 700;
        color: #1d1d1f;
        letter-spacing: -1px;
        line-height: 1;
    }
    .score-label {
        font-size: 12px;
        color: #6e6e73;
        margin-top: 4px;
        font-weight: 500;
    }

    /* Auth Badges */
    .badge-pass {
        display: inline-block;
        background: #e8f5e9;
        color: #2e7d32;
        font-size: 12px;
        font-weight: 600;
        padding: 3px 10px;
        border-radius: 20px;
    }
    .badge-fail {
        display: inline-block;
        background: #ffebee;
        color: #c62828;
        font-size: 12px;
        font-weight: 600;
        padding: 3px 10px;
        border-radius: 20px;
    }
    .badge-none {
        display: inline-block;
        background: #fff8e1;
        color: #f57f17;
        font-size: 12px;
        font-weight: 600;
        padding: 3px 10px;
        border-radius: 20px;
    }

    /* Info Row */
    .info-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 10px 0;
        border-bottom: 1px solid #f5f5f7;
    }
    .info-row:last-child { border-bottom: none; }
    .info-key {
        font-size: 13px;
        color: #6e6e73;
        font-weight: 500;
    }
    .info-val {
        font-size: 13px;
        color: #1d1d1f;
        font-weight: 500;
        text-align: right;
        max-width: 60%;
        word-break: break-all;
    }

    /* Flags */
    .flag-grid {
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 8px;
    }
    .flag-pill {
        background: #fff2f2;
        border: 1px solid #ffcdd2;
        color: #c62828;
        font-size: 12px;
        font-weight: 500;
        padding: 6px 12px;
        border-radius: 8px;
        display: flex;
        align-items: center;
        gap: 6px;
    }

    /* URL Card */
    .url-item {
        background: #f5f5f7;
        border-radius: 12px;
        padding: 14px 16px;
        margin: 8px 0;
    }
    .url-text {
        font-size: 12px;
        font-family: 'SF Mono', 'Courier New', monospace;
        color: #1d1d1f;
        word-break: break-all;
        margin-bottom: 8px;
    }
    .url-meta {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
    }
    .url-tag {
        font-size: 11px;
        font-weight: 600;
        padding: 2px 8px;
        border-radius: 6px;
    }
    .url-tag-danger { background: #ffebee; color: #c62828; }
    .url-tag-warn   { background: #fff8e1; color: #f57f17; }
    .url-tag-safe   { background: #e8f5e9; color: #2e7d32; }

    /* MITRE */
    .mitre-grid {
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 10px;
    }
    .mitre-item {
        background: #f5f5f7;
        border-radius: 12px;
        padding: 14px;
    }
    .mitre-id {
        font-size: 13px;
        font-weight: 700;
        color: #0071e3;
        margin-bottom: 4px;
    }
    .mitre-name {
        font-size: 12px;
        color: #1d1d1f;
        font-weight: 500;
    }
    .mitre-sub {
        font-size: 11px;
        color: #6e6e73;
        margin-top: 2px;
    }

    /* Actions */
    .action-item {
        display: flex;
        align-items: flex-start;
        gap: 12px;
        padding: 10px 0;
        border-bottom: 1px solid #f5f5f7;
    }
    .action-item:last-child { border-bottom: none; }
    .action-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        margin-top: 5px;
        flex-shrink: 0;
    }
    .action-text {
        font-size: 14px;
        color: #1d1d1f;
        font-weight: 400;
    }
    .action-timing {
        font-size: 11px;
        color: #6e6e73;
        margin-top: 2px;
    }

    /* Alert ID */
    .alert-id {
        font-size: 11px;
        color: #6e6e73;
        text-align: center;
        margin-top: 8px;
        font-family: 'SF Mono', monospace;
    }

    /* History item */
    .history-item {
        background: white;
        border-radius: 14px;
        padding: 16px 20px;
        margin: 8px 0;
        display: flex;
        align-items: center;
        justify-content: space-between;
        box-shadow: 0 1px 4px rgba(0,0,0,0.06);
    }

    /* Divider */
    .section-divider {
        height: 1px;
        background: #d2d2d7;
        margin: 8px 0 24px;
    }

    /* Streamlit overrides */
    .stFileUploader {
        background: white;
        border-radius: 18px;
        padding: 8px;
    }
    .stButton > button {
        background: #0071e3;
        color: white;
        border: none;
        border-radius: 12px;
        padding: 12px 28px;
        font-size: 15px;
        font-weight: 600;
        width: 100%;
        transition: all 0.2s;
    }
    .stButton > button:hover {
        background: #0077ed;
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(0,113,227,0.3);
    }
    .stDownloadButton > button {
        background: #1d1d1f !important;
        color: white !important;
        border: none !important;
        border-radius: 12px !important;
        padding: 12px 28px !important;
        font-size: 15px !important;
        font-weight: 600 !important;
        width: 100% !important;
    }
    .stSpinner > div { border-top-color: #0071e3 !important; }

    div[data-testid="stExpander"] {
        background: white;
        border-radius: 14px;
        border: 1px solid rgba(0,0,0,0.06) !important;
        box-shadow: 0 2px 8px rgba(0,0,0,0.04);
    }

    .stTabs [data-baseweb="tab-list"] {
        background: #f5f5f7;
        border-radius: 12px;
        padding: 4px;
        gap: 4px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 10px;
        font-weight: 500;
        font-size: 14px;
    }
    .stTabs [aria-selected="true"] {
        background: white !important;
        box-shadow: 0 1px 4px rgba(0,0,0,0.1);
    }
</style>
""", unsafe_allow_html=True)


# ════════════════════════════════════════════════════
# HERO
# ════════════════════════════════════════════════════
st.markdown("""
<div class="hero">
    <div class="hero-badge">AMIT SOC — Blue Team Pipeline</div>
    <h1>PhishGuard</h1>
    <p>Upload a suspicious email and get an instant<br>
    multi-layer phishing risk analysis.</p>
</div>
""", unsafe_allow_html=True)


# ════════════════════════════════════════════════════
# TABS
# ════════════════════════════════════════════════════
tab1, tab2, tab3 = st.tabs(["  Analyze  ", "  History  ", "  Validation  "])


# ════════════════════════════════════════════════════
# TAB 1 — ANALYZE
# ════════════════════════════════════════════════════
with tab1:

    uploaded = st.file_uploader(
        "Upload .eml file",
        type=["eml"],
        label_visibility="collapsed"
    )

    if not uploaded:
        st.markdown("""
        <div style="text-align:center; padding: 20px 0 40px;">
            <div style="font-size:48px; margin-bottom:12px;">📧</div>
            <div style="font-size:15px; color:#6e6e73;">
                Drop an <strong>.eml</strong> file to begin analysis
            </div>
            <div style="font-size:13px; color:#aeaeb2; margin-top:6px;">
                Supports standard EML format
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Stats Row
        st.markdown("""
        <div style="display:grid; grid-template-columns:repeat(3,1fr);
                    gap:12px; margin-top:8px;">
            <div class="card" style="text-align:center; padding:20px;">
                <div style="font-size:28px; font-weight:700;
                            color:#1d1d1f; letter-spacing:-1px;">6</div>
                <div style="font-size:12px; color:#6e6e73;
                            margin-top:4px; font-weight:500;">
                    Detection Layers</div>
            </div>
            <div class="card" style="text-align:center; padding:20px;">
                <div style="font-size:28px; font-weight:700;
                            color:#1d1d1f; letter-spacing:-1px;">83.6%</div>
                <div style="font-size:12px; color:#6e6e73;
                            margin-top:4px; font-weight:500;">
                    ML Accuracy</div>
            </div>
            <div class="card" style="text-align:center; padding:20px;">
                <div style="font-size:28px; font-weight:700;
                            color:#1d1d1f; letter-spacing:-1px;">58K</div>
                <div style="font-size:12px; color:#6e6e73;
                            margin-top:4px; font-weight:500;">
                    Training Samples</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    if uploaded:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
            tmp.write(uploaded.read())
            tmp_path = tmp.name

        with st.spinner("Analyzing..."):
            report      = run_analysis(tmp_path)
            siem_result = send_alert(report)
        os.unlink(tmp_path)

        verdict = report["verdict"]
        score   = report["final_score"]
        bd      = report["breakdown"]
        auth    = report["auth_results"]
        sender  = report["sender"]
        ml      = report.get("ml_result", {})

        verdict_icons = {
            "CRITICAL": "⛔", "HIGH": "🔴",
            "MEDIUM": "🟡", "LOW": "🟢"
        }
        verdict_descs = {
            "CRITICAL": "Immediate action required",
            "HIGH":     "High probability of phishing",
            "MEDIUM":   "Suspicious — investigate",
            "LOW":      "Low risk detected"
        }

        # ── Verdict ──
        st.markdown(f"""
        <div class="verdict-wrap verdict-{verdict.lower()}">
            <div class="verdict-label">Risk Assessment</div>
            <div class="verdict-main">
                {verdict_icons.get(verdict,'')} {score}
            </div>
            <div class="verdict-sub">
                {verdict} — {verdict_descs.get(verdict,'')}
            </div>
        </div>
        <div class="alert-id">
            Alert {siem_result['alert_id']} &nbsp;·&nbsp;
            {report['timestamp'][:19]} UTC
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # ── Score Breakdown ──
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">Score Breakdown</div>',
                    unsafe_allow_html=True)
        st.markdown(f"""
        <div class="score-grid">
            <div class="score-item">
                <div class="score-num">{bd['header_score']}</div>
                <div class="score-label">Header & Auth</div>
            </div>
            <div class="score-item">
                <div class="score-num">{bd['content_score']}</div>
                <div class="score-label">Content</div>
            </div>
            <div class="score-item">
                <div class="score-num">{bd['url_score']}</div>
                <div class="score-label">URL Analysis</div>
            </div>
            <div class="score-item">
                <div class="score-num">{bd['vt_score']}</div>
                <div class="score-label">VirusTotal</div>
            </div>
            <div class="score-item">
                <div class="score-num">{bd['urlhaus_score']}</div>
                <div class="score-label">URLhaus</div>
            </div>
            <div class="score-item">
                <div class="score-num">{bd['ml_score']}</div>
                <div class="score-label">ML Classifier</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

        # ── Email Info ──
        def auth_badge(val):
            if val == "pass":
                return '<span class="badge-pass">✓ Pass</span>'
            elif val == "fail":
                return '<span class="badge-fail">✗ Fail</span>'
            return '<span class="badge-none">— None</span>'

        st.markdown(f"""
        <div class="card">
            <div class="card-title">Email Information</div>
            <div class="info-row">
                <span class="info-key">From</span>
                <span class="info-val">{sender['raw']}</span>
            </div>
            <div class="info-row">
                <span class="info-key">Domain</span>
                <span class="info-val">{sender['domain']}</span>
            </div>
            <div class="info-row">
                <span class="info-key">Subject</span>
                <span class="info-val">{report['subject']}</span>
            </div>
            <div class="info-row">
                <span class="info-key">SPF</span>
                <span class="info-val">{auth_badge(auth['spf'])}</span>
            </div>
            <div class="info-row">
                <span class="info-key">DKIM</span>
                <span class="info-val">{auth_badge(auth['dkim'])}</span>
            </div>
            <div class="info-row">
                <span class="info-key">DMARC</span>
                <span class="info-val">{auth_badge(auth['dmarc'])}</span>
            </div>
            <div class="info-row">
                <span class="info-key">ML Verdict</span>
                <span class="info-val">
                    {ml.get('ml_verdict','—')}
                    &nbsp;·&nbsp;
                    {ml.get('confidence','—')} confidence
                </span>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # ── URLs ──
        if report["urls_analyzed"]:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.markdown('<div class="card-title">URLs Detected</div>',
                        unsafe_allow_html=True)
            for u in report["urls_analyzed"]:
                vt_tag_cls = "url-tag-danger" if u["vt_verdict"] == "Malicious" \
                             else "url-tag-safe"
                urlhaus_cls = "url-tag-danger" if u["urlhaus_listed"] \
                              else "url-tag-safe"
                urlhaus_txt = "URLhaus: Listed" if u["urlhaus_listed"] \
                              else "URLhaus: Clean"
                st.markdown(f"""
                <div class="url-item">
                    <div class="url-text">{u['url']}</div>
                    <div class="url-meta">
                        <span class="url-tag url-tag-warn">
                            Rule: {u['rule_score']}/100
                        </span>
                        <span class="url-tag {vt_tag_cls}">
                            VT: {u['vt_score']}/100
                        </span>
                        <span class="url-tag {urlhaus_cls}">
                            {urlhaus_txt}
                        </span>
                        <span class="url-tag url-tag-warn">
                            {u['malicious_engines']} engines flagged
                        </span>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        # ── Flags ──
        if report["flags"]:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.markdown('<div class="card-title">Detection Flags</div>',
                        unsafe_allow_html=True)
            flags_html = '<div class="flag-grid">'
            for flag in sorted(report["flags"]):
                flags_html += f"""
                <div class="flag-pill">
                    <span>⚑</span> {flag}
                </div>"""
            flags_html += '</div>'
            st.markdown(flags_html, unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        # ── MITRE ──
        st.markdown("""
        <div class="card">
            <div class="card-title">MITRE ATT&CK</div>
            <div class="mitre-grid">
                <div class="mitre-item">
                    <div class="mitre-id">T1566</div>
                    <div class="mitre-name">Phishing</div>
                    <div class="mitre-sub">Initial Access</div>
                </div>
                <div class="mitre-item">
                    <div class="mitre-id">T1566.001</div>
                    <div class="mitre-name">Spearphishing Link</div>
                    <div class="mitre-sub">URL in email body</div>
                </div>
                <div class="mitre-item">
                    <div class="mitre-id">T1566.002</div>
                    <div class="mitre-name">Spearphishing Attachment</div>
                    <div class="mitre-sub">Malicious attachment</div>
                </div>
                <div class="mitre-item">
                    <div class="mitre-id">T1598</div>
                    <div class="mitre-name">Gather Victim Info</div>
                    <div class="mitre-sub">Credential harvesting</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # ── Recommended Actions ──
        actions = [
            ("#ff3b30", "Block sender domain at email gateway",    "Immediate"),
            ("#ff3b30", "Quarantine from all mailboxes",           "Immediate"),
            ("#ff9500", "Block malicious URLs at firewall",        "Within 1hr"),
            ("#ff9500", "Notify affected recipients",              "Within 1hr"),
            ("#ffcc00", "Submit IOCs to threat intel platform",    "Within 2hrs"),
            ("#34c759", "Update email filtering rules",            "Today"),
        ]
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">Recommended Actions</div>',
                    unsafe_allow_html=True)
        for color, text, timing in actions:
            st.markdown(f"""
            <div class="action-item">
                <div class="action-dot"
                     style="background:{color};"></div>
                <div>
                    <div class="action-text">{text}</div>
                    <div class="action-timing">{timing}</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # ── PDF ──
        if st.button("Download Incident Report  ↓"):
            with st.spinner("Generating PDF..."):
                pdf_path = generate_report(report)
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="Save PDF Report",
                    data=f,
                    file_name=f"{siem_result['alert_id']}.pdf",
                    mime="application/pdf"
                )

        with st.expander("Raw JSON"):
            st.json(report)


# ════════════════════════════════════════════════════
# TAB 2 — HISTORY
# ════════════════════════════════════════════════════
with tab2:
    alerts = get_all_alerts()

    if not alerts:
        st.markdown("""
        <div style="text-align:center; padding:60px 0;">
            <div style="font-size:40px;">📭</div>
            <div style="font-size:15px; color:#6e6e73; margin-top:12px;">
                No alerts recorded yet
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        total    = len(alerts)
        critical = sum(1 for a in alerts if a["verdict"] == "CRITICAL")
        high     = sum(1 for a in alerts if a["verdict"] == "HIGH")

        st.markdown(f"""
        <div style="display:grid; grid-template-columns:repeat(3,1fr);
                    gap:12px; margin-bottom:20px;">
            <div class="card" style="text-align:center; padding:18px;">
                <div style="font-size:28px; font-weight:700;
                            color:#1d1d1f;">{total}</div>
                <div style="font-size:12px; color:#6e6e73;
                            margin-top:4px;">Total Alerts</div>
            </div>
            <div class="card" style="text-align:center; padding:18px;">
                <div style="font-size:28px; font-weight:700;
                            color:#ff3b30;">{critical}</div>
                <div style="font-size:12px; color:#6e6e73;
                            margin-top:4px;">Critical</div>
            </div>
            <div class="card" style="text-align:center; padding:18px;">
                <div style="font-size:28px; font-weight:700;
                            color:#ff9500;">{high}</div>
                <div style="font-size:12px; color:#6e6e73;
                            margin-top:4px;">High Risk</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        colors_map = {
            "CRITICAL": "#ff3b30",
            "HIGH":     "#ff9500",
            "MEDIUM":   "#ffcc00",
            "LOW":      "#34c759"
        }

        for alert in reversed(alerts):
            v     = alert["verdict"]
            color = colors_map.get(v, "#8e8e93")
            with st.expander(
                f"{alert['alert_id']}  ·  {v}  ·  "
                f"{alert['final_score']}/100  ·  "
                f"{alert['timestamp'][:10]}"
            ):
                st.markdown(f"""
                <div class="info-row">
                    <span class="info-key">Sender</span>
                    <span class="info-val">{alert['sender']}</span>
                </div>
                <div class="info-row">
                    <span class="info-key">Subject</span>
                    <span class="info-val">{alert['subject']}</span>
                </div>
                <div class="info-row">
                    <span class="info-key">MITRE</span>
                    <span class="info-val">
                        {alert['mitre']['technique_id']} —
                        {alert['mitre']['technique_name']}
                    </span>
                </div>
                <div class="info-row">
                    <span class="info-key">IOCs</span>
                    <span class="info-val">{alert['iocs']}</span>
                </div>
                """, unsafe_allow_html=True)


# ════════════════════════════════════════════════════
# TAB 3 — VALIDATION
# ════════════════════════════════════════════════════
with tab3:
    val_path = "reports/validation_report.json"
    if not os.path.exists(val_path):
        st.warning("Run `python data/validation.py` first")
    else:
        with open(val_path) as f:
            val = json.load(f)

        st.markdown(f"""
        <div style="display:grid; grid-template-columns:repeat(2,1fr);
                    gap:12px;">
            <div class="card" style="text-align:center; padding:20px;">
                <div style="font-size:32px; font-weight:700;
                            color:#0071e3; letter-spacing:-1px;">
                    {val['accuracy']*100:.1f}%
                </div>
                <div style="font-size:12px; color:#6e6e73;
                            margin-top:4px; font-weight:500;">Accuracy</div>
            </div>
            <div class="card" style="text-align:center; padding:20px;">
                <div style="font-size:32px; font-weight:700;
                            color:#0071e3; letter-spacing:-1px;">
                    {val['precision']*100:.1f}%
                </div>
                <div style="font-size:12px; color:#6e6e73;
                            margin-top:4px; font-weight:500;">Precision</div>
            </div>
            <div class="card" style="text-align:center; padding:20px;">
                <div style="font-size:32px; font-weight:700;
                            color:#0071e3; letter-spacing:-1px;">
                    {val['recall']*100:.1f}%
                </div>
                <div style="font-size:12px; color:#6e6e73;
                            margin-top:4px; font-weight:500;">Recall</div>
            </div>
            <div class="card" style="text-align:center; padding:20px;">
                <div style="font-size:32px; font-weight:700;
                            color:#0071e3; letter-spacing:-1px;">
                    {val['auc_roc']*100:.1f}%
                </div>
                <div style="font-size:12px; color:#6e6e73;
                            margin-top:4px; font-weight:500;">AUC-ROC</div>
            </div>
        </div>

        <div class="card" style="margin-top:12px;">
            <div class="card-title">Dataset & Latency</div>
            <div class="info-row">
                <span class="info-key">Training Samples</span>
                <span class="info-val">
                    {val['dataset_size']:,}
                </span>
            </div>
            <div class="info-row">
                <span class="info-key">F1-Score</span>
                <span class="info-val">{val['f1_score']*100:.1f}%</span>
            </div>
            <div class="info-row">
                <span class="info-key">False Positive Rate</span>
                <span class="info-val">
                    {val['false_positive_rate']*100:.1f}%
                </span>
            </div>
            <div class="info-row">
                <span class="info-key">Avg Latency</span>
                <span class="info-val">{val['avg_latency_ms']} ms</span>
            </div>
        </div>

        <div class="card" style="margin-top:12px;">
            <div class="card-title">Confusion Matrix</div>
            <div style="display:grid; grid-template-columns:1fr 1fr;
                        gap:10px; text-align:center;">
                <div style="background:#e8f5e9; border-radius:12px;
                            padding:16px;">
                    <div style="font-size:24px; font-weight:700;
                                color:#2e7d32;">
                        {val['confusion_matrix']['TP']:,}
                    </div>
                    <div style="font-size:12px; color:#2e7d32;
                                margin-top:4px;">True Positive ✓</div>
                </div>
                <div style="background:#ffebee; border-radius:12px;
                            padding:16px;">
                    <div style="font-size:24px; font-weight:700;
                                color:#c62828;">
                        {val['confusion_matrix']['FP']:,}
                    </div>
                    <div style="font-size:12px; color:#c62828;
                                margin-top:4px;">False Positive ✗</div>
                </div>
                <div style="background:#ffebee; border-radius:12px;
                            padding:16px;">
                    <div style="font-size:24px; font-weight:700;
                                color:#c62828;">
                        {val['confusion_matrix']['FN']:,}
                    </div>
                    <div style="font-size:12px; color:#c62828;
                                margin-top:4px;">False Negative ✗</div>
                </div>
                <div style="background:#e8f5e9; border-radius:12px;
                            padding:16px;">
                    <div style="font-size:24px; font-weight:700;
                                color:#2e7d32;">
                        {val['confusion_matrix']['TN']:,}
                    </div>
                    <div style="font-size:12px; color:#2e7d32;
                                margin-top:4px;">True Negative ✓</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)