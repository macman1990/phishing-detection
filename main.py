import streamlit as st
import json
import html
import os
import tempfile
from modules.risk_engine import run_analysis
from modules.url_analyzer import analyze_url
from modules.report_generator import generate_report
from modules.siem_integration import send_alert, get_all_alerts

st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
}

/* ── Reset & Base ── */
.stApp { background: #f5f5f7 !important; }
#MainMenu, footer, header { visibility: hidden; }
.stDeployButton { display: none; }
section[data-testid="stMain"] > div {
    padding: 1rem 1rem 4rem !important;
}

/* ── Responsive Container ── */
.block-container {
    max-width: 860px !important;
    padding: 0 1rem !important;
    margin: 0 auto !important;
}

/* ── Hero ── */
.hero {
    text-align: center;
    padding: 40px 16px 28px;
}
.hero-badge {
    display: inline-block;
    background: #e8f5e9;
    color: #2e7d32;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
    padding: 5px 14px;
    border-radius: 20px;
    margin-bottom: 16px;
    text-transform: uppercase;
}
.hero h1 {
    font-size: clamp(28px, 5vw, 44px);
    font-weight: 700;
    color: #1d1d1f;
    margin: 0 0 10px;
    letter-spacing: -1.5px;
    line-height: 1.1;
}
.hero p {
    font-size: clamp(14px, 2.5vw, 17px);
    color: #6e6e73;
    margin: 0;
    line-height: 1.6;
}

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] {
    background: #e8e8ed !important;
    border-radius: 12px !important;
    padding: 4px !important;
    gap: 2px !important;
    border: none !important;
}
.stTabs [data-baseweb="tab"] {
    border-radius: 10px !important;
    font-size: 14px !important;
    font-weight: 500 !important;
    color: #6e6e73 !important;
    padding: 8px 16px !important;
    border: none !important;
}
.stTabs [aria-selected="true"] {
    background: white !important;
    color: #1d1d1f !important;
    box-shadow: 0 1px 4px rgba(0,0,0,0.12) !important;
}
.stTabs [data-baseweb="tab-border"] { display: none !important; }
.stTabs [data-baseweb="tab-panel"] { padding: 16px 0 0 !important; }

/* ── Cards ── */
.card {
    background: white;
    border-radius: 16px;
    padding: 20px;
    margin: 10px 0;
    border: 1px solid rgba(0,0,0,0.06);
    box-shadow: 0 2px 8px rgba(0,0,0,0.05);
}
.card-title {
    font-size: 11px;
    font-weight: 700;
    color: #aeaeb2;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin-bottom: 14px;
}

/* ── Verdict ── */
.verdict-wrap {
    border-radius: 20px;
    padding: clamp(20px, 4vw, 32px);
    text-align: center;
    margin: 16px 0 8px;
}
.verdict-critical { background: linear-gradient(135deg,#ff3b30,#c0392b); }
.verdict-high     { background: linear-gradient(135deg,#ff9500,#e67e22); }
.verdict-medium   { background: linear-gradient(135deg,#ffcc00,#f39c12); }
.verdict-low      { background: linear-gradient(135deg,#34c759,#27ae60); }

.verdict-label {
    font-size: 11px; font-weight: 700;
    letter-spacing: 1.5px; text-transform: uppercase;
    color: rgba(255,255,255,0.75); margin-bottom: 6px;
}
.verdict-main {
    font-size: clamp(36px, 8vw, 56px);
    font-weight: 800; color: white;
    letter-spacing: -2px; line-height: 1;
    margin-bottom: 6px;
}
.verdict-sub {
    font-size: clamp(13px, 2.5vw, 16px);
    color: rgba(255,255,255,0.8);
}
.alert-id {
    font-size: 11px; color: #aeaeb2;
    text-align: center; margin-top: 6px;
    font-family: 'SF Mono', monospace;
}

/* ── Score Grid ── */
.score-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 10px;
}
@media (max-width: 500px) {
    .score-grid { grid-template-columns: repeat(2, 1fr); }
}
.score-item {
    background: #f5f5f7; border-radius: 12px;
    padding: 14px 10px; text-align: center;
}
.score-num {
    font-size: clamp(22px, 4vw, 28px);
    font-weight: 700; color: #1d1d1f;
    letter-spacing: -1px; line-height: 1;
}
.score-label {
    font-size: 11px; color: #6e6e73;
    margin-top: 4px; font-weight: 500;
}

/* ── Info Rows ── */
.info-row {
    display: flex; justify-content: space-between;
    align-items: flex-start; padding: 9px 0;
    border-bottom: 1px solid #f5f5f7; gap: 12px;
}
.info-row:last-child { border-bottom: none; }
.info-key {
    font-size: 13px; color: #6e6e73;
    font-weight: 500; white-space: nowrap;
    flex-shrink: 0;
}
.info-val {
    font-size: 13px; color: #1d1d1f;
    font-weight: 500; text-align: right;
    word-break: break-all;
}

/* ── Auth Badges ── */
.badge-pass {
    background:#e8f5e9; color:#2e7d32;
    font-size:12px; font-weight:700;
    padding:3px 10px; border-radius:20px;
    display:inline-block;
}
.badge-fail {
    background:#ffebee; color:#c62828;
    font-size:12px; font-weight:700;
    padding:3px 10px; border-radius:20px;
    display:inline-block;
}
.badge-none {
    background:#fff8e1; color:#f57f17;
    font-size:12px; font-weight:700;
    padding:3px 10px; border-radius:20px;
    display:inline-block;
}

/* ── Flags ── */
.flag-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 8px;
}
.flag-pill {
    background: #fff2f2;
    border: 1px solid #ffcdd2;
    color: #c62828; font-size: 12px;
    font-weight: 500; padding: 7px 12px;
    border-radius: 8px; display: flex;
    align-items: center; gap: 6px;
    word-break: break-word;
}

/* ── URL Items ── */
.url-item {
    background: #f5f5f7; border-radius: 12px;
    padding: 14px 16px; margin: 8px 0;
}
.url-text {
    font-size: 12px;
    font-family: 'SF Mono','Courier New',monospace;
    color: #1d1d1f; word-break: break-all;
    margin-bottom: 10px;
}
.url-meta { display: flex; gap: 6px; flex-wrap: wrap; }
.url-tag {
    font-size: 11px; font-weight: 700;
    padding: 3px 9px; border-radius: 6px;
}
.url-tag-danger { background:#ffebee; color:#c62828; }
.url-tag-warn   { background:#fff8e1; color:#e65100; }
.url-tag-safe   { background:#e8f5e9; color:#2e7d32; }

/* ── URL Checker ── */
.url-checker-result {
    background: white; border-radius: 16px;
    padding: 20px; margin: 12px 0;
    border: 1px solid rgba(0,0,0,0.06);
    box-shadow: 0 2px 8px rgba(0,0,0,0.05);
}
.url-verdict-malicious {
    background: #ffebee; border-left: 4px solid #c62828;
    padding: 12px 16px; border-radius: 0 10px 10px 0;
    margin-bottom: 14px;
}
.url-verdict-suspicious {
    background: #fff8e1; border-left: 4px solid #f57f17;
    padding: 12px 16px; border-radius: 0 10px 10px 0;
    margin-bottom: 14px;
}
.url-verdict-clean {
    background: #e8f5e9; border-left: 4px solid #2e7d32;
    padding: 12px 16px; border-radius: 0 10px 10px 0;
    margin-bottom: 14px;
}
.url-verdict-title {
    font-size: 15px; font-weight: 700;
    color: #1d1d1f; margin-bottom: 2px;
}
.url-verdict-sub { font-size: 12px; color: #6e6e73; }

/* ── MITRE ── */
.mitre-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: 10px;
}
.mitre-item {
    background: #f5f5f7; border-radius: 12px; padding: 14px;
}
.mitre-id {
    font-size: 13px; font-weight: 700;
    color: #0071e3; margin-bottom: 4px;
}
.mitre-name { font-size: 12px; color: #1d1d1f; font-weight: 600; }
.mitre-sub  { font-size: 11px; color: #6e6e73; margin-top: 2px; }

/* ── Actions ── */
.action-item {
    display: flex; align-items: flex-start;
    gap: 12px; padding: 10px 0;
    border-bottom: 1px solid #f5f5f7;
}
.action-item:last-child { border-bottom: none; }
.action-dot {
    width: 8px; height: 8px; border-radius: 50%;
    margin-top: 5px; flex-shrink: 0;
}
.action-text { font-size: 14px; color: #1d1d1f; }
.action-timing { font-size: 11px; color: #aeaeb2; margin-top: 2px; }

/* ── Buttons ── */
.stButton > button {
    background: #0071e3 !important;
    color: white !important;
    border: none !important;
    border-radius: 12px !important;
    padding: 12px 28px !important;
    font-size: 15px !important;
    font-weight: 600 !important;
    width: 100% !important;
    transition: all 0.2s !important;
    font-family: 'Inter', sans-serif !important;
}
.stButton > button:hover {
    background: #0077ed !important;
    transform: translateY(-1px) !important;
    box-shadow: 0 4px 12px rgba(0,113,227,0.3) !important;
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

/* ── Text Input ── */
.stTextInput > div > div > input {
    border-radius: 12px !important;
    border: 1.5px solid #d2d2d7 !important;
    padding: 12px 16px !important;
    font-size: 14px !important;
    background: white !important;
    color: #1d1d1f !important;
    font-family: 'Inter', sans-serif !important;
    transition: border 0.2s !important;
}
.stTextInput > div > div > input:focus {
    border-color: #0071e3 !important;
    box-shadow: 0 0 0 3px rgba(0,113,227,0.15) !important;
}

/* ── File Uploader ── */
[data-testid="stFileUploader"] {
    background: white !important;
    border-radius: 16px !important;
    padding: 8px !important;
    border: 2px dashed #d2d2d7 !important;
}
[data-testid="stFileUploader"]:hover {
    border-color: #0071e3 !important;
}

/* ── Expander ── */
div[data-testid="stExpander"] {
    background: white !important;
    border-radius: 14px !important;
    border: 1px solid rgba(0,0,0,0.06) !important;
    box-shadow: 0 2px 6px rgba(0,0,0,0.04) !important;
    overflow: hidden !important;
}
div[data-testid="stExpander"] summary {
    font-weight: 500 !important;
    color: #1d1d1f !important;
    font-size: 14px !important;
    padding: 14px 16px !important;
}

/* ── Spinner ── */
.stSpinner > div {
    border-top-color: #0071e3 !important;
}

/* ── Metric ── */
[data-testid="stMetricValue"] {
    color: #1d1d1f !important;
    font-weight: 700 !important;
}

/* ── Stats Row ── */
.stats-row {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 12px; margin: 16px 0;
}
@media (max-width: 480px) {
    .stats-row { grid-template-columns: repeat(2, 1fr); }
}
.stat-card {
    background: white; border-radius: 16px;
    padding: 18px; text-align: center;
    border: 1px solid rgba(0,0,0,0.06);
    box-shadow: 0 2px 8px rgba(0,0,0,0.04);
}
.stat-num {
    font-size: 30px; font-weight: 700;
    color: #1d1d1f; letter-spacing: -1px;
}
.stat-label {
    font-size: 12px; color: #6e6e73;
    margin-top: 4px; font-weight: 500;
}
</style>
""", unsafe_allow_html=True)


# ════════════════════════════════
# HERO
# ════════════════════════════════
st.markdown("""
<div class="hero">
    <div class="hero-badge">AMIT SOC — Blue Team Pipeline</div>
    <h1>PhishGuard</h1>
    <p>Multi-layer phishing detection powered by<br>
    rules, threat intelligence & machine learning.</p>
</div>
""", unsafe_allow_html=True)


# ════════════════════════════════
# TABS
# ════════════════════════════════
tab1, tab2, tab3, tab4 = st.tabs([
    "📧  Email Analysis",
    "🔗  URL Checker",
    "📋  Alerts History",
    "📊  Validation"
])


# ════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════
def auth_badge(val):
    if val == "pass":
        return '<span class="badge-pass">✓ Pass</span>'
    elif val == "fail":
        return '<span class="badge-fail">✗ Fail</span>'
    return '<span class="badge-none">— None</span>'


def render_verdict(report, siem_result):
    verdict = report["verdict"]
    score   = report["final_score"]
    icons   = {"CRITICAL":"⛔","HIGH":"🔴","MEDIUM":"🟡","LOW":"🟢"}
    descs   = {
        "CRITICAL": "Immediate action required",
        "HIGH":     "High probability of phishing",
        "MEDIUM":   "Suspicious — investigate",
        "LOW":      "Low risk detected"
    }
    st.markdown(f"""
    <div class="verdict-wrap verdict-{verdict.lower()}">
        <div class="verdict-label">Risk Assessment</div>
        <div class="verdict-main">
            {icons.get(verdict,'')} {score}
        </div>
        <div class="verdict-sub">
            {verdict} — {descs.get(verdict,'')}
        </div>
    </div>
    <div class="alert-id">
        Alert {siem_result['alert_id']}
        &nbsp;·&nbsp;
        {report['timestamp'][:19]} UTC
    </div>
    """, unsafe_allow_html=True)


def render_scores(bd):
    import plotly.graph_objects as go

    scores = {
        "Header":   bd.get("header_score",   0),
        "Content":  bd.get("content_score",  0),
        "URL":      bd.get("url_score",      0),
        "VT":       bd.get("vt_score",       0),
        "URLhaus":  bd.get("urlhaus_score",  0),
        "ML":       bd.get("ml_score",       0),
        "Advanced": bd.get("advanced_score", 0),
    }
    final = sum(
        v * w for v, w in zip(scores.values(),
        [0.22, 0.18, 0.18, 0.14, 0.08, 0.10, 0.10])
    )

    bar_colors = [
        "#ff3b30" if s >= 70 else
        "#ff9500" if s >= 40 else
        "#34c759"
        for s in scores.values()
    ]

    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=list(scores.keys()),
        y=list(scores.values()),
        marker_color=bar_colors,
        marker_line_width=0,
        text=[str(v) for v in scores.values()],
        textposition="outside",
        textfont=dict(size=11, color="#1d1d1f"),
    ))
    fig.update_layout(
        height=220,
        margin=dict(t=20, b=0, l=0, r=0),
        paper_bgcolor="white",
        plot_bgcolor="white",
        yaxis=dict(range=[0,115], showgrid=True,
                   gridcolor="#f5f5f7", zeroline=False,
                   tickfont=dict(size=10, color="#6e6e73")),
        xaxis=dict(tickfont=dict(size=11, color="#1d1d1f")),
        showlegend=False,
        font=dict(family="Inter, sans-serif"),
        bargap=0.3,
    )

    # Radar Chart
    categories = list(scores.keys())
    values     = list(scores.values())
    values_closed = values + [values[0]]
    cats_closed   = categories + [categories[0]]

    fig_radar = go.Figure()
    fig_radar.add_trace(go.Scatterpolar(
        r=values_closed,
        theta=cats_closed,
        fill="toself",
        fillcolor="rgba(0,113,227,0.15)",
        line=dict(color="#0071e3", width=2),
        marker=dict(size=5, color="#0071e3"),
    ))
    fig_radar.update_layout(
        polar=dict(
            bgcolor="white",
            radialaxis=dict(
                visible=True, range=[0,100],
                tickfont=dict(size=8, color="#6e6e73"),
                gridcolor="#e5e5ea",
            ),
            angularaxis=dict(
                tickfont=dict(size=10, color="#1d1d1f"),
                gridcolor="#e5e5ea",
            ),
        ),
        height=220,
        margin=dict(t=20, b=20, l=20, r=20),
        paper_bgcolor="white",
        showlegend=False,
        font=dict(family="Inter, sans-serif"),
    )

    col1, col2 = st.columns(2)
    with col1:
        st.markdown('<div class="card"><div class="card-title">Score by Layer</div>',
                    unsafe_allow_html=True)
        st.plotly_chart(fig, width="stretch",
                        config={"displayModeBar": False})
        st.markdown('</div>', unsafe_allow_html=True)
    with col2:
        st.markdown('<div class="card"><div class="card-title">Risk Radar</div>',
                    unsafe_allow_html=True)
        st.plotly_chart(fig_radar, width="stretch",
                        config={"displayModeBar": False})
        st.markdown('</div>', unsafe_allow_html=True)

    # Score cards below charts
    st.markdown(f"""
    <div class="score-grid" style="margin-top:10px;">
        <div class="score-item">
            <div class="score-num">{html.escape(str(bd.get("header_score",0)))}</div>
            <div class="score-label">Header & Auth</div>
        </div>
        <div class="score-item">
            <div class="score-num">{html.escape(str(bd.get("content_score",0)))}</div>
            <div class="score-label">Content</div>
        </div>
        <div class="score-item">
            <div class="score-num">{html.escape(str(bd.get("url_score",0)))}</div>
            <div class="score-label">URL Rules</div>
        </div>
        <div class="score-item">
            <div class="score-num">{html.escape(str(bd.get("vt_score",0)))}</div>
            <div class="score-label">VirusTotal</div>
        </div>
        <div class="score-item">
            <div class="score-num">{html.escape(str(bd.get("urlhaus_score",0)))}</div>
            <div class="score-label">URLhaus</div>
        </div>
        <div class="score-item">
            <div class="score-num">{html.escape(str(bd.get("ml_score",0)))}</div>
            <div class="score-label">ML Model</div>
        </div>
        <div class="score-item">
            <div class="score-num">{html.escape(str(bd.get("advanced_score",0)))}</div>
            <div class="score-label">Advanced</div>
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_email_info(report):
    sender = report["sender"]
    auth   = report["auth_results"]
    ml     = report.get("ml_result", {})
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
        <div class="info-row">
            <span class="info-key">Attachments</span>
            <span class="info-val">
                {len(report.get('attachments', []))}
            </span>
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_urls(report):
    urls = report.get("urls_analyzed", [])
    if not urls:
        return
    st.markdown('<div class="card"><div class="card-title">URLs Detected</div>',
                unsafe_allow_html=True)
    for u in urls:
        vt_cls = "url-tag-danger" if u["vt_verdict"]=="Malicious" \
                 else "url-tag-safe"
        uh_cls = "url-tag-danger" if u["urlhaus_listed"] \
                 else "url-tag-safe"
        uh_txt = "URLhaus: Listed" if u["urlhaus_listed"] \
                 else "URLhaus: Clean"
        st.markdown(f"""
        <div class="url-item">
            <div class="url-text">{u['url']}</div>
            <div class="url-meta">
                <span class="url-tag url-tag-warn">
                    Score: {u['rule_score']}/100
                </span>
                <span class="url-tag {vt_cls}">
                    VT: {u['vt_score']}/100
                </span>
                <span class="url-tag {uh_cls}">{uh_txt}</span>
                <span class="url-tag url-tag-warn">
                    {u['malicious_engines']} engines
                </span>
            </div>
        </div>
        """, unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)


def render_flags(report):
    flags = sorted(report.get("flags", []))
    if not flags:
        return
    st.markdown('<div class="card"><div class="card-title">Detection Flags</div>',
                unsafe_allow_html=True)
    html = '<div class="flag-grid">'
    for f in flags:
        html += f'<div class="flag-pill">⚑ {f}</div>'
    html += '</div>'
    st.markdown(html + '</div>', unsafe_allow_html=True)


def render_mitre():
    st.markdown("""
    <div class="card">
        <div class="card-title">MITRE ATT&CK Mapping</div>
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
                <div class="mitre-sub">Malicious file</div>
            </div>
            <div class="mitre-item">
                <div class="mitre-id">T1598</div>
                <div class="mitre-name">Gather Victim Info</div>
                <div class="mitre-sub">Credential harvesting</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_actions(verdict):
    actions = [
        ("#ff3b30", "Block sender domain at email gateway",   "Immediate"),
        ("#ff3b30", "Quarantine from all mailboxes",          "Immediate"),
        ("#ff9500", "Block malicious URLs at firewall/proxy", "Within 1hr"),
        ("#ff9500", "Notify affected recipients",             "Within 1hr"),
        ("#ffcc00", "Submit IOCs to threat intel platform",   "Within 2hrs"),
        ("#34c759", "Update email filtering rules",           "Today"),
    ]
    if verdict == "CRITICAL":
        actions.insert(0,(
            "#c62828",
            "Escalate to Tier 2 SOC analyst",
            "Immediate"
        ))
    st.markdown('<div class="card"><div class="card-title">Recommended Actions</div>',
                unsafe_allow_html=True)
    for color, text, timing in actions:
        st.markdown(f"""
        <div class="action-item">
            <div class="action-dot" style="background:{color};"></div>
            <div>
                <div class="action-text">{text}</div>
                <div class="action-timing">{timing}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)


# ════════════════════════════════════════════════════
# TAB 1 — EMAIL ANALYSIS
# ════════════════════════════════════════════════════
with tab1:
    uploaded = st.file_uploader(
        "Upload .eml file",
        type=["eml"],
        label_visibility="collapsed"
    )

    if not uploaded:
        st.markdown("""
        <div style="text-align:center; padding:24px 0 32px;">
            <div style="font-size:44px; margin-bottom:12px;">📧</div>
            <div style="font-size:15px; color:#1d1d1f; font-weight:500;">
                Drop an .eml file to begin
            </div>
            <div style="font-size:13px; color:#aeaeb2; margin-top:6px;">
                Supports standard EML format
            </div>
        </div>
        <div class="stats-row">
            <div class="stat-card">
                <div class="stat-num">6</div>
                <div class="stat-label">Detection Layers</div>
            </div>
            <div class="stat-card">
                <div class="stat-num">83.6%</div>
                <div class="stat-label">ML Accuracy</div>
            </div>
            <div class="stat-card">
                <div class="stat-num">58K</div>
                <div class="stat-label">Training Samples</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    if uploaded:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
            tmp.write(uploaded.read())
            tmp_path = tmp.name

        with st.spinner("Running multi-layer analysis..."):
            report      = run_analysis(tmp_path)
            siem_result = send_alert(report)
        os.unlink(tmp_path)

        render_verdict(report, siem_result)
        st.markdown("<br>", unsafe_allow_html=True)
        render_scores(report["breakdown"])
        render_email_info(report)
        render_urls(report)
        render_flags(report)
        render_mitre()

        # Advanced Analysis Section
        adv = report.get("advanced", {})
        if adv:
            st.markdown("""
            <div class="card">
                <div class="card-title">Advanced Analysis</div>
            """, unsafe_allow_html=True)

            # Domain Age
            da = adv.get("domain_age", {})
            age_val = f"{da.get('age_days')} days" if da.get('age_days') else "Unknown"
            st.markdown(f"""
                <div class="info-row">
                    <span class="info-key">Domain Age</span>
                    <span class="info-val">{html.escape(str(age_val))}</span>
                </div>
                <div class="info-row">
                    <span class="info-key">Registrar</span>
                    <span class="info-val">{html.escape(str(da.get('registrar') or '—'))}</span>
                </div>
                <div class="info-row">
                    <span class="info-key">Created</span>
                    <span class="info-val">{html.escape(str(da.get('creation_date') or '—'))}</span>
                </div>
                <div class="info-row">
                    <span class="info-key">Expires</span>
                    <span class="info-val">{html.escape(str(da.get('expiry_date') or '—'))}</span>
                </div>
            """, unsafe_allow_html=True)

            # IP Reputation
            ip = adv.get("ip_reputation", {})
            st.markdown(f"""
                <div class="info-row">
                    <span class="info-key">IP Address</span>
                    <span class="info-val">{html.escape(str(ip.get('ip') or '—'))}</span>
                </div>
                <div class="info-row">
                    <span class="info-key">Reverse DNS</span>
                    <span class="info-val">{html.escape(str(ip.get('reverse_dns') or '—'))}</span>
                </div>
            """, unsafe_allow_html=True)

            # Redirect Chain
            rd = adv.get("redirect", {})
            hops = rd.get('hops', 0)
            final_url = html.escape(str(rd.get('final_url', '—') or '—')[:60])
            st.markdown(f"""
                <div class="info-row">
                    <span class="info-key">Redirect Hops</span>
                    <span class="info-val">{html.escape(str(hops))}</span>
                </div>
                <div class="info-row">
                    <span class="info-key">Final URL</span>
                    <span class="info-val"
                          style="font-family:monospace; font-size:11px;">
                        {final_url}
                    </span>
                </div>
            """, unsafe_allow_html=True)

            # Unicode
            uc = adv.get("unicode", {})
            suspicious_chars = uc.get('suspicious_chars')
            suspicious_value = (
                "🔴 " + html.escape(str(suspicious_chars))
                if suspicious_chars else "🟢 None"
            )
            st.markdown(f"""
                <div class="info-row">
                    <span class="info-key">Punycode</span>
                    <span class="info-val">
                        {"🔴 Detected" if uc.get('is_punycode') else "🟢 None"}
                    </span>
                </div>
                <div class="info-row">
                    <span class="info-key">Homograph Attack</span>
                    <span class="info-val">
                        {suspicious_value}
                    </span>
                </div>
            """, unsafe_allow_html=True)

            st.markdown('</div>', unsafe_allow_html=True)

        render_actions(report["verdict"])

        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("📄  Download Incident Report"):
            with st.spinner("Generating PDF..."):
                pdf_path = generate_report(report)
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="⬇️  Save PDF Report",
                    data=f,
                    file_name=f"{siem_result['alert_id']}.pdf",
                    mime="application/pdf"
                )

        with st.expander("🔍  Raw JSON Report"):
            st.json(report)


# ════════════════════════════════════════════════════
# TAB 2 — URL CHECKER
# ════════════════════════════════════════════════════
with tab2:
    st.markdown("""
    <div style="padding:8px 0 16px;">
        <div style="font-size:22px; font-weight:700;
                    color:#1d1d1f; letter-spacing:-0.5px;">
            URL Checker
        </div>
        <div style="font-size:14px; color:#6e6e73; margin-top:4px;">
            Check any URL across 4 threat intelligence sources instantly.
        </div>
    </div>
    """, unsafe_allow_html=True)

    url_input = st.text_input(
        "Enter URL",
        placeholder="https://example.com or http://suspicious-site.xyz/login",
        label_visibility="collapsed"
    )

    check_btn = st.button("🔍  Analyze URL")

    if check_btn and url_input:
        url_input = url_input.strip()

        with st.spinner("Checking across 4 intelligence sources..."):
            from modules.threat_intel import full_url_check
            rule_result = analyze_url(url_input)
            full_result = full_url_check(url_input)

        combined = full_result["combined_score"]
        verdict = full_result["final_verdict"]
        sources = full_result["sources"]
        vt = sources["virustotal"]
        uh = sources["urlhaus"]
        pt = sources["phishtank"]
        gsb = sources["google_safebrowsing"]

        verdict_colors = {
            "Malicious": ("#ff3b30", "🔴 MALICIOUS"),
            "Suspicious": ("#ff9500", "🟡 SUSPICIOUS"),
            "Clean": ("#34c759", "🟢 CLEAN"),
        }
        verdict_color, verdict_label = verdict_colors.get(
            verdict, ("#aeaeb2", "⚪ UNKNOWN")
        )

        st.markdown(f"""
        <div style="background:{verdict_color}; border-radius:16px;
                    padding:24px; text-align:center; margin:12px 0;">
            <div style="font-size:11px; font-weight:700;
                        letter-spacing:1.5px; color:rgba(255,255,255,0.8);
                        text-transform:uppercase; margin-bottom:6px;">
                Threat Assessment
            </div>
            <div style="font-size:36px; font-weight:800;
                        color:white; letter-spacing:-1px;">
                {verdict_label}
            </div>
            <div style="font-size:14px; color:rgba(255,255,255,0.8);
                        margin-top:4px;">
                Combined Score: {combined}/100
            </div>
        </div>
        """, unsafe_allow_html=True)

        import plotly.graph_objects as go

        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=combined,
            domain={"x": [0, 1], "y": [0, 1]},
            title={"text": "Risk Score", "font": {"size": 14,
                                                   "color": "#6e6e73"}},
            number={"font": {"size": 32, "color": "#1d1d1f"},
                    "suffix": "/100"},
            gauge={
                "axis": {"range": [0, 100],
                         "tickfont": {"size": 10, "color": "#6e6e73"},
                         "tickwidth": 1,
                         "tickcolor": "#e5e5ea"},
                "bar": {"color": verdict_color, "thickness": 0.25},
                "bgcolor": "white",
                "borderwidth": 0,
                "steps": [
                    {"range": [0, 25], "color": "#e8f5e9"},
                    {"range": [25, 50], "color": "#fff8e1"},
                    {"range": [50, 75], "color": "#fff3e0"},
                    {"range": [75, 100], "color": "#ffebee"},
                ],
                "threshold": {
                    "line": {"color": verdict_color, "width": 3},
                    "thickness": 0.8,
                    "value": combined
                }
            }
        ))
        fig_gauge.update_layout(
            height=220,
            margin=dict(t=30, b=0, l=20, r=20),
            paper_bgcolor="white",
            plot_bgcolor="white",
            font=dict(family="Inter, sans-serif")
        )

        api_names = ["Rule Engine", "VirusTotal", "URLhaus",
                     "PhishTank", "Google SB"]
        api_scores = [
            rule_result.get("score", 0),
            vt.get("vt_score", 0),
            100 if uh.get("listed") else 0,
            pt.get("score", 0),
            gsb.get("score", 0),
        ]
        bar_colors = [
            "#ff3b30" if score >= 70 else
            "#ff9500" if score >= 40 else
            "#34c759"
            for score in api_scores
        ]
        fig_bar = go.Figure(go.Bar(
            x=api_names,
            y=api_scores,
            marker_color=bar_colors,
            marker_line_width=0,
            text=[str(score) for score in api_scores],
            textposition="outside",
            textfont=dict(size=11, color="#1d1d1f"),
        ))
        fig_bar.update_layout(
            height=220,
            margin=dict(t=20, b=0, l=0, r=0),
            paper_bgcolor="white",
            plot_bgcolor="white",
            yaxis=dict(range=[0, 110], showgrid=True,
                       gridcolor="#f5f5f7", zeroline=False,
                       tickfont=dict(size=10, color="#6e6e73")),
            xaxis=dict(tickfont=dict(size=11, color="#1d1d1f")),
            showlegend=False,
            font=dict(family="Inter, sans-serif"),
            bargap=0.3,
        )

        col_g, col_b = st.columns(2)
        with col_g:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.markdown('<div class="card-title">Risk Gauge</div>',
                        unsafe_allow_html=True)
            st.plotly_chart(fig_gauge, width="stretch",
                            config={"displayModeBar": False})
            st.markdown('</div>', unsafe_allow_html=True)
        with col_b:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.markdown('<div class="card-title">Score by Source</div>',
                        unsafe_allow_html=True)
            st.plotly_chart(fig_bar, width="stretch",
                            config={"displayModeBar": False})
            st.markdown('</div>', unsafe_allow_html=True)

        st.markdown("---", unsafe_allow_html=True)
        st.markdown(
            '<div class="card-title" style="margin-top:8px;">'
            'Intelligence Sources</div>',
            unsafe_allow_html=True
        )

        s1, s2, s3, s4 = st.columns(4)

        def src_card(col, name, score, verdict_val, detail):
            color = (
                "#ff3b30" if verdict_val in ["Malicious", "Phishing"]
                else "#ff9500" if verdict_val == "Suspicious"
                else "#34c759" if verdict_val == "Clean"
                else "#aeaeb2"
            )
            col.markdown(f"""
            <div style="background:#f5f5f7; border-radius:14px;
                        padding:14px; text-align:center;
                        border-top:3px solid {color};">
                <div style="font-size:11px; color:#6e6e73;
                            font-weight:600; text-transform:uppercase;
                            letter-spacing:0.5px; margin-bottom:8px;">
                    {html.escape(str(name))}
                </div>
                <div style="font-size:22px; font-weight:700;
                            color:{color}; letter-spacing:-0.5px;">
                    {html.escape(str(score))}/100
                </div>
                <div style="font-size:11px; color:#6e6e73;
                            margin-top:4px;">
                    {html.escape(str(detail))}
                </div>
            </div>
            """, unsafe_allow_html=True)

        src_card(s1, "Rule Engine", rule_result.get("score", 0),
                 rule_result.get("verdict", "—"),
                 rule_result.get("verdict", "—"))
        src_card(s2, "VirusTotal", vt.get("vt_score", 0),
                 vt.get("verdict", "—"),
                 f"{vt.get('malicious_engines', 0)} engines flagged")
        src_card(s3, "URLhaus", 100 if uh.get("listed") else 0,
                 "Malicious" if uh.get("listed") else "Clean",
                 "Listed" if uh.get("listed") else "Not listed")
        src_card(s4, "PhishTank", pt.get("score", 0),
                 pt.get("verdict", "—"),
                 "Verified" if pt.get("verified") else "Not listed")

        st.markdown("<br>", unsafe_allow_html=True)

        safe_url = html.escape(url_input)
        safe_domain = html.escape(str(rule_result.get("domain", "—")))
        safe_gsb_verdict = html.escape(str(gsb.get("verdict", "Unknown")))
        safe_gsb_threats = html.escape(", ".join(gsb.get("threats", [])))
        https_label = (
            "🟢 Yes" if "no_https" not in rule_result.get("flags", [])
            else "🔴 No"
        )
        st.markdown(f"""
        <div class="card">
            <div class="card-title">URL Analysis</div>
            <div class="info-row">
                <span class="info-key">URL</span>
                <span class="info-val"
                      style="font-family:monospace; font-size:12px;">
                    {safe_url}
                </span>
            </div>
            <div class="info-row">
                <span class="info-key">Domain</span>
                <span class="info-val">{safe_domain}</span>
            </div>
            <div class="info-row">
                <span class="info-key">HTTPS</span>
                <span class="info-val">{https_label}</span>
            </div>
            <div class="info-row">
                <span class="info-key">Google Safe Browsing</span>
                <span class="info-val">
                    {safe_gsb_verdict}
                    {" ? " + safe_gsb_threats if safe_gsb_threats else ""}
                </span>
            </div>
            <div class="info-row">
                <span class="info-key">Sources Flagged</span>
                <span class="info-val">
                    {full_result.get("malicious_count", 0)} / 4
                </span>
            </div>
        </div>
        """, unsafe_allow_html=True)

        flags = rule_result.get("flags", [])
        if flags:
            st.markdown('<div class="card"><div class="card-title">'
                        'Rule Engine Flags</div>', unsafe_allow_html=True)
            flags_html = '<div class="flag-grid">'
            for flag in flags:
                flags_html += (
                    f'<div class="flag-pill">⚑ '
                    f'{html.escape(str(flag))}</div>'
                )
            st.markdown(flags_html + '</div></div>', unsafe_allow_html=True)

    elif check_btn and not url_input:
        st.warning("Please enter a URL first")

    if not check_btn:
        st.markdown("""
        <div style="text-align:center; padding:32px 0 20px;">
            <div style="font-size:40px; margin-bottom:12px;">🔗</div>
            <div style="font-size:15px; color:#1d1d1f; font-weight:500;">
                Enter any URL to analyze
            </div>
            <div style="font-size:13px; color:#aeaeb2; margin-top:6px;">
                Checked against 4 intelligence sources
            </div>
        </div>
        <div class="card">
            <div class="card-title">Intelligence Sources</div>
            <div class="info-row">
                <span class="info-key">🔵 VirusTotal</span>
                <span class="info-val">70+ AV engines</span>
            </div>
            <div class="info-row">
                <span class="info-key">🟠 URLhaus</span>
                <span class="info-val">Malware URL blacklist</span>
            </div>
            <div class="info-row">
                <span class="info-key">🔴 PhishTank</span>
                <span class="info-val">Community phishing database</span>
            </div>
            <div class="info-row">
                <span class="info-key">🔵 Google Safe Browsing</span>
                <span class="info-val">Google threat database</span>
            </div>
        </div>
        """, unsafe_allow_html=True)


with tab3:
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
        critical = sum(1 for a in alerts if a["verdict"]=="CRITICAL")
        high     = sum(1 for a in alerts if a["verdict"]=="HIGH")
        medium   = sum(1 for a in alerts if a["verdict"]=="MEDIUM")

        st.markdown(f"""
        <div class="stats-row">
            <div class="stat-card">
                <div class="stat-num">{total}</div>
                <div class="stat-label">Total Alerts</div>
            </div>
            <div class="stat-card">
                <div class="stat-num" style="color:#ff3b30;">
                    {critical}
                </div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-num" style="color:#ff9500;">
                    {high}
                </div>
                <div class="stat-label">High Risk</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        colors_map = {
            "CRITICAL":"#ff3b30","HIGH":"#ff9500",
            "MEDIUM":"#ffcc00","LOW":"#34c759"
        }

        for alert in reversed(alerts):
            v     = alert["verdict"]
            color = colors_map.get(v, "#aeaeb2")
            with st.expander(
                f"{alert['alert_id']}  ·  "
                f"{v}  ·  {alert['final_score']}/100  ·  "
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
                <div class="info-row">
                    <span class="info-key">Flags</span>
                    <span class="info-val">
                        {', '.join(alert['flags'][:5])}
                        {"..." if len(alert['flags'])>5 else ""}
                    </span>
                </div>
                """, unsafe_allow_html=True)


# ════════════════════════════════════════════════════
# TAB 4 — VALIDATION
# ════════════════════════════════════════════════════
with tab4:
    val_path = "reports/validation_report.json"
    if not os.path.exists(val_path):
        st.warning("Run `python data/validation.py` first")
    else:
        with open(val_path) as f:
            val = json.load(f)

        st.markdown(f"""
        <div class="stats-row">
            <div class="stat-card">
                <div class="stat-num" style="color:#0071e3;">
                    {val['accuracy']*100:.1f}%
                </div>
                <div class="stat-label">Accuracy</div>
            </div>
            <div class="stat-card">
                <div class="stat-num" style="color:#0071e3;">
                    {val['precision']*100:.1f}%
                </div>
                <div class="stat-label">Precision</div>
            </div>
            <div class="stat-card">
                <div class="stat-num" style="color:#0071e3;">
                    {val['auc_roc']*100:.1f}%
                </div>
                <div class="stat-label">AUC-ROC</div>
            </div>
        </div>

        <div class="card">
            <div class="card-title">Full Metrics</div>
            <div class="info-row">
                <span class="info-key">F1-Score</span>
                <span class="info-val">
                    {val['f1_score']*100:.1f}%
                </span>
            </div>
            <div class="info-row">
                <span class="info-key">Recall</span>
                <span class="info-val">
                    {val['recall']*100:.1f}%
                </span>
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
            <div class="info-row">
                <span class="info-key">Dataset Size</span>
                <span class="info-val">
                    {val['dataset_size']:,} samples
                </span>
            </div>
        </div>

        <div class="card">
            <div class="card-title">Confusion Matrix</div>
            <div style="display:grid; grid-template-columns:1fr 1fr;
                        gap:10px; text-align:center;">
                <div style="background:#e8f5e9; border-radius:12px;
                            padding:16px;">
                    <div style="font-size:28px; font-weight:700;
                                color:#2e7d32; letter-spacing:-1px;">
                        {val['confusion_matrix']['TP']:,}
                    </div>
                    <div style="font-size:12px; color:#2e7d32;
                                margin-top:4px; font-weight:600;">
                        True Positive ✓
                    </div>
                </div>
                <div style="background:#ffebee; border-radius:12px;
                            padding:16px;">
                    <div style="font-size:28px; font-weight:700;
                                color:#c62828; letter-spacing:-1px;">
                        {val['confusion_matrix']['FP']:,}
                    </div>
                    <div style="font-size:12px; color:#c62828;
                                margin-top:4px; font-weight:600;">
                        False Positive ✗
                    </div>
                </div>
                <div style="background:#ffebee; border-radius:12px;
                            padding:16px;">
                    <div style="font-size:28px; font-weight:700;
                                color:#c62828; letter-spacing:-1px;">
                        {val['confusion_matrix']['FN']:,}
                    </div>
                    <div style="font-size:12px; color:#c62828;
                                margin-top:4px; font-weight:600;">
                        False Negative ✗
                    </div>
                </div>
                <div style="background:#e8f5e9; border-radius:12px;
                            padding:16px;">
                    <div style="font-size:28px; font-weight:700;
                                color:#2e7d32; letter-spacing:-1px;">
                        {val['confusion_matrix']['TN']:,}
                    </div>
                    <div style="font-size:12px; color:#2e7d32;
                                margin-top:4px; font-weight:600;">
                        True Negative ✓
                    </div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)