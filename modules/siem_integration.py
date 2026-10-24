import json
import socket
import logging
import os
from datetime import datetime
from config import SIEM_HOST, SIEM_PORT, LOG_PATH


# ── Config ──────────────────────────────────────────
# ── Local Logger (backup) ────────────────────────────
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(message)s"
)


def send_alert(report: dict) -> dict:
    """بيحول الـ report لـ SIEM alert ويبعته"""

    alert = _build_alert(report)

    # 1 — حفظ محلي دايمًا
    _save_local(alert)

    # 2 — حاول تبعت لـ SIEM
    siem_sent = _send_syslog(alert)

    return {
        "alert_id":  alert["alert_id"],
        "saved":     True,
        "siem_sent": siem_sent,
        "log_path":  LOG_PATH,
    }


def _build_alert(report: dict) -> dict:
    """بيبني الـ alert بصيغة SIEM"""

    verdict  = report["verdict"]
    score    = report["final_score"]
    sender   = report["sender"]["raw"]
    domain   = report["sender"]["domain"]
    subject  = report["subject"]
    auth     = report["auth_results"]
    urls     = [u["url"] for u in report.get("urls_analyzed", [])]
    flags    = report.get("flags", [])
    ml       = report.get("ml_result", {})

    # severity mapping
    severity_map = {
        "CRITICAL": 2,
        "HIGH":     3,
        "MEDIUM":   5,
        "LOW":      6,
    }

    alert_id = f"PHI-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

    return {
        # ── Metadata ──
        "alert_id":   alert_id,
        "timestamp":  datetime.utcnow().isoformat(),
        "rule_id":    "100001",
        "rule_level": severity_map.get(verdict, 5),

        # ── Classification ──
        "verdict":     verdict,
        "final_score": score,
        "ml_score":    ml.get("ml_score", 0),
        "ml_verdict":  ml.get("ml_verdict", "Unknown"),

        # ── Email Info ──
        "sender":  sender,
        "domain":  domain,
        "subject": subject,

        # ── Auth ──
        "spf":   auth.get("spf",   "none"),
        "dkim":  auth.get("dkim",  "none"),
        "dmarc": auth.get("dmarc", "none"),

        # ── IOCs ──
        "iocs": {
            "domains": [domain],
            "urls":    urls,
        },

        # ── MITRE ──
        "mitre": {
            "technique_id":   "T1566",
            "technique_name": "Phishing",
            "sub_technique":  "T1566.001",
        },

        # ── Flags ──
        "flags": flags,

        # ── Scores ──
        "breakdown": report.get("breakdown", {}),

        # ── Source ──
        "source": "AMIT-Phishing-Detection-System",
    }


def _save_local(alert: dict):
    """بيحفظ الـ alert في log file محلي"""
    os.makedirs("reports", exist_ok=True)
    logging.info(json.dumps(alert, ensure_ascii=False))


def _send_syslog(alert: dict) -> bool:
    """بيبعت الـ alert لـ SIEM عن طريق UDP Syslog"""
    try:
        message = json.dumps(alert, ensure_ascii=False)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(message.encode("utf-8"), (SIEM_HOST, SIEM_PORT))
        sock.close()
        return True
    except Exception:
        # لو مفيش SIEM متنصب — مش مشكلة
        return False


def get_all_alerts() -> list:
    """بيرجع كل الـ alerts المحفوظة"""
    if not os.path.exists(LOG_PATH):
        return []

    alerts = []
    with open(LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    alerts.append(json.loads(line))
                except Exception:
                    continue
    return alerts


if __name__ == "__main__":
    from modules.risk_engine import run_analysis

    report = run_analysis("data/test.eml")
    result = send_alert(report)

    print(f"✅ Alert ID:   {result['alert_id']}")
    print(f"✅ Saved:      {result['saved']}")
    print(f"✅ SIEM Sent:  {result['siem_sent']}")
    print(f"✅ Log Path:   {result['log_path']}")

    print("\n📋 All Alerts:")
    alerts = get_all_alerts()
    print(f"Total: {len(alerts)} alert(s)")
    for a in alerts:
        print(f"  [{a['timestamp']}] {a['alert_id']} — {a['verdict']} ({a['final_score']}/100)")