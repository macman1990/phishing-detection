import socket
import unicodedata
import requests
import re
import urllib.parse
from datetime import datetime

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


# ══════════════════════════════════════════
# 1 — DOMAIN AGE & WHOIS
# ══════════════════════════════════════════
def analyze_domain_age(domain: str) -> dict:
    result = {
        "domain": domain, "score": 0, "flags": [],
        "age_days": None, "creation_date": None,
        "expiry_date": None, "registrar": None,
    }
    if not WHOIS_AVAILABLE or not domain:
        return result
    try:
        w = whois.whois(domain)

        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            if isinstance(creation, str):
                creation = datetime.strptime(creation[:10], "%Y-%m-%d")
            age = (datetime.now() - creation).days
            result["age_days"]      = age
            result["creation_date"] = str(creation)[:10]
            if age < 30:
                result["score"] += 80
                result["flags"].append("domain_very_new_under_30_days")
            elif age < 90:
                result["score"] += 50
                result["flags"].append("domain_new_under_90_days")
            elif age < 180:
                result["score"] += 25
                result["flags"].append("domain_recent_under_180_days")

        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        if expiry:
            result["expiry_date"] = str(expiry)[:10]
            if creation and hasattr(expiry, "year"):
                period = (expiry - creation).days
                if period < 365:
                    result["score"] += 15
                    result["flags"].append("short_registration_period")

        result["registrar"] = w.registrar

    except Exception:
        result["score"] += 5
        result["flags"].append("whois_lookup_failed")

    result["score"] = min(result["score"], 100)
    return result


# ══════════════════════════════════════════
# 2 — REDIRECT CHAIN ANALYSIS
# ══════════════════════════════════════════
def analyze_redirect_chain(url: str) -> dict:
    result = {
        "url": url, "score": 0, "flags": [],
        "chain": [], "hops": 0, "final_url": url,
    }
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        resp = requests.get(
            url, allow_redirects=True,
            timeout=8, headers=headers, verify=False
        )
        chain = [
            {"url": r.url, "status": r.status_code}
            for r in resp.history
        ]
        chain.append({"url": resp.url, "status": resp.status_code})
        result["chain"]     = chain
        result["hops"]      = len(resp.history)
        result["final_url"] = resp.url

        if result["hops"] > 3:
            result["score"] += 35
            result["flags"].append(f"excessive_redirects_{result['hops']}_hops")
        elif result["hops"] > 1:
            result["score"] += 15
            result["flags"].append(f"redirect_chain_{result['hops']}_hops")

        orig_domain  = urllib.parse.urlparse(url).netloc
        final_domain = urllib.parse.urlparse(resp.url).netloc
        if orig_domain != final_domain:
            result["score"] += 25
            result["flags"].append("redirect_domain_change")

        if resp.status_code in [403, 404, 500]:
            result["score"] += 10
            result["flags"].append(f"suspicious_status_{resp.status_code}")

    except requests.exceptions.SSLError:
        result["score"] += 20
        result["flags"].append("ssl_certificate_invalid")
    except requests.exceptions.ConnectionError:
        result["score"] += 10
        result["flags"].append("connection_error")
    except Exception:
        result["flags"].append("redirect_check_failed")

    result["score"] = min(result["score"], 100)
    return result


# ══════════════════════════════════════════
# 3 — UNICODE HOMOGRAPH DETECTION
# ══════════════════════════════════════════
def detect_unicode_homograph(domain: str) -> dict:
    result = {
        "domain": domain, "score": 0,
        "flags": [], "suspicious_chars": [],
        "is_punycode": False,
    }
    if not domain:
        return result

    if "xn--" in domain.lower():
        result["is_punycode"] = True
        result["score"] += 40
        result["flags"].append("punycode_domain_detected")

    homographs = {
        "а": "a", "е": "e", "о": "o",
        "р": "p", "с": "c", "х": "x",
        "у": "y", "ο": "o", "α": "a",
        "ν": "v", "і": "i", "ј": "j",
    }
    found = []
    scripts = set()

    for char in domain:
        if char.isalpha():
            try:
                name = unicodedata.name(char, "")
                if "LATIN" in name:
                    scripts.add("latin")
                elif "CYRILLIC" in name:
                    scripts.add("cyrillic")
                    result["suspicious_chars"].append(char)
                elif "GREEK" in name:
                    scripts.add("greek")
                    result["suspicious_chars"].append(char)
            except Exception:
                pass
            if char in homographs:
                found.append(f"{char}→{homographs[char]}")

    if len(scripts) > 1:
        result["score"] += 50
        result["flags"].append("mixed_script_domain")

    if found:
        result["score"] += 60
        result["flags"].append("homograph_characters_detected")
        result["suspicious_chars"].extend(found)

    result["score"] = min(result["score"], 100)
    return result


# ══════════════════════════════════════════
# 4 — ATTACHMENT DEEP SCAN
# ══════════════════════════════════════════
def scan_attachments(attachments: list) -> dict:
    result = {"score": 0, "flags": [], "scanned": []}
    if not attachments:
        return result

    dangerous = {
        ".exe": 90, ".bat": 85, ".cmd": 85,
        ".ps1": 80, ".vbs": 80, ".js":  75,
        ".jar": 75, ".scr": 85, ".com": 80,
        ".pif": 80, ".reg": 70, ".msi": 65,
    }
    suspicious = {
        ".zip": 30, ".rar": 35, ".7z": 30,
        ".doc": 40, ".xls": 40, ".docm": 60,
        ".xlsm": 60, ".pdf": 20, ".iso": 50,
    }
    double_ext = re.compile(
        r'\.(pdf|doc|txt|jpg|png)\.(exe|bat|cmd|vbs|js|ps1)$',
        re.IGNORECASE
    )

    for att in attachments:
        fname = att.get("filename",  "")
        ext   = att.get("extension", "").lower()
        size  = att.get("size",      0)

        a = {"filename": fname, "extension": ext,
             "size": size, "score": 0, "flags": []}

        if ext in dangerous:
            a["score"] += dangerous[ext]
            a["flags"].append(f"dangerous_extension_{ext}")
            result["flags"].append(f"attachment_dangerous_{ext}")
            result["score"] = max(result["score"], dangerous[ext])

        elif ext in suspicious:
            a["score"] += suspicious[ext]
            a["flags"].append(f"suspicious_extension_{ext}")
            result["score"] = max(result["score"], suspicious[ext])

        if double_ext.search(fname):
            a["score"] += 70
            a["flags"].append("double_extension_attack")
            result["flags"].append("attachment_double_extension")
            result["score"] = max(result["score"], 70)

        if 0 < size < 1000:
            a["flags"].append("suspicious_tiny_file")

        if not ext and fname:
            a["score"] += 20
            a["flags"].append("no_file_extension")

        result["scanned"].append(a)

    result["score"] = min(result["score"], 100)
    return result


# ══════════════════════════════════════════
# 5 — IP REPUTATION CHECK
# ══════════════════════════════════════════
def check_ip_reputation(domain: str) -> dict:
    result = {
        "domain": domain, "ip": None,
        "score": 0, "flags": [],
        "is_private": False, "reverse_dns": None,
    }
    if not domain:
        return result
    try:
        ip = socket.gethostbyname(domain)
        result["ip"] = ip

        private = ["10.", "192.168.", "172.16.", "127."]
        if any(ip.startswith(r) for r in private):
            result["is_private"] = True
            result["score"] += 20
            result["flags"].append("private_ip_as_sender")

        try:
            rdns = socket.gethostbyaddr(ip)[0]
            result["reverse_dns"] = rdns
            suspicious_rdns = [
                "dynamic", "dsl", "cable",
                "pool", "dhcp", "ppp"
            ]
            if any(s in rdns.lower() for s in suspicious_rdns):
                result["score"] += 25
                result["flags"].append("dynamic_ip_reverse_dns")
        except Exception:
            result["score"] += 10
            result["flags"].append("no_reverse_dns")

    except socket.gaierror:
        result["score"] += 15
        result["flags"].append("dns_resolution_failed")
    except Exception:
        pass

    result["score"] = min(result["score"], 100)
    return result


# ══════════════════════════════════════════
# MAIN — RUN ALL
# ══════════════════════════════════════════
def run_advanced_analysis(email_data: dict, urls: list) -> dict:
    domain      = email_data.get("sender", {}).get("domain", "")
    attachments = email_data.get("attachments", [])

    domain_age  = analyze_domain_age(domain)
    redirect    = analyze_redirect_chain(urls[0]) if urls else {}
    unicode_r   = detect_unicode_homograph(domain)
    attachment  = scan_attachments(attachments)
    ip_rep      = check_ip_reputation(domain)

    all_flags = (
        domain_age.get("flags", []) +
        redirect.get("flags",   []) +
        unicode_r.get("flags",  []) +
        attachment.get("flags", []) +
        ip_rep.get("flags",     [])
    )

    scores = [
        domain_age.get("score", 0),
        redirect.get("score",   0),
        unicode_r.get("score",  0),
        attachment.get("score", 0),
        ip_rep.get("score",     0),
    ]
    combined = int(sum(scores) / len([s for s in scores if s > 0])) \
               if any(s > 0 for s in scores) else 0

    return {
        "score":       combined,
        "flags":       list(set(all_flags)),
        "domain_age":  domain_age,
        "redirect":    redirect,
        "unicode":     unicode_r,
        "attachment":  attachment,
        "ip_reputation": ip_rep,
    }


if __name__ == "__main__":
    import json
    from modules.email_parser import parse_email

    data   = parse_email("data/test.eml")
    urls   = data.get("urls", [])
    result = run_advanced_analysis(data, urls)
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))