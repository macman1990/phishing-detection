import eml_parser
import json
from datetime import datetime


def parse_email(file_path: str) -> dict:
    """
    بياخد مسار ملف .eml ويرجع dict فيه كل المعلومات المهمة
    """
    with open(file_path, "rb") as f:
        raw_email = f.read()

    ep = eml_parser.EmlParser(include_raw_body=True, include_attachment_data=True)
    parsed = ep.decode_email_bytes(raw_email)

    result = {
        "sender": _get_sender(parsed),
        "reply_to": _get_reply_to(parsed),
        "subject": parsed.get("header", {}).get("subject", ""),
        "date": _get_date(parsed),
        "recipients": _get_recipients(parsed),
        "urls": _get_urls(parsed),
        "attachments": _get_attachments(parsed),
        "auth_results": _get_auth_results(parsed),
        "body_text": _get_body(parsed),
    }

    return result


# ── helpers ──────────────────────────────────────────

def _get_sender(parsed: dict) -> dict:
    header = parsed.get("header", {})
    return {
        "raw": header.get("from", ""),
        "domain": _extract_domain(header.get("from", "")),
    }


def _get_reply_to(parsed: dict) -> str:
    return parsed.get("header", {}).get("reply-to", "")


def _get_date(parsed: dict) -> str:
    date = parsed.get("header", {}).get("date", "")
    return str(date) if date else ""


def _get_recipients(parsed: dict) -> list:
    header = parsed.get("header", {})
    to = header.get("to", [])
    if isinstance(to, str):
        to = [to]
    return to


def _get_urls(parsed: dict) -> list:
    urls = []
    for body in parsed.get("body", []):
        urls.extend(body.get("uri", []))
    return list(set(urls))  # إزالة التكرار


def _get_attachments(parsed: dict) -> list:
    attachments = []
    for att in parsed.get("attachment", []):
        attachments.append({
            "filename": att.get("filename", ""),
            "extension": att.get("extension", ""),
            "size": att.get("size", 0),
            "hash_md5": att.get("hash", {}).get("md5", ""),
            "hash_sha256": att.get("hash", {}).get("sha256", ""),
        })
    return attachments


def _get_auth_results(parsed: dict) -> dict:
    """
    بيدور على نتايج SPF / DKIM / DMARC في الـ headers
    """
    raw_headers = parsed.get("header", {}).get("header", {})
    auth_raw = ""

    for key, value in raw_headers.items():
        if "authentication-results" in key.lower():
            auth_raw = value[0] if isinstance(value, list) else value
            break

    return {
        "raw": auth_raw,
        "spf": _extract_auth_value(auth_raw, "spf"),
        "dkim": _extract_auth_value(auth_raw, "dkim"),
        "dmarc": _extract_auth_value(auth_raw, "dmarc"),
    }


def _get_body(parsed: dict) -> str:
    for body in parsed.get("body", []):
        if body.get("content_type") == "text/plain":
            return body.get("content", "")
    # لو مفيش plain text هاخد أول body
    bodies = parsed.get("body", [])
    if bodies:
        return bodies[0].get("content", "")
    return ""


def _extract_domain(email_str: str) -> str:
    """
    بيطلع الدومين من الإيميل
    example: "John <john@gmail.com>" → "gmail.com"
    """
    import re
    match = re.search(r"@([\w\.\-]+)", email_str)
    return match.group(1).lower() if match else ""


def _extract_auth_value(auth_str: str, protocol: str) -> str:
    """
    بيطلع نتيجة SPF أو DKIM أو DMARC من الـ header
    pass / fail / neutral / none
    """
    import re
    pattern = rf"{protocol}=(\w+)"
    match = re.search(pattern, auth_str, re.IGNORECASE)
    return match.group(1).lower() if match else "none"


# ── test ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("الاستخدام: python email_parser.py <path_to_eml>")
        sys.exit(1)

    result = parse_email(sys.argv[1])
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))