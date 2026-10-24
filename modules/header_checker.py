import re


def check_headers(parsed_email: dict) -> dict:
    result = {
        "score": 0,
        "flags": [],
    }

    sender_domain = parsed_email.get("sender", {}).get("domain", "")
    reply_to = parsed_email.get("reply_to", "")
    auth = parsed_email.get("auth_results", {})
    subject = parsed_email.get("subject", "").lower()

    # 1 — SPF
    if auth.get("spf") == "fail":
        result["score"] += 30
        result["flags"].append("spf_fail")
    elif auth.get("spf") == "none":
        result["score"] += 10
        result["flags"].append("spf_none")

    # 2 — DKIM
    if auth.get("dkim") == "fail":
        result["score"] += 25
        result["flags"].append("dkim_fail")
    elif auth.get("dkim") == "none":
        result["score"] += 10
        result["flags"].append("dkim_none")

    # 3 — DMARC
    if auth.get("dmarc") == "fail":
        result["score"] += 25
        result["flags"].append("dmarc_fail")
    elif auth.get("dmarc") == "none":
        result["score"] += 10
        result["flags"].append("dmarc_none")

    # 4 — Reply-To مختلف عن المرسل
    if reply_to:
        reply_domain = _extract_domain(reply_to)
        if reply_domain and reply_domain != sender_domain:
            result["score"] += 20
            result["flags"].append("reply_to_mismatch")

    # 5 — كلمات إلحاح في الـ subject
    urgency_words = [
        "urgent", "suspended", "verify", "immediately",
        "action required", "limited", "unusual", "locked"
    ]
    for word in urgency_words:
        if word in subject:
            result["score"] += 10
            result["flags"].append(f"urgency_{word.replace(' ', '_')}")
            break  # واحدة بس تكفي

    # 6 — انتحال براندات معروفة في المرسل
    brands = ["paypal", "amazon", "google", "microsoft", "apple",
              "facebook", "instagram", "netflix", "bank"]
    for brand in brands:
        if brand in sender_domain and not _is_official(brand, sender_domain):
            result["score"] += 30
            result["flags"].append(f"impersonating_{brand}")
            break

    result["score"] = min(result["score"], 100)

    if result["score"] >= 70:
        result["verdict"] = "Malicious"
    elif result["score"] >= 40:
        result["verdict"] = "Suspicious"
    else:
        result["verdict"] = "Clean"

    return result


def _extract_domain(email_str: str) -> str:
    match = re.search(r"@([\w\.\-]+)", email_str)
    return match.group(1).lower() if match else ""


def _is_official(brand: str, domain: str) -> bool:
    official = {
        "paypal": "paypal.com",
        "amazon": "amazon.com",
        "google": "google.com",
        "microsoft": "microsoft.com",
        "apple": "apple.com",
        "facebook": "facebook.com",
        "instagram": "instagram.com",
        "netflix": "netflix.com",
    }
    return domain == official.get(brand, "")


if __name__ == "__main__":
    import json

    test_email = {
        "sender": {"raw": "support@paypa1.com", "domain": "paypa1.com"},
        "reply_to": "attacker@gmail.com",
        "subject": "Urgent: Your account will be suspended!",
        "auth_results": {
            "spf": "fail",
            "dkim": "fail",
            "dmarc": "fail",
        },
    }

    result = check_headers(test_email)
    print(json.dumps(result, indent=2))