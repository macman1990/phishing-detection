import re
from bs4 import BeautifulSoup


def analyze_content(parsed_email: dict) -> dict:
    result = {
        "score": 0,
        "flags": [],
    }

    body = parsed_email.get("body_text", "").lower()
    urls = parsed_email.get("urls", [])

    # ── 1. Urgency Language ──
    urgency_patterns = [
        r"your account.{0,20}(suspend|limit|block|close|terminat)",
        r"(verify|confirm).{0,20}(immediately|now|urgent|asap)",
        r"(24|48)\s*hour",
        r"act\s*(now|immediately)",
        r"failure to.{0,20}(result|lead)",
        r"unusual\s*(activity|sign)",
    ]
    for pattern in urgency_patterns:
        if re.search(pattern, body):
            result["score"] += 15
            result["flags"].append("urgency_language")
            break

    # ── 2. Credential Harvesting ──
    credential_patterns = [
        r"(enter|provide|confirm|update).{0,30}(password|passwd|pin)",
        r"(enter|provide|confirm|update).{0,30}(credit card|card number)",
        r"(enter|provide|confirm|update).{0,30}(social security|ssn)",
        r"click.{0,20}(here|below|link).{0,20}(verify|confirm|login)",
        r"sign\s*in\s*to\s*(verify|confirm|update)",
    ]
    for pattern in credential_patterns:
        if re.search(pattern, body):
            result["score"] += 25
            result["flags"].append("credential_harvesting")
            break

    # ── 3. Impersonation Language ──
    brands = [
        "paypal", "amazon", "google", "microsoft", "apple",
        "facebook", "instagram", "netflix", "bank", "dhl",
        "fedex", "ups", "irs", "support team", "security team"
    ]
    for brand in brands:
        if brand in body:
            result["score"] += 15
            result["flags"].append(f"impersonation_{brand.replace(' ', '_')}")
            break

    # ── 4. HTML Template Analysis ──
    html_score = _analyze_html(parsed_email)
    result["score"]  += html_score["score"]
    result["flags"]  += html_score["flags"]

    # ── 5. Suspicious Attachments ──
    attachments = parsed_email.get("attachments", [])
    dangerous_ext = [".exe", ".js", ".vbs", ".bat", ".ps1",
                     ".zip", ".rar", ".doc", ".xls"]
    for att in attachments:
        ext = att.get("extension", "").lower()
        if any(ext.endswith(e) for e in dangerous_ext):
            result["score"] += 30
            result["flags"].append(f"dangerous_attachment_{ext}")

    # ── 6. URL Count in Body ──
    if len(urls) > 3:
        result["score"] += 10
        result["flags"].append("excessive_urls")

    # ── 7. Mismatch: Display Text vs Actual URL ──
    mismatch = _check_url_mismatch(parsed_email.get("body_text", ""))
    if mismatch:
        result["score"] += 20
        result["flags"].append("url_display_mismatch")

    result["score"] = min(result["score"], 100)

    if result["score"] >= 70:
        result["verdict"] = "Malicious"
    elif result["score"] >= 40:
        result["verdict"] = "Suspicious"
    else:
        result["verdict"] = "Clean"

    return result


def _analyze_html(parsed_email: dict) -> dict:
    """تحليل HTML body"""
    score = 0
    flags = []

    body = parsed_email.get("body_text", "")

    try:
        soup = BeautifulSoup(body, "html.parser")

        # فورم بيطلب بيانات
        forms = soup.find_all("form")
        if forms:
            score += 20
            flags.append("html_form_detected")

        # hidden fields
        hidden = soup.find_all("input", {"type": "hidden"})
        if len(hidden) > 2:
            score += 10
            flags.append("excessive_hidden_fields")

        # external images من دومينات مختلفة
        imgs = soup.find_all("img", src=True)
        external_imgs = [i for i in imgs
                         if i["src"].startswith("http")]
        if len(external_imgs) > 3:
            score += 10
            flags.append("excessive_external_images")

    except Exception:
        pass

    return {"score": score, "flags": flags}


def _check_url_mismatch(body: str) -> bool:
    """
    بيشوف لو في رابط ظاهر للمستخدم
    مختلف عن الرابط الحقيقي
    مثال: <a href="evil.com">paypal.com</a>
    """
    pattern = r'href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>'
    matches = re.findall(pattern, body, re.IGNORECASE)

    for actual_url, display_text in matches:
        display_text = display_text.strip().lower()
        actual_url   = actual_url.strip().lower()

        if display_text.startswith("http") and display_text != actual_url:
            return True
        if re.match(r"[\w\-]+\.\w+", display_text):
            if display_text not in actual_url:
                return True

    return False


if __name__ == "__main__":
    import json

    test_email = {
        "body_text": """
        Dear Customer,
        Your PayPal account has been limited.
        Please verify your account immediately to avoid suspension.
        Click here to confirm your password:
        http://paypa1.secure-login.xyz/verify?token=abc123
        Failure to verify within 24 hours will result in suspension.
        """,
        "urls": ["http://paypa1.secure-login.xyz/verify?token=abc123"],
        "attachments": [],
    }

    result = analyze_content(test_email)
    print(json.dumps(result, indent=2))