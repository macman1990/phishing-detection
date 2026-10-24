import re
import urllib.parse
from datetime import datetime


def analyze_url(url: str) -> dict:
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path
    full_url = url.lower()

    features = {
        "url": url,
        "domain": domain,
        "score": 0,
        "flags": [],
    }

    # 1 — طول الـ URL
    if len(url) > 75:
        features["score"] += 10
        features["flags"].append("url_too_long")

    # 2 — IP بدل domain
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        features["score"] += 30
        features["flags"].append("ip_as_domain")

    # 3 — كلمات خطيرة في الـ URL
    suspicious_keywords = [
        "login", "verify", "secure", "account", "update",
        "confirm", "banking", "password", "signin", "paypal",
        "amazon", "apple", "microsoft", "support"
    ]
    for word in suspicious_keywords:
        if word in full_url:
            features["score"] += 10
            features["flags"].append(f"keyword_{word}")

    # 4 — عدد النقاط في الدومين (subdomain abuse)
    dot_count = domain.count(".")
    if dot_count > 3:
        features["score"] += 15
        features["flags"].append("excessive_subdomains")

    # 5 — علامات مشبوهة في الـ URL
    special_chars = ["@", "//", "%", "-login", "-secure"]
    for char in special_chars:
        if char in full_url:
            features["score"] += 10
            features["flags"].append(f"special_char_{char.strip('-')}")

    # 6 — HTTP بدل HTTPS
    if url.startswith("http://"):
        features["score"] += 15
        features["flags"].append("no_https")

    # 7 — lookalike domains
    brands = {
        "paypal": ["paypa1", "paypa-l", "paypall"],
        "amazon": ["amaz0n", "arnazon", "amazon-"],
        "google": ["g00gle", "googIe"],
        "microsoft": ["micros0ft", "rnicrosof"],
        "apple": ["app1e", "appl3"],
    }
    for brand, fakes in brands.items():
        for fake in fakes:
            if fake in domain:
                features["score"] += 40
                features["flags"].append(f"lookalike_{brand}")

    # 8 — تشفير مشبوه في الـ URL
    if "%" in url:
        features["score"] += 10
        features["flags"].append("url_encoding")

    # الـ score مايعدش 100
    features["score"] = min(features["score"], 100)

    # verdict
    if features["score"] >= 70:
        features["verdict"] = "Malicious"
    elif features["score"] >= 40:
        features["verdict"] = "Suspicious"
    else:
        features["verdict"] = "Clean"

    return features


def analyze_urls_from_email(urls: list) -> list:
    """بياخد list من الـ URLs ويحللهم كلهم"""
    return [analyze_url(url) for url in urls]


if __name__ == "__main__":
    test_urls = [
        "http://paypa1.secure-login.xyz/verify?token=abc123",
        "https://www.google.com",
        "http://192.168.1.1/login",
        "https://amazon-support-update.com/account/verify",
    ]

    for url in test_urls:
        result = analyze_url(url)
        print(f"\nURL: {result['url']}")
        print(f"Score: {result['score']}/100")
        print(f"Verdict: {result['verdict']}")
        print(f"Flags: {result['flags']}")