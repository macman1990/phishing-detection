import requests
import base64
import time
from config import VIRUSTOTAL_API_KEY


API_KEY = VIRUSTOTAL_API_KEY
BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": API_KEY}


def check_url(url: str) -> dict:
    """بيبعت الـ URL لـ VirusTotal ويرجع النتيجة"""

    # VirusTotal بيحتاج الـ URL يتحول لـ base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    try:
        response = requests.get(
            f"{BASE_URL}/urls/{url_id}",
            headers=HEADERS,
            timeout=10
        )

        if response.status_code == 404:
            return _submit_url(url)

        if response.status_code == 200:
            return _parse_url_result(response.json(), url)

        return _error_result(url, f"HTTP {response.status_code}")

    except Exception as e:
        return _error_result(url, str(e))


def _submit_url(url: str) -> dict:
    """لو الـ URL مش موجود يبعته للفحص"""
    try:
        response = requests.post(
            f"{BASE_URL}/urls",
            headers=HEADERS,
            data={"url": url},
            timeout=10
        )

        if response.status_code == 200:
            time.sleep(3)  # استنى التحليل
            return check_url(url)

        return _error_result(url, "Submission failed")

    except Exception as e:
        return _error_result(url, str(e))


def _parse_url_result(data: dict, url: str) -> dict:
    stats = (
        data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
    )

    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless", 0)
    total      = malicious + suspicious + harmless

    # حساب الـ score
    if total > 0:
        vt_score = int(((malicious + suspicious) / total) * 100)
    else:
        vt_score = 0

    if malicious >= 3:
        verdict = "Malicious"
    elif malicious >= 1 or suspicious >= 2:
        verdict = "Suspicious"
    else:
        verdict = "Clean"

    return {
        "url": url,
        "vt_score": vt_score,
        "verdict": verdict,
        "malicious_engines": malicious,
        "suspicious_engines": suspicious,
        "harmless_engines": harmless,
        "total_engines": total,
        "error": None,
    }


def _error_result(url: str, error: str) -> dict:
    return {
        "url": url,
        "vt_score": 0,
        "verdict": "Unknown",
        "malicious_engines": 0,
        "suspicious_engines": 0,
        "harmless_engines": 0,
        "total_engines": 0,
        "error": error,
    }


def check_urls_list(urls: list) -> list:
    results = []
    for url in urls:
        result = check_url(url)
        results.append(result)
        time.sleep(1)  # مش تتجاوز الـ rate limit
    return results

def check_urlhaus(url: str) -> dict:
    """بيتحقق من الـ URL في قاعدة بيانات URLhaus"""
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=10
        )

        data = response.json()

        if data.get("query_status") == "is_listed":
            return {
                "url":         url,
                "listed":      True,
                "threat":      data.get("threat", "unknown"),
                "url_status":  data.get("url_status", "unknown"),
                "date_added":  data.get("date_added", ""),
                "urlhaus_ref": data.get("urlhaus_reference", ""),
                "tags":        data.get("tags", []),
            }

        return {
            "url":         url,
            "listed":      False,
            "threat":      None,
            "url_status":  "clean",
            "date_added":  "",
            "urlhaus_ref": "",
            "tags":        [],
        }

    except Exception as e:
        return {
            "url":        url,
            "listed":     False,
            "threat":     None,
            "url_status": "error",
            "error":      str(e),
        }


def check_urlhaus_list(urls: list) -> list:
    results = []
    for url in urls:
        result = check_urlhaus(url)
        results.append(result)
        time.sleep(0.5)
    return results


def check_phishtank(url: str) -> dict:
    try:
        response = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": url, "format": "json"},
            headers={"User-Agent": "phishtank/PhishGuard"},
            timeout=10
        )
        data = response.json()
        results = data.get("results", {})
        in_database = results.get("in_database", False)
        verified    = results.get("verified",    False)
        if in_database and verified:
            verdict, score = "Phishing", 100
        elif in_database:
            verdict, score = "Suspicious", 60
        else:
            verdict, score = "Clean", 0
        return {
            "url": url, "listed": in_database,
            "verified": verified, "verdict": verdict,
            "score": score,
            "phishtank_url": results.get("phish_detail_page",""),
            "error": None,
        }
    except Exception as e:
        return {"url": url, "listed": False, "verified": False,
                "verdict": "Unknown", "score": 0, "error": str(e)}


def check_google_safebrowsing(url: str, api_key: str = None) -> dict:
    if not api_key:
        from config import GOOGLE_API_KEY
        api_key = GOOGLE_API_KEY
    if not api_key or api_key == "YOUR_GOOGLE_KEY":
        return {"url": url, "threats": [], "verdict": "Unknown",
                "score": 0, "error": "No API key"}
    try:
        body = {
            "client": {"clientId": "PhishGuard", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE","SOCIAL_ENGINEERING",
                                "UNWANTED_SOFTWARE",
                                "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":    [{"url": url}]
            }
        }
        response = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
            f"?key={api_key}",
            json=body, timeout=10
        )
        matches = response.json().get("matches", [])
        if matches:
            return {"url": url,
                    "threats": [m.get("threatType","") for m in matches],
                    "verdict": "Malicious", "score": 100, "error": None}
        return {"url": url, "threats": [], "verdict": "Clean",
                "score": 0, "error": None}
    except Exception as e:
        return {"url": url, "threats": [], "verdict": "Unknown",
                "score": 0, "error": str(e)}


def full_url_check(url: str) -> dict:
    vt  = check_url(url) or {}
    uh  = check_urlhaus(url) or {}
    pt  = check_phishtank(url) or {}
    gsb = check_google_safebrowsing(url) or {}
    urlhaus_listed = uh.get("listed", False)
    scores = [
        vt.get("vt_score", 0),
        100 if urlhaus_listed else 0,
        pt.get("score", 0),
        gsb.get("score", 0),
    ]
    combined = int(sum(scores) / len(scores)) if scores else 0
    malicious_count = sum([
        1 if vt.get("verdict", "Unknown") == "Malicious" else 0,
        1 if urlhaus_listed else 0,
        1 if pt.get("verdict", "Unknown") == "Phishing" else 0,
        1 if gsb.get("verdict", "Unknown") == "Malicious" else 0,
    ])
    if malicious_count >= 2 or combined >= 70:
        final_verdict = "Malicious"
    elif malicious_count >= 1 or combined >= 40:
        final_verdict = "Suspicious"
    else:
        final_verdict = "Clean"
    return {
        "url": url, "combined_score": combined,
        "final_verdict": final_verdict,
        "malicious_count": malicious_count,
        "sources": {
            "virustotal": {
                **vt,
                "vt_score": vt.get("vt_score", 0),
                "verdict": vt.get("verdict", "Unknown"),
            },
            "urlhaus": {
                **uh,
                "listed": urlhaus_listed,
            },
            "phishtank": {
                **pt,
                "score": pt.get("score", 0),
                "verdict": pt.get("verdict", "Unknown"),
            },
            "google_safebrowsing": {
                **gsb,
                "score": gsb.get("score", 0),
                "verdict": gsb.get("verdict", "Unknown"),
            },
        }
    }


if __name__ == "__main__":
    import json

    test_urls = [
        "http://paypa1.secure-login.xyz/verify?token=abc123",
        "https://www.google.com",
    ]

    print("=== VirusTotal ===")
    for url in test_urls:
        result = check_url(url)
        print(f"\nURL: {result['url']}")
        print(f"VT Score:  {result['vt_score']}/100")
        print(f"Verdict:   {result['verdict']}")
        print(f"Malicious: {result['malicious_engines']} engines")

    print("\n=== URLhaus ===")
    for url in test_urls:
        result = check_urlhaus(url)
        print(f"\nURL:    {result['url']}")
        print(f"Listed: {result['listed']}")
        print(f"Threat: {result['threat']}")
        print(f"Status: {result['url_status']}")

    for url in test_urls:
        result = check_url(url)
        print(f"\nURL: {result['url']}")
        print(f"VT Score: {result['vt_score']}/100")
        print(f"Verdict: {result['verdict']}")
        print(f"Malicious Engines: {result['malicious_engines']}")
        print(f"Error: {result['error']}")