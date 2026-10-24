from modules.email_parser import parse_email
from modules.url_analyzer import analyze_urls_from_email
from modules.header_checker import check_headers
from modules.ml_classifier import predict  # ← جديد
from modules.content_analyzer import analyze_content
from datetime import datetime
from modules.threat_intel import check_urls_list, check_urlhaus_list


def run_analysis(eml_path: str) -> dict:

    # 1 — Parse
    email_data = parse_email(eml_path)

    # 2 — Header Check
    header_result = check_headers(email_data)

    # 2.5 — Content Analysis
    content_result = analyze_content(email_data)

    # 3 — URL Analysis
    url_results = analyze_urls_from_email(email_data.get("urls", []))

    # 4 — VirusTotal
    vt_results = check_urls_list(email_data.get("urls", []))

    # 5 — URLhaus
    urlhaus_results = check_urlhaus_list(email_data.get("urls", []))

    # 6 — دمج نتائج URL + VT + URLhaus
    combined_urls = _merge_url_results(url_results, vt_results, urlhaus_results)

    # 7 — أعلى score من الـ URLs
    url_score     = 0
    vt_score      = 0
    urlhaus_score = 0
    if combined_urls:
        url_score     = max(r["rule_score"]    for r in combined_urls)
        vt_score      = max(r["vt_score"]      for r in combined_urls)
        urlhaus_score = max(r["urlhaus_score"] for r in combined_urls)

    # 8 — ML Prediction
    ml_result = predict({
        "urls_analyzed": combined_urls,
        "auth_results":  email_data["auth_results"],
        "flags":         list(set(header_result["flags"])),
    })

    # 9 — Final Score
    final_score = int(
        header_result["score"]  * 0.25 +
        content_result["score"] * 0.20 +
        url_score               * 0.20 +
        vt_score                * 0.15 +
        urlhaus_score           * 0.10 +
        ml_result["ml_score"]   * 0.10
    )
    final_score = min(final_score, 100)

    # 8 — Verdict
    if final_score >= 75:
        verdict = "CRITICAL"
    elif final_score >= 50:
        verdict = "HIGH"
    elif final_score >= 25:
        verdict = "MEDIUM"
    else:
        verdict = "LOW"

    # 9 — كل الـ flags
    all_flags = header_result["flags"].copy()
    all_flags += content_result["flags"]
    for url in combined_urls:
        all_flags.extend(url["flags"])

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "file": eml_path,
        "final_score": final_score,
        "verdict": verdict,
        "breakdown": {
            "header_score": header_result["score"],
            "content_score": content_result["score"],
            "url_score":    url_score,
            "vt_score":     vt_score,
            "urlhaus_score": urlhaus_score,
            "ml_score":     ml_result["ml_score"],
        },
        "flags":         list(set(all_flags)),
        "sender":        email_data["sender"],
        "subject":       email_data["subject"],
        "urls_analyzed": combined_urls,
        "auth_results":  email_data["auth_results"],
        "attachments":   email_data["attachments"],
    }


def _merge_url_results(url_results, vt_results, urlhaus_results):
    vt_map      = {r["url"]: r for r in vt_results}
    urlhaus_map = {r["url"]: r for r in urlhaus_results}
    merged = []
    for url in url_results:
        vt      = vt_map.get(url["url"], {})
        urlhaus = urlhaus_map.get(url["url"], {})
        urlhaus_score = 100 if urlhaus.get("listed") else 0
        merged.append({
            "url":               url["url"],
            "domain":            url["domain"],
            "rule_score":        url["score"],
            "rule_verdict":      url["verdict"],
            "vt_score":          vt.get("vt_score", 0),
            "vt_verdict":        vt.get("verdict", "Unknown"),
            "malicious_engines": vt.get("malicious_engines", 0),
            "urlhaus_listed":    urlhaus.get("listed", False),
            "urlhaus_threat":    urlhaus.get("threat", None),
            "urlhaus_score":     urlhaus_score,
            "flags":             url["flags"],
        })
    return merged


if __name__ == "__main__":
    import json
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "data/test.eml"
    report = run_analysis(path)
    print(json.dumps(report, indent=2, ensure_ascii=False, default=str))