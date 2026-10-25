import pandas as pd
import requests
import os


def download_datasets():
    datasets = [
        {
            "name": "PhiUSIIL",
            "url": "https://raw.githubusercontent.com/GregaVrbancic/"
                   "Phishing-Dataset/master/dataset_full.csv",
            "path": "data/phishing_full.csv"
        },
        {
            "name": "ISCX-URL-2016",
            "url": "https://raw.githubusercontent.com/Rohith-2/"
                   "URL-Feature-Extraction/master/phishing.csv",
            "path": "data/phishing_extra.csv"
        },
    ]

    downloaded = []
    for ds in datasets:
        print(f"Downloading {ds['name']}...")
        try:
            r = requests.get(ds["url"], timeout=30)
            if r.status_code == 200:
                with open(ds["path"], "wb") as f:
                    f.write(r.content)
                print(f"✅ {ds['name']} downloaded")
                downloaded.append(ds["path"])
            else:
                print(f"⚠️ {ds['name']} failed: {r.status_code}")
        except Exception as e:
            print(f"⚠️ {ds['name']} error: {e}")

    return downloaded


def prepare_combined():
    dfs = []

    # Dataset 1 — الأصلي
    if os.path.exists("data/dataset.csv"):
        df1 = pd.read_csv("data/dataset.csv")
        dfs.append(df1)
        print(f"✅ Original dataset: {len(df1)} samples")

    # Dataset 2 — Full
    if os.path.exists("data/phishing_full.csv"):
        try:
            df2 = pd.read_csv("data/phishing_full.csv")
            if "phishing" in df2.columns:
                prepared = _prepare_standard(df2)
                dfs.append(prepared)
                print(f"✅ Full dataset: {len(prepared)} samples")
        except Exception as e:
            print(f"⚠️ Full dataset error: {e}")

    # Dataset 3 — Extra patterns
    extra = _generate_extra_patterns()
    dfs.append(extra)
    print(f"✅ Extra patterns: {len(extra)} samples")

    if not dfs:
        print("❌ No datasets found")
        return

    combined = pd.concat(dfs, ignore_index=True)
    # features are numeric so drop_duplicates would remove valid data
    combined = combined.fillna(0).astype(int)

    combined.to_csv("data/dataset.csv", index=False)

    total    = len(combined)
    phishing = combined["label"].sum()
    clean    = total - phishing

    print(f"\n✅ Combined dataset saved")
    print(f"   Total:    {total:,} samples")
    print(f"   Phishing: {phishing:,} ({phishing/total*100:.1f}%)")
    print(f"   Clean:    {clean:,} ({clean/total*100:.1f}%)")

    return combined


def _prepare_standard(df):
    """تحويل dataset بصيغة قياسية"""
    prepared = pd.DataFrame()
    prepared["url_length"]        = df.get("length_url", 50)
    prepared["has_ip"]            = df.get("domain_in_ip", 0)
    prepared["has_https"]         = df.get("tls_ssl_certificate", 0)
    prepared["suspicious_words"]  = (
        df.get("qty_at_url", 0) + df.get("qty_percent_url", 0)
    )
    col = df.get("domain_spf", pd.Series([1]*len(df)))
    prepared["spf_fail"] = col.apply(lambda x: 1 if x == 0 else 0)
    prepared["dkim_fail"]         = 0
    prepared["dmarc_fail"]        = 0
    prepared["reply_to_mismatch"] = df.get("email_in_url", 0)
    prepared["dot_count"]         = df.get("qty_dot_url", 2)
    prepared["vt_score"]          = df.get("url_google_index", 0).apply(
        lambda x: 0 if x == 1 else 50
    )
    prepared["label"] = df["phishing"]
    return prepared


def _generate_extra_patterns():
    """patterns إضافية للأشكال المحتملة"""
    import numpy as np
    np.random.seed(42)
    n = 2000

    data = {
        # Phishing patterns
        "url_length":        list(np.random.randint(80,200, n//2)) +
                             list(np.random.randint(10,50,  n//2)),
        "has_ip":            [1]*(n//4) + [0]*(n//4) +
                             [0]*(n//4) + [0]*(n//4),
        "has_https":         [0]*(n//2) + [1]*(n//2),
        "suspicious_words":  list(np.random.randint(3,8, n//2)) +
                             list(np.random.randint(0,2, n//2)),
        "spf_fail":          [1]*(n//2) + [0]*(n//2),
        "dkim_fail":         [1]*(n//2) + [0]*(n//2),
        "dmarc_fail":        [1]*(n//2) + [0]*(n//2),
        "reply_to_mismatch": [1]*(n//3) + [0]*(n - n//3),
        "dot_count":         list(np.random.randint(4,8, n//2)) +
                             list(np.random.randint(1,3, n//2)),
        "vt_score":          list(np.random.randint(50,100, n//2)) +
                             list(np.random.randint(0,10,  n//2)),
        "label":             [1]*(n//2) + [0]*(n//2),
    }

    return pd.DataFrame(data)


if __name__ == "__main__":
    download_datasets()
    prepare_combined()