import pandas as pd
import requests


def download_dataset():
    print("جاري تحميل الـ dataset...")
    url = "https://raw.githubusercontent.com/GregaVrbancic/Phishing-Dataset/master/dataset_small.csv"
    response = requests.get(url, timeout=30)
    with open("data/phishing_raw.csv", "wb") as f:
        f.write(response.content)
    print("✅ تم التحميل")


def prepare_dataset():
    df = pd.read_csv("data/phishing_raw.csv")
    prepared = pd.DataFrame()
    prepared["url_length"]        = df["length_url"]
    prepared["has_ip"]            = df["domain_in_ip"]
    prepared["has_https"]         = df["tls_ssl_certificate"]
    prepared["suspicious_words"]  = df["qty_at_url"] + df["qty_percent_url"]
    prepared["spf_fail"]          = df["domain_spf"].apply(lambda x: 1 if x == 0 else 0)
    prepared["dkim_fail"]         = 0
    prepared["dmarc_fail"]        = 0
    prepared["reply_to_mismatch"] = df["email_in_url"]
    prepared["dot_count"]         = df["qty_dot_url"]
    prepared["vt_score"]          = df["url_google_index"].apply(lambda x: 0 if x == 1 else 50)
    prepared["label"]             = df["phishing"]
    prepared = prepared.fillna(0).astype(int)
    prepared.to_csv("data/dataset.csv", index=False)
    total    = len(prepared)
    phishing = prepared["label"].sum()
    clean    = total - phishing
    print(f"✅ Dataset ready: {total} samples")
    print(f"   Phishing: {phishing} ({phishing/total*100:.1f}%)")
    print(f"   Clean:    {clean} ({clean/total*100:.1f}%)")


if __name__ == "__main__":
    download_dataset()
    prepare_dataset()