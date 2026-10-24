import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import pickle
import os
from config import MODEL_PATH


def extract_features(report: dict) -> dict:
    """بيحول الـ report لـ features الـ ML"""
    urls = report.get("urls_analyzed", [])
    auth = report.get("auth_results", {})

    url_length       = len(urls[0]["url"]) if urls else 0
    has_ip           = 1 if urls and "ip_as_domain" in urls[0]["flags"] else 0
    has_https        = 0 if urls and "no_https" in urls[0]["flags"] else 1
    suspicious_words = sum(1 for f in (urls[0]["flags"] if urls else [])
                           if f.startswith("keyword_"))
    dot_count        = urls[0]["url"].count(".") if urls else 0
    vt_score         = urls[0]["vt_score"] if urls else 0

    return {
        "url_length":        url_length,
        "has_ip":            has_ip,
        "has_https":         has_https,
        "suspicious_words":  suspicious_words,
        "spf_fail":          1 if auth.get("spf")   == "fail" else 0,
        "dkim_fail":         1 if auth.get("dkim")  == "fail" else 0,
        "dmarc_fail":        1 if auth.get("dmarc") == "fail" else 0,
        "reply_to_mismatch": 1 if "reply_to_mismatch" in report.get("flags", []) else 0,
        "dot_count":         dot_count,
        "vt_score":          vt_score,
    }


def train_model():
    """بيدرب الموديل ويحفظه"""
    df = pd.read_csv("data/dataset.csv")

    features = ["url_length", "has_ip", "has_https", "suspicious_words",
                "spf_fail", "dkim_fail", "dmarc_fail", "reply_to_mismatch",
                "dot_count", "vt_score"]

    X = df[features]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42
    )

    # Random Forest
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # تقييم الموديل
    y_pred = model.predict(X_test)
    print("📊 Model Evaluation:")
    print(classification_report(y_test, y_pred,
          target_names=["Clean", "Phishing"]))

    # حفظ الموديل
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    print(f"✅ Model saved: {MODEL_PATH}")

    return model


def load_model():
    """بيحمل الموديل المحفوظ"""
    if not os.path.exists(MODEL_PATH):
        print("⚠️ Model not found — training now...")
        return train_model()

    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)


def predict(report: dict) -> dict:
    """بياخد report ويرجع تنبؤ الـ ML"""
    model    = load_model()
    features = extract_features(report)
    X        = pd.DataFrame([features])

    prediction   = model.predict(X)[0]
    probability  = model.predict_proba(X)[0]
    ml_score     = int(probability[1] * 100)

    return {
        "ml_score":      ml_score,
        "ml_verdict":    "Phishing" if prediction == 1 else "Clean",
        "confidence":    f"{max(probability)*100:.1f}%",
        "features_used": features,
    }


if __name__ == "__main__":
    import json
    from modules.risk_engine import run_analysis

    # تدريب
    train_model()

    # تنبؤ
    report = run_analysis("data/test.eml")
    result = predict(report)

    print("\n🤖 ML Prediction:")
    print(f"Score:      {result['ml_score']}/100")
    print(f"Verdict:    {result['ml_verdict']}")
    print(f"Confidence: {result['confidence']}")