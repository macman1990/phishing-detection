import json
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.metrics import (
    classification_report, confusion_matrix,
    precision_score, recall_score, f1_score,
    roc_auc_score
)
import pickle
import time
import numpy as np


FEATURES = [
    "url_length", "has_ip", "has_https", "suspicious_words",
    "spf_fail", "dkim_fail", "dmarc_fail", "reply_to_mismatch",
    "dot_count", "vt_score"
]


def run_validation():
    print("=" * 55)
    print("  PHISHING DETECTION SYSTEM — VALIDATION REPORT")
    print("=" * 55)

    df = pd.read_csv("data/dataset.csv")
    X  = df[FEATURES]
    y  = df["label"]

    with open("data/model.pkl", "rb") as f:
        model = pickle.load(f)

    # ── 1. Cross Validation ──
    print("\n📊 1. Cross-Validation (5-Fold)")
    print("-" * 40)
    cv     = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = cross_val_score(model, X, y, cv=cv, scoring="accuracy")
    print(f"Accuracy per fold: {[f'{s:.3f}' for s in scores]}")
    print(f"Mean Accuracy:     {scores.mean():.3f} ± {scores.std():.3f}")

    # ── 2. Classification Report ──
    print("\n📊 2. Classification Report")
    print("-" * 40)
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42
    )
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    print(classification_report(
        y_test, y_pred,
        target_names=["Clean", "Phishing"]
    ))

    # ── 3. Confusion Matrix ──
    print("📊 3. Confusion Matrix")
    print("-" * 40)
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print(f"True  Negative  (Clean → Clean):       {tn}")
    print(f"False Positive  (Clean → Phishing):    {fp}")
    print(f"False Negative  (Phishing → Clean):    {fn}")
    print(f"True  Positive  (Phishing → Phishing): {tp}")

    # ── 4. Key Metrics ──
    print("\n📊 4. Key Metrics")
    print("-" * 40)
    precision   = precision_score(y_test, y_pred)
    recall      = recall_score(y_test, y_pred)
    f1          = f1_score(y_test, y_pred)
    auc         = roc_auc_score(y_test, y_prob)
    fpr         = fp / (fp + tn)

    print(f"Precision:          {precision:.3f}  ({precision*100:.1f}%)")
    print(f"Recall:             {recall:.3f}  ({recall*100:.1f}%)")
    print(f"F1-Score:           {f1:.3f}  ({f1*100:.1f}%)")
    print(f"AUC-ROC:            {auc:.3f}  ({auc*100:.1f}%)")
    print(f"False Positive Rate:{fpr:.3f}  ({fpr*100:.1f}%)")

    # ── 5. Latency Test ──
    print("\n📊 5. System Latency")
    print("-" * 40)
    sample = X_test.iloc[:1]
    times  = []
    for _ in range(100):
        start = time.time()
        model.predict(sample)
        times.append((time.time() - start) * 1000)

    print(f"Avg prediction time: {np.mean(times):.3f} ms")
    print(f"Max prediction time: {np.max(times):.3f} ms")

    # ── 6. Feature Importance ──
    print("\n📊 6. Feature Importance")
    print("-" * 40)
    importance = pd.Series(
        model.feature_importances_, index=FEATURES
    ).sort_values(ascending=False)
    for feat, score in importance.items():
        bar = "█" * int(score * 50)
        print(f"{feat:<25} {score:.3f} {bar}")

    # ── Summary ──
    print("\n" + "=" * 55)
    print("  SUMMARY")
    print("=" * 55)
    print(f"  Dataset Size:    {len(df):,} samples")
    print(f"  Accuracy:        {scores.mean()*100:.1f}%")
    print(f"  Precision:       {precision*100:.1f}%")
    print(f"  Recall:          {recall*100:.1f}%")
    print(f"  F1-Score:        {f1*100:.1f}%")
    print(f"  AUC-ROC:         {auc*100:.1f}%")
    print(f"  False Pos Rate:  {fpr*100:.1f}%")
    print(f"  Avg Latency:     {np.mean(times):.2f} ms")
    print("=" * 55)

    # ── حفظ التقرير ──
    report = {
        "dataset_size":       len(df),
        "accuracy":           round(scores.mean(), 3),
        "precision":          round(precision, 3),
        "recall":             round(recall, 3),
        "f1_score":           round(f1, 3),
        "auc_roc":            round(auc, 3),
        "false_positive_rate":round(fpr, 3),
        "avg_latency_ms":     round(np.mean(times), 3),
        "confusion_matrix": {
            "TP": int(tp), "TN": int(tn),
            "FP": int(fp), "FN": int(fn),
        }
    }
    with open("reports/validation_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print("\n✅ Saved: reports/validation_report.json")


if __name__ == "__main__":
    run_validation()
    