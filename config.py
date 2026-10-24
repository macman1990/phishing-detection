import os

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "YOUR_VT_KEY_HERE")
SIEM_HOST = os.getenv("SIEM_HOST", "localhost")
SIEM_PORT = int(os.getenv("SIEM_PORT", "514"))
MODEL_PATH   = "data/model.pkl"
DATASET_PATH = "data/dataset.csv"
REPORTS_PATH = "reports/"
LOG_PATH     = "reports/siem_alerts.log"
WEIGHTS = {
    "header": 0.25, "content": 0.20, "url": 0.20,
    "vt": 0.15, "urlhaus": 0.10, "ml": 0.10,
}
THRESHOLDS = {
    "CRITICAL": 75, "HIGH": 50, "MEDIUM": 25, "LOW": 0,
}
