# 🛡️ Phishing Detection & Analysis System

> **AMIT Graduate Project — SOC Blue Team Pipeline & Triage Engine**

---

## 📌 Overview

A mini SOC-style phishing detection pipeline that analyzes suspicious emails using **6 detection layers** and produces a risk verdict with an analyst-ready incident report.

Designed for **automated triage** rather than a simple blacklist check, the pipeline combines:
- Rule-based checks
- Threat-intelligence enrichment
- Machine-learning classification
- Full explainability for SOC analysts

---

## 🏗️ Project Structure

```
phishing-detection/
├── main.py                    # Streamlit Web Dashboard
├── config.py                  # Configuration & API settings
├── requirements.txt           # Python dependencies
├── .env                       # API keys (not committed)
├── .gitignore
│
├── modules/
│   ├── __init__.py
│   ├── email_parser.py        # EML parser — headers, URLs, attachments
│   ├── header_checker.py      # SPF / DKIM / DMARC validation
│   ├── content_analyzer.py    # Urgency, credential, impersonation detection
│   ├── url_analyzer.py        # URL feature extraction & lookalike detection
│   ├── threat_intel.py        # VirusTotal + URLhaus API integration
│   ├── risk_engine.py         # Multi-layer weighted scoring engine
│   ├── ml_classifier.py       # Random Forest classifier
│   ├── report_generator.py    # PDF incident report generator
│   └── siem_integration.py    # SIEM alert forwarding
│
├── data/
│   ├── download_dataset.py    # Dataset downloader & preprocessor
│   ├── create_dataset.py      # Sample dataset creator
│   ├── validation.py          # Model validation & testing
│   ├── dataset.csv            # 58,645 labeled URL samples
│   ├── model.pkl              # Trained ML model
│   └── test.eml               # Test phishing email sample
│
└── reports/
    ├── incident_report.pdf    # Generated PDF report
    ├── validation_report.json # Model validation metrics
    └── siem_alerts.log        # SIEM alert history
```

---

## 🔍 Detection Layers

| # | Layer | Method | Weight |
|---|-------|--------|--------|
| 1 | **Header & Auth** | SPF / DKIM / DMARC validation | 25% |
| 2 | **Content Analysis** | Urgency / credential / impersonation | 20% |
| 3 | **URL Analysis** | Lookalike / obfuscation / patterns | 20% |
| 4 | **VirusTotal** | 70+ AV engines reputation check | 15% |
| 5 | **URLhaus** | Malware URL blacklist | 10% |
| 6 | **ML Classifier** | Random Forest — 83.6% accuracy | 10% |

---

## 🚨 Risk Verdicts

| Score | Verdict | Action |
|-------|---------|--------|
| 75–100 | 🔴 CRITICAL | Immediate escalation |
| 50–74 | 🟠 HIGH | Block & quarantine |
| 25–49 | 🟡 MEDIUM | Investigate |
| 0–24 | 🟢 LOW | Monitor |

---

## ⚙️ Installation

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/phishing-detection.git
cd phishing-detection

# 2. Create virtual environment
python -m venv venv

# 3. Activate virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt
```

---

## 🔑 Configuration

Create a `.env` file in the root directory:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
SIEM_HOST=localhost
SIEM_PORT=514
```

Get your free VirusTotal API key at: https://www.virustotal.com

---

## 🚀 Usage

### Run Web Dashboard
```bash
streamlit run main.py
```
Open: http://localhost:8501

### Analyze from CLI
```bash
python -m modules.risk_engine data/test.eml
```

### Train ML Model
```bash
python data/download_dataset.py
python -m modules.ml_classifier
```

### Run Validation
```bash
python data/validation.py
```

### Generate PDF Report
```bash
python -m modules.report_generator data/test.eml
```

---

## 📊 Model Performance

| Metric | Score |
|--------|-------|
| **Accuracy** | 83.6% |
| **Precision** | 85.7% |
| **Recall** | 81.7% |
| **F1-Score** | 83.6% |
| **AUC-ROC** | 91.1% |
| **False Positive Rate** | 14.9% |
| **Avg Latency** | 4.07 ms |
| **Dataset Size** | 58,645 samples |

---

## 🗺️ MITRE ATT&CK Coverage

| Technique ID | Name | Status |
|-------------|------|--------|
| T1566 | Phishing | ✅ Detected |
| T1566.001 | Spearphishing Link | ✅ Detected |
| T1566.002 | Spearphishing Attachment | ✅ Monitored |
| T1598 | Gather Victim Info | ✅ Detected |

---

## 🛠️ Tech Stack

| Category | Tools |
|----------|-------|
| **Language** | Python 3.11 |
| **Web UI** | Streamlit |
| **ML** | scikit-learn, pandas, numpy |
| **Email Parsing** | eml-parser, BeautifulSoup |
| **DNS** | dnspython |
| **Threat Intel** | VirusTotal API, URLhaus API |
| **SIEM** | Wazuh / ELK / Splunk compatible |
| **Reporting** | ReportLab PDF |
| **Storage** | SQLite, JSON logs |

---

## 📦 Project Deliverables

- ✅ Fully Operational Pipeline (Backend + Web UI)
- ✅ Detection Rule & ML Package with scoring logic
- ✅ Sample Analysis Reports with evidence & IOCs
- ✅ SIEM Integration rules & validation reports
- ✅ Validation Report (precision, recall, F1, AUC-ROC)

---

## 👨‍💻 Developer

**YUSIF ALI**
AMIT Graduate Program — 2026
SOC Blue Team Track

---

## 📄 License

This project is developed for educational purposes as part of the AMIT Graduate Program.    # phishing-detection
