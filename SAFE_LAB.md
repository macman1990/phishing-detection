# Safe Lab Environment — AMIT Phishing Detection Project

## Overview
This project was developed and tested in an isolated environment
to safely analyze phishing samples without risk to production systems.

## Environment Setup

### Isolation Method
- Virtual Machine: Windows 10 (Host) + isolated venv
- Network: Restricted outbound — only VirusTotal & URLhaus APIs allowed
- No real phishing emails stored permanently
- All test samples are synthetic or from approved public datasets

## Dataset Sources
| Source | Type | Samples |
|--------|------|---------|
| GregaVrbancic/Phishing-Dataset (GitHub) | URL features | 58,645 |
| Synthetic test.eml | Email headers | 1 |

## API Keys Management
| API | Usage | Key Storage |
|-----|-------|-------------|
| VirusTotal | URL reputation | Environment variable |
| URLhaus | URL blacklist | No key required |

## Safety Rules Applied
1. Never store real victim email addresses
2. Never execute suspicious attachments
3. All URLs analyzed remotely — never visited directly
4. Test samples contain no real PII
5. API keys rotated after testing

## MITRE ATT&CK Coverage
| Technique | ID | Covered |
|-----------|-----|---------|
| Phishing | T1566 | ✅ |
| Spearphishing Link | T1566.001 | ✅ |
| Spearphishing Attachment | T1566.002 | ✅ |
| Gather Victim Info | T1598 | ✅ |

## Validation Results
| Metric | Score |
|--------|-------|
| Accuracy | 83.6% |
| Precision | 85.7% |
| Recall | 81.7% |
| F1-Score | 83.6% |
| AUC-ROC | 91.1% |
| Avg Latency | 4.07ms |