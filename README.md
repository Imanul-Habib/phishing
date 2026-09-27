# 🛡️ Phishing & Spam Risk Detector

## 🌐 Live Demo

👉 [Open the Streamlit ML demo](https://phishing-4uzc2mrxxqyg99rhxmvflu.streamlit.app/)

A student-built machine-learning application for detecting spam/phishing messages, analyzing URLs, and producing an interpretable **LOW / MEDIUM / HIGH risk assessment**.

📘 **Technical documentation:** [DOCUMENTATION.md](./DOCUMENTATION.md) — approach, model choices, feature engineering, risk engine, evaluation, limitations, and setup.

## ✨ Features

- Spam/Ham message classification with TF-IDF + Logistic Regression
- URL extraction and engineered URL features
- URL classification with Random Forest
- Multi-signal risk engine combining message probability, URL signals, urgency, credential requests, personal-information requests, threats, and requested actions
- Explainable risk signals shown alongside the classification
- Model metrics and explanation
- Web-based interface

## 🧠 Risk Engine

The project now includes a refined risk-engine layer after the spam and URL models:

**Message → Spam probability + URL results → risk signals → LOW / MEDIUM / HIGH**

The refined risk-engine training experiment used **7,996 unique email rows**:

| Metric | Result |
|---|---:|
| Accuracy | 89.75% |
| Macro F1 | 90.85% |
| LOW F1 | 85.41% |
| MEDIUM F1 | 87.27% |
| HIGH F1 | 99.87% |

The risk labels used for this experiment were **engineered labels produced by the project's refined v2 scoring rubric**, not manually verified ground truth. Therefore these metrics measure agreement with the engineered rubric and should not be presented as real-world security accuracy.

The repository includes the risk-engine inference/scoring module. The large trained Random Forest artifact is kept as a local build artifact for the current demo; if you add `risk_engine_rf_v4_9000.joblib` beside `email/app.py`, the helper can load it.

## 🏗️ Architecture

```
Email / SMS
   │
   ├──► TF-IDF ──► Logistic Regression ──► SPAM probability
   │
   └──► URL extraction ──► 21 URL features ──► Random Forest ──► URL risk
                              │
                              └──────────────┐
                                             ▼
                                      Risk Engine
                                             │
                              ┌──────────────┼──────────────┐
                              ▼              ▼              ▼
                            LOW           MEDIUM           HIGH
```

## 🛠️ Technologies Used

- Python
- Streamlit
- Pandas
- Scikit-learn
- TF-IDF
- Logistic Regression
- Random Forest
