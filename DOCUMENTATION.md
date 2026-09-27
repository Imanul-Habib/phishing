# 📘 Technical Documentation — Phishing & Spam Risk Detector

## 1. Project Overview

This project is a lightweight machine-learning system for analyzing suspicious email/SMS messages and the URLs contained in them.

The system is designed as a **multi-stage detector** rather than relying on a single classifier:

1. Classify the message as **SPAM** or **HAM**.
2. Extract URLs from the message.
3. Convert each URL into engineered structural features and classify it with a separate Random Forest model.
4. Combine message-level and URL-level signals in a **risk engine**.
5. Produce an interpretable **LOW / MEDIUM / HIGH** risk assessment and supporting risk signals.

The goal is not to claim that one model can definitively identify every phishing message. Instead, the project combines several practical signals so that the final output is easier to understand and demonstrate.

---

## 2. Why This Approach?

A phishing message can look suspicious for several different reasons. For example:

- the wording may resemble known spam;
- the message may contain a suspicious URL;
- the recipient may be asked to log in or provide an OTP;
- the message may create urgency or threaten account suspension;
- several of these signals may occur together.

A single text classifier mainly sees the **language of the message**. It does not explicitly reason about the structure of a URL.

For this reason, the project separates the problem into components:

**Message text → text classifier**

**URL → URL feature extractor → URL classifier**

**Message + URL results + security signals → risk engine**

This makes the system modular and also gives the project a clear novelty layer beyond a basic spam classifier.

---

## 3. System Architecture

```
                         Email / SMS
                              │
                 ┌────────────┴────────────┐
                 │                         │
                 ▼                         ▼
          Message Text               URL Extraction
                 │                         │
                 ▼                         ▼
          TF-IDF Vectorizer          21 URL Features
                 │                         │
                 ▼                         ▼
       Logistic Regression          Random Forest
                 │                         │
                 ▼                         ▼
          Spam Probability            URL Risk Labels
                 │                         │
                 └────────────┬────────────┘
                              ▼
                       Risk Engine
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
            LOW            MEDIUM           HIGH
```

The deployed Streamlit application trains the message and URL models from the available datasets and uses the trained risk-engine artifact when it is available.

---

## 4. Component 1 — Message Classification

### 4.1 Input

The message model uses the `Category` and `Message` columns from `email/mail_data.csv`.

The categories are normalized to:

- `spam`
- `ham`

The application maps them internally to numeric classes for model training.

### 4.2 Text preprocessing

The project uses **TF-IDF (Term Frequency–Inverse Document Frequency)** to convert text into numerical features.

Configuration:

- lowercase text;
- English stop-word removal;
- unigram and bigram features;
- sublinear TF scaling.

A unigram represents one word, while a bigram represents two consecutive words. Using both allows the model to capture signals such as individual words as well as short phrases.

### 4.3 Model

The message classifier is **Logistic Regression** with balanced class weights.

The choice is deliberate:

- it is lightweight enough for a student project;
- it trains quickly;
- it works well with sparse TF-IDF features;
- its coefficients can be inspected;
- it provides class probabilities that can be passed to the risk engine.

The application also displays important spam-leaning and ham-leaning terms for an analyzed message. This provides a simple explanation of why the text model leaned toward one class.

### 4.4 Why not use a large language model?

A transformer or large language model could be used, but it would add considerably more computational and implementation complexity.

For this project, TF-IDF + Logistic Regression provides a strong baseline while remaining:

- fast;
- understandable;
- reproducible;
- easy to deploy;
- easy to explain during a technical demonstration.

---

## 5. Component 2 — URL Extraction

Messages are scanned for:

- URLs beginning with `http://` or `https://`;
- `www.` URLs;
- recognized bare domains such as `example.com`.

URLs are normalized by adding `https://` when a protocol is missing, and duplicates are removed.

This step is important because phishing messages frequently use links as the mechanism that takes the recipient to a malicious or fraudulent destination.

---

## 6. Component 3 — URL Feature Engineering

Instead of treating a URL as plain text, the project extracts structural properties from it.

The URL model uses **21 engineered features**, including:

| Feature | What it represents |
|---|---|
| `use_of_ip` | Whether the hostname is an IP address |
| `abnormal_url` | Structural URL/hostname check |
| `count.` | Number of dots |
| `count-www` | Occurrences of `www` |
| `count@` | Use of `@` in the URL |
| `count_dir` | Number of path directories |
| `count_embed_domian` | Embedded-domain/path structure |
| `short_url` | Known URL-shortener pattern |
| `count-https` | Occurrences of `https` |
| `count-http` | Occurrences of `http` |
| `count%` | Percent-encoding characters |
| `count?` | Query markers |
| `count-` | Hyphens |
| `count=` | Equals signs |
| `url_length` | Total URL length |
| `hostname_length` | Hostname length |
| `sus_url` | Suspicious keyword pattern |
| `fd_length` | First directory/path length |
| `tld_length` | Top-level-domain length |
| `count-digits` | Number of digits |
| `count-letters` | Number of letters |

### Why engineered URL features?

Phishing URLs often have structural characteristics that are useful independently of the message wording. Engineered features let the model learn these patterns without requiring a large language model.

This also makes the URL-analysis component explainable: the project can describe exactly what properties are being measured.

---

## 7. URL Classification Model

The URL features are passed to a **Random Forest classifier**.

Random Forest was selected because it:

- handles mixed numerical feature patterns well;
- can learn non-linear relationships;
- requires relatively little feature scaling;
- is lightweight enough for this prototype;
- works naturally with engineered security features.

The URL dataset used by the application is:

`malicious_phish.csv`

The deployed application can download it from the public GitHub release used in the code:

https://github.com/rajashree2407/phishing/releases/download/v1.0-data/malicious_phish.csv

---

## 8. Component 4 — Risk Engine

The main novelty of the project is the additional **risk-engine layer**.

Instead of stopping at:

> "This message is spam."

the system combines multiple signals and produces:

> **LOW / MEDIUM / HIGH risk**

The risk engine considers signals such as:

- message spam/phishing probability;
- URL model output;
- credential or OTP requests;
- requests for personal information;
- threat or pressure language;
- requested actions such as clicking, verifying, paying, or updating;
- urgency language;
- suspicious security/account keywords;
- number of links;
- detected brand mentions.

This provides a more informative output than a binary spam/ham prediction alone.

---

## 9. Risk Scoring Logic

The fallback scoring rubric assigns points to security signals.

Examples include:

| Signal | Points |
|---|---:|
| Spam/phishing probability ≥ 90% | +5 |
| Spam/phishing probability ≥ 70% | +4 |
| Spam/phishing probability ≥ 50% | +2 |
| Malicious URL result | +4 |
| Suspicious URL result | +2 |
| Credential/OTP request | +3 |
| Personal-information request | +2 |
| Threat/pressure language | +1 |
| Requested action | +1 |
| Multiple suspicious keywords | +1 or +2 |
| Repeated urgency language | +1 or +2 |
| Three or more links | +1 |

The resulting score is mapped to:

- **LOW:** score < 5
- **MEDIUM:** score 5–9
- **HIGH:** score ≥ 10

Brand mentions are displayed as an explanatory signal but are not independently used to increase the score.

The trained risk-engine model uses the same refined signal-labeling approach for its training experiment.

---

## 10. Trained Risk Engine

The repository contains a trained Random Forest risk-engine artifact.

The training experiment used **7,996 unique email rows** with engineered refined-v2 risk labels.

The model uses a larger feature representation than the live URL classifier, including features such as:

- email length;
- word count;
- reading time;
- character entropy;
- readability score;
- number of links;
- special-character count;
- uppercase-word count;
- suspicious-keyword count;
- urgency score;
- grammar score;
- phishing probability;
- domain age;
- link/attachment/HTML indicators;
- SPF, DKIM and DMARC status;
- sender reputation;
- spoofed-domain indicator;
- URL reputation;
- brand-impersonation information.

### Important deployment assumption

A pasted message in the live Streamlit interface does not contain all of those email metadata fields.

For unavailable fields, the inference adapter uses neutral/default values such as:

- domain age: 365 days;
- SPF: Pass;
- DKIM: Pass;
- DMARC: Pass;
- sender reputation: Unknown;
- spoofed domain: No.

Therefore, the live demo should be understood as an adapter around the trained model, not as a claim that the application has access to hidden sender infrastructure data.

---

## 11. Risk-Engine Evaluation

The current risk-engine experiment produced:

| Metric | Result |
|---|---:|
| Dataset rows | 7,996 |
| Accuracy | 89.75% |
| Macro F1 | 90.85% |
| LOW F1 | 85.41% |
| MEDIUM F1 | 87.27% |
| HIGH F1 | 99.87% |

The class distribution was:

| Risk class | Rows |
|---|---:|
| LOW | 2,747 |
| MEDIUM | 3,260 |
| HIGH | 1,989 |

### Interpretation

The confusion matrix was:

```
                 Predicted
              LOW  MED  HIGH

Actual LOW    477   73    0
Actual MED     90  562    0
Actual HIGH     0    1  397
```

The model separates the HIGH class very strongly in this experiment, while some LOW and MEDIUM examples are confused with each other.

### Important limitation

These are **not manually verified real-world phishing labels**.

The risk labels were generated using the project's refined-v2 scoring rubric. Therefore, the reported metrics measure how well the Random Forest reproduces those engineered labels.

They should **not** be presented as real-world security accuracy.

---

## 12. Novelty

The base problem could be solved with a simple spam/ham text classifier.

This project extends that baseline in three identifiable ways:

### 12.1 Separate URL intelligence

The system extracts URLs and analyzes their structural characteristics using a dedicated feature pipeline and Random Forest model.

### 12.2 Multi-signal risk engine

The final result combines:

`message probability + URL signals + security-language signals + requested actions`

rather than returning only SPAM/HAM.

### 12.3 Explainable output

The application exposes:

- spam probability;
- spam-leaning and ham-leaning terms;
- URL classifications;
- risk level;
- risk signals;
- detected brand mentions;
- model metrics.

This makes the result easier for a user to inspect instead of presenting an unexplained prediction.

---

## 13. Why These Models Were Chosen

| Component | Method | Reason |
|---|---|---|
| Message classification | TF-IDF + Logistic Regression | Fast, interpretable, strong baseline for text |
| URL classification | 21 engineered features + Random Forest | Captures non-linear structural URL patterns |
| Risk engine | Rule-derived labels + Random Forest | Combines heterogeneous security signals into a practical risk category |
| Interface | Streamlit | Fast deployment and simple ML demonstration |

The overall design prioritizes **practicality, explainability and low computational overhead**, which is appropriate for a student prototype.

---

## 14. Data Processing and Assumptions

### Message data

The message classifier expects:

- `Category`
- `Message`

The application removes unused columns and normalizes category/message values before training.

### URL data

The URL classifier expects:

- `url`
- `type`

Rows with missing required values are removed before feature extraction.

### Risk-engine data

The risk-engine experiment was built from email records containing message, URL, sender/domain and security metadata. Refined-v2 labels were generated from a scoring rubric before the Random Forest was trained.

---

## 15. Limitations

This prototype has several limitations:

1. **Engineered labels:** the risk-engine evaluation labels are generated by rules rather than manually verified security labels.
2. **Limited live metadata:** a pasted message does not provide sender reputation, SPF/DKIM/DMARC results, domain age or spoofing information.
3. **URL heuristics:** URL features describe structural patterns and do not prove that a destination is malicious.
4. **Dataset dependence:** model behavior depends on the datasets used for training.
5. **No guarantee of zero false positives/negatives:** legitimate messages can look suspicious and phishing messages can be written convincingly.
6. **No live website inspection:** the system does not visit a URL and determine whether its destination is safe.
7. **Prototype scope:** this is an academic demonstration, not a replacement for a production email-security gateway.

---

## 16. Reproducibility and Running the Project

### Requirements

The main application uses:

- Python
- Streamlit
- Pandas
- scikit-learn
- joblib

The dependency list is stored in:

`email/requirements.txt`

### Run locally

From the repository root:

```bash
cd email
pip install -r requirements.txt
streamlit run app.py
```

The application loads `mail_data.csv` from the `email` directory.

The URL dataset can be loaded from the public release configured in `app.py`, or supplied locally as `email/malicious_phish.csv`.

The risk-engine model artifact can be placed beside `app.py` as:

`risk_engine_rf_v4_9000.joblib`

A compressed `.joblib.gz` artifact is also supported by the loader.

---

## 17. Project Flow for Demonstration

A simple demo can be presented in this order:

1. Paste an ordinary message and analyze it.
2. Show the SPAM/HAM prediction and probability.
3. Point out the terms that influenced the message model.
4. Paste a message containing a suspicious-looking URL.
5. Show the extracted URL and URL-model result.
6. Show the final LOW/MEDIUM/HIGH risk level.
7. Explain the risk signals that contributed to the final assessment.
8. Open the Model Metrics tab to show the evaluation results.
9. Explain that the risk-engine metrics are against engineered labels, not manually verified ground truth.

---

## 18. Conclusion

The project combines a simple text-classification baseline with dedicated URL analysis and a multi-signal risk engine.

The key design decision is to treat phishing detection as a **combination of signals** rather than only a binary text-classification problem.

This gives the prototype three useful properties:

- **Practical:** lightweight models that can run in a student-scale deployment.
- **Explainable:** the application shows probabilities, terms, URL results and risk signals.
- **Extensible:** additional metadata, URL reputation services or stronger models can be added later without replacing the entire architecture.

> **Note:** This project is an academic prototype. Its risk assessment should not be treated as a definitive security verdict.
