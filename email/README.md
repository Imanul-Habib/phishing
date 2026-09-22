# Spam + URL Risk Detector

A Streamlit app that combines two machine-learning components:

1. **Spam/ham message classification** using **TF-IDF + Logistic Regression**.
2. **URL classification/risk assessment** using engineered URL features + **Random Forest**.

The app reorganizes the supplied spam-mail and malicious-URL notebook workflows into one runnable application.

## Project structure

```text
email/
├── app.py
├── requirements.txt
├── README.md
├── mail_data.csv              # keep locally; not included in the repo
└── malicious_phish.csv        # keep locally; not included in the repo
```

## What the app does

### Message model

```text
Message
   ↓
TF-IDF
   ↓
Logistic Regression
   ↓
SPAM / HAM + spam probability
```

The app also displays the strongest TF-IDF × model-coefficient contributions for the message.

### URL model

```text
Message
   ↓
URL extraction
   ↓
URL feature engineering
   ↓
Random Forest
   ↓
URL class learned from malicious_phish.csv
```

URL features include observable properties such as URL length, hostname length, dots, `@`, digits, HTTP/HTTPS text, shortening-service patterns, suspicious keywords, directory depth, and related URL structure.

**Important:** this is not a live URL reputation service. The result is a machine-learning classification based on the supplied URL dataset.

## Expected datasets

### `mail_data.csv`

Required columns:

- `Category` — expected values: `spam` and `ham`
- `Message` — message text

### `malicious_phish.csv`

Required columns:

- `url` — URL string
- `type` — URL class used by the dataset

The app validates these column names before training.

## Run locally

Open a terminal in the `email/` directory:

```bash
pip install -r requirements.txt
streamlit run app.py
```

Then open the local Streamlit URL shown in the terminal and upload both CSV files in the sidebar.

## Run in Google Colab

In a Colab cell:

```python
!pip install -r requirements.txt
!streamlit run app.py
```

For a normal college demo, running the project locally is simpler. If using Colab, expose the Streamlit port with a tunneling tool approved by your environment.

## GitHub

Repository:

https://github.com/Imanul-Habib/phishing

Application files are under:

```text
email/
```

The datasets are intentionally kept outside the repository unless you have permission to redistribute them.

## Reproducibility

The message split uses:

- test size: 20%
- random state: 3
- TF-IDF: `min_df=1`, English stop-word removal, lowercase text
- Logistic Regression: `max_iter=1000`

The URL split uses:

- test size: 20%
- stratification by URL class
- random state: 5
- Random Forest: 100 trees, `max_features="sqrt"`

Final project metrics should be reported from the app's own evaluation run rather than copied from an earlier experiment.

## Scope and limitations

The available mail dataset contains message content and its spam/ham label. It does **not** provide sender identity, sender-domain reputation, subject fields, attachments, or email headers. Therefore those features are not claimed by this implementation.

The URL module is separate from the message classifier. A message can be classified as spam/ham independently of whether it contains a URL, and each extracted URL receives its own model output.

This project is intended for academic demonstration, not as a production anti-phishing or email-security system.

## Suggested demo flow

1. Start the app.
2. Upload both datasets.
3. Open **Model metrics**.
4. Paste a normal message and analyze it.
5. Paste a message containing a URL.
6. Show the separate URL result.
7. Show the TF-IDF contribution table and explain that the model is using learned feature weights.
8. Present the novelty as the **separate URL-risk analysis layer**, not simply URL detection.

## Future improvements

- Save trained models with `joblib` instead of retraining after each app restart.
- Add a dedicated train/evaluate script.
- Add cross-validation and class-aware metrics.
- Add more robust URL parsing and validation.
- Add live reputation checks only through a trustworthy external service.
- Add sender/domain features if a genuine email dataset with those fields becomes available.
