"""Risk engine for phishing-email analysis.

The trained RF model can be loaded when the model artifact is available. The
fallback scorer implements the refined-v2 signal rubric used to create the
training labels, so the repository remains runnable without a binary model.
"""
from __future__ import annotations

import gzip
import os
import re
import urllib.request
from pathlib import Path
from typing import Any

import joblib
import pandas as pd

MODEL_PATH = Path(__file__).resolve().parent / "risk_engine_rf_v4_9000.joblib"
MODEL_GZ_PATH = Path(__file__).resolve().parent / "risk_engine_rf_v4_9000.joblib.gz"
MODEL_URL = os.getenv(
    "RISK_MODEL_URL",
    "https://raw.githubusercontent.com/Imanul-Habib/phishing/main/email/risk_engine_rf_v4_9000.joblib.gz",
)

PATTERNS = {
    "credential": re.compile(r"password|passcode|credential|login|sign[ -]?in|otp|one[- ]time password|verification code", re.I),
    "personal": re.compile(r"date of birth|dob|address|phone number|social security|aadhaar|pan card|identity|id number|personal information", re.I),
    "threat": re.compile(r"suspend|terminate|close your account|legal action|penalty|arrest|blocked|locked|warning", re.I),
    "action": re.compile(r"click|open|download|reply|call|confirm|verify|update|submit|pay|send", re.I),
    "urgency": re.compile(r"urgent|immediately|asap|right now|act now|last chance|expires|deadline|within \d+ hours?", re.I),
    "suspicious": re.compile(r"login|sign[ -]?in|verify|verification|account|password|credential|bank|payment|invoice|refund|otp|security|suspend|locked|click|update|confirm", re.I),
}
BRANDS = ["Adobe","Amazon","Apple","Bank of America","Binance","Chase Bank","Coinbase","Dropbox","Facebook","GitHub","Google","Instagram","LinkedIn","Microsoft","Netflix","PayPal","Slack","Steam","Zoom"]

def _count(pattern: re.Pattern[str], text: str) -> int:
    return len(pattern.findall(text))

def extract_risk_signals(message: str, spam_probability: float, url_labels: list[str] | None = None) -> dict[str, Any]:
    text = str(message or "")
    labels = [str(x).lower() for x in (url_labels or [])]
    signals: list[str] = []
    score = 0

    phishing_pct = float(spam_probability) * 100
    if phishing_pct >= 90:
        score += 5
    elif phishing_pct >= 70:
        score += 4
    elif phishing_pct >= 50:
        score += 2
    elif phishing_pct >= 30:
        score += 1
    if phishing_pct >= 70:
        signals.append("High spam/phishing probability")
    elif phishing_pct >= 50:
        signals.append("Elevated spam/phishing probability")

    if "malicious" in labels:
        score += 4
        signals.append("URL model flagged a malicious URL")
    elif "suspicious" in labels:
        score += 2
        signals.append("URL model flagged a suspicious URL")

    credential = _count(PATTERNS["credential"], text) > 0
    personal = _count(PATTERNS["personal"], text) > 0
    threat = _count(PATTERNS["threat"], text) > 0
    action = _count(PATTERNS["action"], text) > 0
    urgency_hits = _count(PATTERNS["urgency"], text)
    suspicious_hits = _count(PATTERNS["suspicious"], text)
    link_count = len(re.findall(r"(?:https?://|www\.)\S+|\b(?:[a-z0-9-]+\.)+(?:com|org|net|edu|gov|io|co|uk|in|xyz|me|app|site)\b", text, re.I))

    if credential:
        score += 3
        signals.append("Credential or OTP request")
    if personal:
        score += 2
        signals.append("Personal-information request")
    if threat:
        score += 1
        signals.append("Threat or pressure language")
    if action:
        score += 1
        signals.append("Action requested from recipient")
    if suspicious_hits >= 8:
        score += 2
    elif suspicious_hits >= 4:
        score += 1
    if urgency_hits >= 4:
        score += 2
    elif urgency_hits >= 2:
        score += 1
    if link_count >= 3:
        score += 1

    brand = next((b for b in BRANDS if re.search(re.escape(b), text, re.I)), None)
    if brand:
        signals.append(f"Brand mentioned: {brand}")

    label = "HIGH" if score >= 10 else "MEDIUM" if score >= 5 else "LOW"
    return {
        "risk_label": label,
        "risk_score": score,
        "signals": list(dict.fromkeys(signals)),
        "link_count": link_count,
        "brand_mentioned": brand,
        "note": "Risk assessment is an academic prototype, not a definitive security or legal verdict.",
    }


def predict_trained_risk(message: str, spam_probability: float, url_labels: list[str] | None = None) -> dict[str, Any] | None:
    """Run the trained 7,996-row RF when its artifact is present.

    The live pasted-message UI does not have sender/domain metadata, so missing
    fields are represented conservatively (for example, sender reputation is
    Unknown). This is a deployment adapter, not a claim that the RF has access
    to metadata that the user did not provide.
    """
    model = load_trained_model()
    if model is None:
        return None

    text = str(message or "")
    labels = [str(x).lower() for x in (url_labels or [])]
    links = re.findall(
        r"(?:https?://|www\.)\S+|\b(?:[a-z0-9-]+\.)+(?:com|org|net|edu|gov|io|co|uk|in|xyz|me|app|site)\b",
        text,
        re.I,
    )
    suspicious_hits = _count(PATTERNS["suspicious"], text)
    urgency_hits = _count(PATTERNS["urgency"], text)
    credential = _count(PATTERNS["credential"], text) > 0
    personal = _count(PATTERNS["personal"], text) > 0
    threat = _count(PATTERNS["threat"], text) > 0
    action = _count(PATTERNS["action"], text) > 0
    brand = next((b for b in BRANDS if re.search(re.escape(b), text, re.I)), None)

    row: dict[str, Any] = {
        "email_length": len(text),
        "word_count": len(text.split()),
        "reading_time_minutes": max(len(text.split()) / 200.0, 0.01),
        "character_entropy": 0.0,
        "readability_score": 50.0,
        "num_links": len(links),
        "num_special_characters": sum(not c.isalnum() and not c.isspace() for c in text),
        "num_uppercase_words": sum(w.isalpha() and w.isupper() and len(w) > 1 for w in text.split()),
        "suspicious_keyword_count": suspicious_hits,
        "urgency_score": min(10, urgency_hits * 2 + (2 if threat else 0)),
        "grammar_score": 50.0,
        "phishing_probability": round(float(spam_probability) * 100, 4),
        "domain_age_days": 365.0,
        "contains_link": "Yes" if links else "No",
        "contains_attachment": "No",
        "is_html_email": "Yes" if re.search(r"<(?:html|body|a|div)\b", text, re.I) else "No",
        "spf_status": "Pass",
        "dkim_status": "Pass",
        "dmarc_status": "Pass",
        "sender_reputation": "Unknown",
        "spoofed_domain": "No",
        "url_reputation": ("Malicious" if "malicious" in labels else "Suspicious" if "suspicious" in labels else "Safe"),
        "brand_impersonated": brand or "nan",
    }

    categorical = [
        "contains_link", "contains_attachment", "is_html_email",
        "spf_status", "dkim_status", "dmarc_status", "sender_reputation",
        "spoofed_domain", "url_reputation", "brand_impersonated",
    ]
    frame = pd.DataFrame([row])
    frame = pd.get_dummies(frame, columns=categorical, dummy_na=True)
    feature_names = list(getattr(model, "feature_names_in_", []))
    if not feature_names:
        return None
    frame = frame.reindex(columns=feature_names, fill_value=0)

    predicted = str(model.predict(frame)[0])
    probabilities = model.predict_proba(frame)[0] if hasattr(model, "predict_proba") else []
    classes = list(getattr(model, "classes_", []))
    probability = None
    if classes and len(probabilities) == len(classes):
        probability = float(probabilities[classes.index(predicted)])

    fallback = extract_risk_signals(message, spam_probability, url_labels)
    return {
        **fallback,
        "risk_label": predicted,
        "model_probability": probability,
        "model_source": "trained RF risk engine (7,996 engineered-label rows)",
        "metadata_note": "Live message analysis does not include sender/domain metadata; unavailable fields use neutral/default values.",
    }


def load_trained_model(path: str | Path = MODEL_PATH):
    """Load the local model, or download the compressed artifact once if needed."""
    path = Path(path)
    if path.exists():
        return joblib.load(path)

    if MODEL_GZ_PATH.exists():
        with gzip.open(MODEL_GZ_PATH, "rb") as fh:
            model_bytes = fh.read()
        path.write_bytes(model_bytes)
        return joblib.load(path)

    cache_path = Path("/tmp/risk_engine_rf_v4_9000.joblib")
    try:
        if not cache_path.exists():
            urllib.request.urlretrieve(MODEL_URL, "/tmp/risk_engine_rf_v4_9000.joblib.gz")
            with gzip.open("/tmp/risk_engine_rf_v4_9000.joblib.gz", "rb") as fh:
                cache_path.write_bytes(fh.read())
        return joblib.load(cache_path)
    except Exception:
        return None
