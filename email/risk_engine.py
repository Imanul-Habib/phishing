"""Risk engine for phishing-email analysis.

The trained RF model can be loaded when the model artifact is available. The
fallback scorer implements the refined-v2 signal rubric used to create the
training labels, so the repository remains runnable without a binary model.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import joblib

MODEL_PATH = Path(__file__).resolve().parent / "risk_engine_rf_v4_9000.joblib"

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

def load_trained_model(path: str | Path = MODEL_PATH):
    """Load the trained RF artifact when it has been added to the repo."""
    path = Path(path)
    if not path.exists():
        return None
    return joblib.load(path)
