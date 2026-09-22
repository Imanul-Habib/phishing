"""
Combined Email Spam/Ham + URL Phishing Detector

Required files:
    mail_data.csv
    malicious_phish.csv

The message model uses TF-IDF + Logistic Regression.
The URL model uses the URL features from the supplied malicious-phish notebook
and a Random Forest classifier.

URL extraction:
- splits message on whitespace
- recognizes http://, https://, www., and common bare domains
"""

import re
import pandas as pd
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder


# -------------------- MESSAGE MODEL --------------------

raw_mail_data = pd.read_csv("mail_data.csv")
mail_data = raw_mail_data.where(pd.notnull(raw_mail_data), "")

mail_data.loc[mail_data["Category"] == "spam", "Category"] = 0
mail_data.loc[mail_data["Category"] == "ham", "Category"] = 1

X = mail_data["Message"].astype(str)
Y = mail_data["Category"].astype(int)

X_train, X_test, Y_train, Y_test = train_test_split(
    X, Y, test_size=0.2, random_state=3
)

feature_extraction = TfidfVectorizer(
    min_df=1, stop_words="english", lowercase=True
)
X_train_features = feature_extraction.fit_transform(X_train)

spam_model = LogisticRegression(max_iter=1000)
spam_model.fit(X_train_features, Y_train)


# -------------------- URL EXTRACTION --------------------

URL_START_RE = re.compile(r"^(?:https?://|www\\.)", re.IGNORECASE)
BARE_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9-]+\\.)+"
    r"(?:com|org|net|edu|gov|io|co|uk|in|biz|info|xyz|me|ly|de|fr|ca|au|app|site)"
    r"(?:[/:?#].*)?$",
    re.IGNORECASE,
)

def extract_urls_from_message(message):
    urls = []
    for token in str(message).split():
        candidate = token.strip(" \\t\\r\\n<>[]{}()\\\"'.,;:!?")

        if URL_START_RE.match(candidate) or BARE_DOMAIN_RE.match(candidate):
            if candidate.lower().startswith("www."):
                candidate = "https://" + candidate
            elif not re.match(r"^https?://", candidate, re.IGNORECASE):
                candidate = "https://" + candidate
            urls.append(candidate)

    return list(dict.fromkeys(urls))


# -------------------- URL FEATURES --------------------

def having_ip_address(url):
    match = re.search(
        r"(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
        r"([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
        r"([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
        r"([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|"
        r"(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}",
        str(url),
    )
    return int(bool(match))

def abnormal_url(url):
    hostname = urlparse(str(url)).hostname
    return int(bool(hostname and re.search(re.escape(hostname), str(url))))

def count_dot(url): return str(url).count(".")
def count_www(url): return str(url).lower().count("www")
def count_atrate(url): return str(url).count("@")
def no_of_dir(url): return urlparse(str(url)).path.count("/")
def no_of_embed(url): return urlparse(str(url)).path.count("//")

SHORTENERS = re.compile(
    r"bit\\.ly|goo\\.gl|shorte\\.st|go2l\\.ink|x\\.co|ow\\.ly|t\\.co|"
    r"tinyurl|tr\\.im|is\\.gd|cli\\.gs|tiny\\.cc|lnkd\\.in|cutt\\.us|"
    r"v\\.gd|u\\.to|j\\.mp",
    re.IGNORECASE,
)

def shortening_service(url): return int(bool(SHORTENERS.search(str(url))))
def count_https(url): return str(url).lower().count("https")
def count_http(url): return str(url).lower().count("http")
def count_per(url): return str(url).count("%")
def count_ques(url): return str(url).count("?")
def count_hyphen(url): return str(url).count("-")
def count_equal(url): return str(url).count("=")
def url_length(url): return len(str(url))
def hostname_length(url): return len(urlparse(str(url)).netloc)

SUSPICIOUS_WORDS = re.compile(
    r"paypal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr",
    re.IGNORECASE,
)

def suspicious_words(url): return int(bool(SUSPICIOUS_WORDS.search(str(url))))
def digit_count(url): return sum(ch.isnumeric() for ch in str(url))
def letter_count(url): return sum(ch.isalpha() for ch in str(url))

def fd_length(url):
    path = urlparse(str(url)).path
    try:
        return len(path.split("/")[1])
    except (IndexError, AttributeError):
        return 0

def tld_length_from_url(url):
    hostname = urlparse(str(url)).hostname or ""
    parts = hostname.split(".")
    return len(parts[-1]) if len(parts) > 1 else 0

URL_FEATURE_COLUMNS = [
    "use_of_ip", "abnormal_url", "count.", "count-www", "count@",
    "count_dir", "count_embed_domian", "short_url", "count-https",
    "count-http", "count%", "count?", "count-", "count=", "url_length",
    "hostname_length", "sus_url", "fd_length", "tld_length",
    "count-digits", "count-letters",
]

def url_to_features(url):
    return [
        having_ip_address(url), abnormal_url(url), count_dot(url),
        count_www(url), count_atrate(url), no_of_dir(url), no_of_embed(url),
        shortening_service(url), count_https(url), count_http(url),
        count_per(url), count_ques(url), count_hyphen(url), count_equal(url),
        url_length(url), hostname_length(url), suspicious_words(url),
        fd_length(url), tld_length_from_url(url), digit_count(url),
        letter_count(url),
    ]


# -------------------- URL MODEL --------------------

url_df = pd.read_csv("malicious_phish.csv")

url_features = pd.DataFrame(
    [url_to_features(u) for u in url_df["url"].astype(str)],
    columns=URL_FEATURE_COLUMNS,
)

label_encoder = LabelEncoder()
y_url = label_encoder.fit_transform(url_df["type"].astype(str))

X_url_train, X_url_test, y_url_train, y_url_test = train_test_split(
    url_features,
    y_url,
    test_size=0.2,
    stratify=y_url,
    random_state=5,
)

url_model = RandomForestClassifier(
    n_estimators=100,
    max_features="sqrt",
    random_state=5,
    n_jobs=-1,
)
url_model.fit(X_url_train, y_url_train)


# -------------------- COMBINED ANALYZER --------------------

def analyze_message(message):
    message = str(message)

    # Main spam/ham prediction
    vector = feature_extraction.transform([message])
    pred = int(spam_model.predict(vector)[0])
    proba = spam_model.predict_proba(vector)[0]

    # Extract and analyze URLs
    urls = extract_urls_from_message(message)
    url_results = []

    for url in urls:
        features = pd.DataFrame(
            [url_to_features(url)],
            columns=URL_FEATURE_COLUMNS,
        )
        code = int(url_model.predict(features)[0])
        label = label_encoder.inverse_transform([code])[0]

        url_results.append({
            "url": url,
            "classification": label,
        })

    return {
        "message_classification": "SPAM" if pred == 0 else "HAM",
        "spam_probability": float(proba[0]),
        "urls_found": url_results,
    }


if __name__ == "__main__":
    message = input("Paste a message/email: ")
    result = analyze_message(message)

    print("\\nMessage:", result["message_classification"])
    print("Spam probability:", f"{result['spam_probability']:.2%}")

    if not result["urls_found"]:
        print("URLs found: none")
    else:
        print("URLs:")
        for item in result["urls_found"]:
            print(" -", item["url"], "=>", item["classification"].upper())
