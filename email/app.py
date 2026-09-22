import re
from io import BytesIO
from urllib.parse import urlparse

import pandas as pd
import streamlit as st
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

st.set_page_config(page_title="Spam + URL Risk Detector", page_icon="🛡️", layout="wide")

URL_START_RE = re.compile(r"^(?:https?://|www\.)", re.IGNORECASE)
BARE_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9-]+\.)+"
    r"(?:com|org|net|edu|gov|io|co|uk|in|biz|info|xyz|me|ly|de|fr|ca|au|app|site)"
    r"(?:[/:?#].*)?$", re.IGNORECASE,
)
SHORTENERS = re.compile(
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|"
    r"tinyurl|tr\.im|is\.gd|cli\.gs|tiny\.cc|lnkd\.in|cutt\.us|v\.gd|u\.to|j\.mp",
    re.IGNORECASE,
)
SUSPICIOUS_WORDS = re.compile(
    r"paypal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr",
    re.IGNORECASE,
)
URL_FEATURE_COLUMNS = [
    "use_of_ip", "abnormal_url", "count.", "count-www", "count@", "count_dir",
    "count_embed_domian", "short_url", "count-https", "count-http", "count%",
    "count?", "count-", "count=", "url_length", "hostname_length", "sus_url",
    "fd_length", "tld_length", "count-digits", "count-letters",
]

def extract_urls_from_message(message):
    urls = []
    for token in str(message).split():
        candidate = token.strip(" \t\r\n<>[]{}()\\\"'.,;:!?")
        if URL_START_RE.match(candidate) or BARE_DOMAIN_RE.match(candidate):
            if candidate.lower().startswith("www."):
                candidate = "https://" + candidate
            elif not re.match(r"^https?://", candidate, re.IGNORECASE):
                candidate = "https://" + candidate
            urls.append(candidate)
    return list(dict.fromkeys(urls))

def having_ip_address(url):
    hostname = urlparse(str(url)).hostname or ""
    return int(bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", hostname)))

def abnormal_url(url):
    hostname = urlparse(str(url)).hostname
    return int(bool(hostname and re.search(re.escape(hostname), str(url))))

def count_dot(url): return str(url).count(".")
def count_www(url): return str(url).lower().count("www")
def count_atrate(url): return str(url).count("@")
def no_of_dir(url): return urlparse(str(url)).path.count("/")
def no_of_embed(url): return urlparse(str(url)).path.count("//")
def shortening_service(url): return int(bool(SHORTENERS.search(str(url))))
def count_https(url): return str(url).lower().count("https")
def count_http(url): return str(url).lower().count("http")
def count_per(url): return str(url).count("%")
def count_ques(url): return str(url).count("?")
def count_hyphen(url): return str(url).count("-")
def count_equal(url): return str(url).count("=")
def url_length(url): return len(str(url))
def hostname_length(url): return len(urlparse(str(url)).netloc)
def suspicious_words(url): return int(bool(SUSPICIOUS_WORDS.search(str(url))))
def digit_count(url): return sum(ch.isnumeric() for ch in str(url))
def letter_count(url): return sum(ch.isalpha() for ch in str(url))

def fd_length(url):
    parts = urlparse(str(url)).path.split("/")
    return len(parts[1]) if len(parts) > 1 else 0

def tld_length_from_url(url):
    parts = (urlparse(str(url)).hostname or "").split(".")
    return len(parts[-1]) if len(parts) > 1 else 0

def url_to_features(url):
    return [
        having_ip_address(url), abnormal_url(url), count_dot(url), count_www(url),
        count_atrate(url), no_of_dir(url), no_of_embed(url), shortening_service(url),
        count_https(url), count_http(url), count_per(url), count_ques(url),
        count_hyphen(url), count_equal(url), url_length(url), hostname_length(url),
        suspicious_words(url), fd_length(url), tld_length_from_url(url),
        digit_count(url), letter_count(url),
    ]

@st.cache_resource(show_spinner=False)
def train_message_model(data_bytes):
    data = pd.read_csv(BytesIO(data_bytes))
    required = {"Category", "Message"}
    if not required.issubset(data.columns):
        raise ValueError("mail_data.csv must contain Category and Message columns.")
    data = data[["Category", "Message"]].copy()
    data["Category"] = data["Category"].astype(str).str.lower().str.strip()
    data["Message"] = data["Message"].fillna("").astype(str)
    mapping = {"spam": 0, "ham": 1}
    unknown = set(data["Category"]) - set(mapping)
    if unknown:
        raise ValueError(f"Unexpected Category values: {sorted(unknown)}")
    X_train, X_test, y_train, y_test = train_test_split(
        data["Message"], data["Category"].map(mapping).astype(int),
        test_size=0.2, random_state=3, stratify=data["Category"].map(mapping),
    )
    vectorizer = TfidfVectorizer(min_df=1, stop_words="english", lowercase=True)
    X_train_features = vectorizer.fit_transform(X_train)
    X_test_features = vectorizer.transform(X_test)
    model = LogisticRegression(max_iter=1000)
    model.fit(X_train_features, y_train)
    predictions = model.predict(X_test_features)
    return {
        "model": model, "vectorizer": vectorizer,
        "accuracy": accuracy_score(y_test, predictions),
        "report": classification_report(y_test, predictions, target_names=["spam", "ham"],
                                        output_dict=True, zero_division=0),
        "confusion": confusion_matrix(y_test, predictions),
        "rows": len(data),
    }

@st.cache_resource(show_spinner=False)
def train_url_model(data_bytes):
    data = pd.read_csv(BytesIO(data_bytes))
    required = {"url", "type"}
    if not required.issubset(data.columns):
        raise ValueError("malicious_phish.csv must contain url and type columns.")
    data = data[["url", "type"]].dropna().copy()
    data["url"] = data["url"].astype(str)
    data["type"] = data["type"].astype(str)
    features = pd.DataFrame([url_to_features(u) for u in data["url"]],
                            columns=URL_FEATURE_COLUMNS)
    encoder = LabelEncoder()
    y = encoder.fit_transform(data["type"])
    X_train, X_test, y_train, y_test = train_test_split(
        features, y, test_size=0.2, stratify=y, random_state=5
    )
    model = RandomForestClassifier(n_estimators=100, max_features="sqrt",
                                   random_state=5, n_jobs=-1)
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)
    return {
        "model": model, "encoder": encoder,
        "accuracy": accuracy_score(y_test, predictions),
        "report": classification_report(y_test, predictions,
                                        target_names=encoder.classes_,
                                        output_dict=True, zero_division=0),
        "rows": len(data),
    }

def top_message_contributions(message, vectorizer, model, top_n=8):
    vector = vectorizer.transform([message])
    names = vectorizer.get_feature_names_out()
    values = vector.toarray()[0]
    contributions = values * model.coef_[0]
    nonzero = contributions.nonzero()[0]
    spam = sorted([(names[i], float(contributions[i])) for i in nonzero if contributions[i] > 0],
                  key=lambda x: x[1], reverse=True)[:top_n]
    ham = sorted([(names[i], float(contributions[i])) for i in nonzero if contributions[i] < 0],
                 key=lambda x: x[1])[:top_n]
    return spam, ham

st.title("🛡️ Spam + URL Risk Detector")
st.caption("TF-IDF + Logistic Regression for message classification, plus a separate URL-feature + Random Forest classifier.")

with st.sidebar:
    st.header("Load datasets")
    mail_upload = st.file_uploader("mail_data.csv", type=["csv"],
                                   help="CSV with Category and Message columns.")
    url_upload = st.file_uploader("malicious_phish.csv", type=["csv"],
                                  help="CSV with url and type columns.")
    if mail_upload is None or url_upload is None:
        st.info("Upload both CSV files to train the models.")
        st.stop()
    mail_bytes = mail_upload.getvalue()
    url_bytes = url_upload.getvalue()

try:
    with st.spinner("Training message model..."):
        message_bundle = train_message_model(mail_bytes)
    with st.spinner("Training URL model..."):
        url_bundle = train_url_model(url_bytes)
except Exception as exc:
    st.error(f"Could not train the models: {exc}")
    st.stop()

tab_detector, tab_metrics, tab_about = st.tabs(["Detector", "Model metrics", "About"])

with tab_detector:
    st.subheader("Analyze a message")
    message = st.text_area(
        "Paste an email/SMS message",
        value="Congratulations! You have won a free prize. Click https://example.com/login now.",
        height=180,
    )

    if st.button("Analyze message", type="primary", use_container_width=True):
        vector = message_bundle["vectorizer"].transform([message])
        prediction = int(message_bundle["model"].predict(vector)[0])
        probabilities = message_bundle["model"].predict_proba(vector)[0]
        spam_probability = float(probabilities[0])
        classification = "SPAM" if prediction == 0 else "HAM"

        c1, c2 = st.columns(2)
        c1.metric("Message classification", classification)
        c2.metric("Spam probability", f"{spam_probability:.2%}")
        st.progress(spam_probability)

        spam_terms, ham_terms = top_message_contributions(
            message, message_bundle["vectorizer"], message_bundle["model"]
        )
        st.markdown("### Why did the message model lean this way?")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Spam-leaning terms**")
            st.dataframe(pd.DataFrame(spam_terms, columns=["term", "contribution"]),
                         hide_index=True, use_container_width=True)
        with c2:
            st.markdown("**Ham-leaning terms**")
            st.dataframe(pd.DataFrame(ham_terms, columns=["term", "contribution"]),
                         hide_index=True, use_container_width=True)

        st.markdown("### URL analysis")
        urls = extract_urls_from_message(message)
        if not urls:
            st.info("No URL was extracted from this message.")
        else:
            rows = []
            for url in urls:
                features = pd.DataFrame([url_to_features(url)], columns=URL_FEATURE_COLUMNS)
                code = int(url_bundle["model"].predict(features)[0])
                label = url_bundle["encoder"].inverse_transform([code])[0]
                rows.append({"URL": url, "URL model classification": str(label)})
            st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
        st.warning("URL results are model outputs from the supplied dataset, not a live reputation lookup or a definitive phishing verdict.")

with tab_metrics:
    st.subheader("Message model")
    c1, c2 = st.columns(2)
    c1.metric("Test accuracy", f"{message_bundle['accuracy']:.2%}")
    c2.metric("Dataset rows", f"{message_bundle['rows']:,}")
    st.dataframe(pd.DataFrame(message_bundle["report"]).T, use_container_width=True)

    st.subheader("URL model")
    c1, c2 = st.columns(2)
    c1.metric("Test accuracy", f"{url_bundle['accuracy']:.2%}")
    c2.metric("Dataset rows", f"{url_bundle['rows']:,}")
    st.dataframe(pd.DataFrame(url_bundle["report"]).T, use_container_width=True)

with tab_about:
    st.markdown(
        """
### Architecture

**Message classifier:** Message → TF-IDF → Logistic Regression → SPAM/HAM + probability.

**URL classifier:** Message → URL extraction → engineered URL features → Random Forest → URL class.

The two predictions are deliberately kept separate. The available mail dataset contains message content and Category, not sender metadata, subject, attachments, or domain reputation fields, so those fields are not invented here.

This is an academic demonstration, not a production email-security system.
"""
    )
