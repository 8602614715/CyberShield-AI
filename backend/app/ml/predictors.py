import re
from urllib.parse import urlparse

import pandas as pd
import tldextract

from app.ml import registry


def extract_url_candidate(text: str, supplied_url: str = "") -> str:
    if supplied_url and supplied_url.strip():
        return supplied_url.strip()

    match = re.search(r"(https?://[^\s]+|www\.[^\s]+)", text, re.IGNORECASE)
    if match:
        return match.group(0).strip()
    return ""


def build_phishing_features(url: str):
    registry.ensure_models_loaded()
    phishing_model = registry.phishing_model
    if phishing_model is None or not hasattr(phishing_model, "feature_names_in_"):
        return None

    candidate_url = url.strip()
    if not candidate_url:
        return None

    normalized_url = (
        candidate_url
        if re.match(r"^https?://", candidate_url, re.IGNORECASE)
        else f"http://{candidate_url}"
    )
    parsed = urlparse(normalized_url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    extracted = tldextract.extract(normalized_url)
    subdomain = extracted.subdomain or ""
    domain = extracted.domain or ""
    tld = extracted.suffix or ""

    is_ip = bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname))
    sensitive_words = [
        "login",
        "secure",
        "account",
        "verify",
        "bank",
        "update",
        "free",
        "urgent",
    ]
    brands = ["google", "amazon", "paypal", "apple", "bank"]

    features_dict = {
        "NumDots": normalized_url.count("."),
        "SubdomainLevel": subdomain.count(".") + (1 if subdomain else 0),
        "PathLevel": path.count("/"),
        "UrlLength": len(normalized_url),
        "NumDash": normalized_url.count("-"),
        "NumDashInHostname": hostname.count("-"),
        "AtSymbol": 1 if "@" in normalized_url else 0,
        "TildeSymbol": 1 if "~" in normalized_url else 0,
        "NumUnderscore": normalized_url.count("_"),
        "NumPercent": normalized_url.count("%"),
        "NumQueryComponents": len(query.split("&")) if query else 0,
        "NumAmpersand": query.count("&"),
        "NumHash": 1 if "#" in normalized_url else 0,
        "NumNumericChars": sum(char.isdigit() for char in normalized_url),
        "NoHttps": 1 if parsed.scheme != "https" else 0,
        "RandomString": 0,
        "IpAddress": 1 if is_ip else 0,
        "DomainInSubdomains": 1 if domain and subdomain and domain in subdomain else 0,
        "DomainInPaths": 1 if domain and path and domain in path else 0,
        "HttpsInHostname": 1 if "https" in hostname else 0,
        "HostnameLength": len(hostname),
        "PathLength": len(path),
        "QueryLength": len(query),
        "DoubleSlashInPath": 1 if "//" in path else 0,
        "NumSensitiveWords": sum(word in normalized_url.lower() for word in sensitive_words),
        "EmbeddedBrandName": 1 if any(brand in normalized_url.lower() for brand in brands) else 0,
        "PctExtHyperlinks": 0,
        "PctExtResourceUrls": 0,
        "ExtFormActionIntoLoginPage": 0,
        "ExtRequiredHtml": 0,
        "Redirect": 0,
        "RightClickDisabled": 0,
        "FakeLoginPage": 0,
        "PopupWindow": 0,
        "Iframe": 0,
        "StatusBarCustomization": 0,
        "WebsiteFavicon": 0,
        "UsingMailto": 0,
        "SFH": 0,
        "valid_url": 1,
        "entropy": 0,
        "num_fragments": 1 if fragment else 0,
        "num_special_chars": sum(not char.isalnum() for char in normalized_url),
        "entropy_domain": 0,
        "entropy_path": 0,
        "entropy_query": 0,
        "entropy_fragment": 0,
        "tld_length": len(tld) if tld else 0,
    }

    alias_map = {
        "PctExtResourceUrlsRT": "PctExtResourceUrls",
        "PopupWindow": "PopupWindow",
        "IframeOrFrame": "Iframe",
        "having_IPhaving_IP_Address ": "IpAddress",
        "URLURL_Length ": "UrlLength",
        "having_At_Symbol ": "AtSymbol",
        "double_slash_redirecting ": "DoubleSlashInPath",
        "Prefix_Suffix ": "NumDashInHostname",
        "having_Sub_Domain ": "SubdomainLevel",
        "Submitting_to_email ": "UsingMailto",
        "url_length": "UrlLength",
        "at_symbol": "AtSymbol",
        "sensitive_words_count": "NumSensitiveWords",
        "path_length": "PathLength",
        "nb_dots": "NumDots",
        "nb_hyphens": "NumDash",
        "nb_and": "NumAmpersand",
        "nb_underscore": "NumUnderscore",
    }

    features = {}
    for name in phishing_model.feature_names_in_:
        if name in features_dict:
            features[name] = features_dict[name]
        elif name in alias_map and alias_map[name] in features_dict:
            features[name] = features_dict[alias_map[name]]
        elif name == "isHttps":
            features[name] = 1 if parsed.scheme == "https" else 0
        elif name == "nb_or":
            features[name] = normalized_url.count("|")
        elif name == "nb_www":
            features[name] = normalized_url.lower().count("www")
        elif name == "nb_com":
            features[name] = normalized_url.lower().count(".com")
        elif name == "target":
            features[name] = 0
        else:
            features[name] = 0

    return pd.DataFrame(
        [[features[name] for name in phishing_model.feature_names_in_]],
        columns=phishing_model.feature_names_in_,
    )


def predict_with_trained_model(text: str):
    registry.ensure_models_loaded()
    trained_model = registry.trained_model
    text_vectorizer = registry.text_vectorizer
    if trained_model is not None and text_vectorizer is not None:
        try:
            features = text_vectorizer.transform([text])
            label = str(trained_model.predict(features)[0])
            confidence = 0.78

            if hasattr(trained_model, "predict_proba"):
                probabilities = trained_model.predict_proba(features)[0]
                confidence = float(max(probabilities))

            return {
                "label": label,
                "confidence": round(confidence, 3),
            }
        except Exception:
            return None
    return None


def predict_with_spam_model(text: str):
    registry.ensure_models_loaded()
    spam_model = registry.spam_model
    spam_tokenizer = registry.spam_tokenizer
    spam_device = registry.spam_device
    if spam_model is None or spam_tokenizer is None or spam_device is None:
        return None

    try:
        import torch

        inputs = spam_tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=128,
        )
        inputs = {key: value.to(spam_device) for key, value in inputs.items()}

        with torch.no_grad():
            outputs = spam_model(**inputs)

        probabilities = torch.softmax(outputs.logits, dim=1)
        predicted_index = torch.argmax(probabilities, dim=1).item()
        confidence = float(probabilities[0][predicted_index])
        labels = ["ham", "spam"]

        return {
            "label": labels[predicted_index],
            "confidence": round(confidence, 3),
        }
    except Exception:
        return None


def predict_with_phishing_model(text: str, supplied_url: str = ""):
    registry.ensure_models_loaded()
    phishing_model = registry.phishing_model
    if phishing_model is None:
        return None

    candidate_url = extract_url_candidate(text, supplied_url)
    if not candidate_url:
        return None

    try:
        feature_frame = build_phishing_features(candidate_url)
        if feature_frame is None:
            return None

        predicted_value = int(phishing_model.predict(feature_frame)[0])
        confidence = 0.75
        if hasattr(phishing_model, "predict_proba"):
            probabilities = phishing_model.predict_proba(feature_frame)[0]
            confidence = float(max(probabilities))

        return {
            "label": "phishing" if predicted_value == 1 else "safe",
            "confidence": round(confidence, 3),
            "url": candidate_url,
        }
    except Exception:
        return None
