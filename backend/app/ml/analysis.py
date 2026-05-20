import base64

import httpx

from app.config import VT_API_KEY
from app.ml.predictors import (
    predict_with_phishing_model,
    predict_with_spam_model,
    predict_with_trained_model,
)


def classify_with_rules(text: str, url: str = ""):
    phishing_prediction = predict_with_phishing_model(text, url)
    if phishing_prediction and phishing_prediction["label"] == "phishing":
        return {
            "type": "phishing",
            "confidence": phishing_prediction["confidence"],
            "model_used": "phishing_xgbclassifier",
            "explanation": (
                f"Predicted using the XGBClassifier phishing model on URL: "
                f"{phishing_prediction['url']}."
            ),
        }

    spam_prediction = predict_with_spam_model(text)
    if spam_prediction and spam_prediction["label"] == "spam":
        lowered_text = text.lower()
        predicted_type = (
            "phishing"
            if any(
                term in lowered_text
                for term in ["otp", "password", "verify", "account", "bank", "link"]
            )
            else "spam"
        )
        return {
            "type": predicted_type,
            "confidence": spam_prediction["confidence"],
            "model_used": "spam_roberta",
            "explanation": "Predicted using the imported RoBERTa spam model from the models folder.",
        }

    text_prediction = predict_with_trained_model(text)
    if text_prediction:
        return {
            "type": text_prediction["label"],
            "confidence": text_prediction["confidence"],
            "model_used": "trained_text_model",
            "explanation": "Predicted using the trained text model from the models folder.",
        }

    text = text.lower()
    matched_terms = []
    detected_type = "other"

    if any(x in text for x in ["otp", "password", "bank", "account", "phishing"]):
        matched_terms = [x for x in ["otp", "password", "bank", "account", "phishing"] if x in text]
        detected_type = "phishing"
    elif any(x in text for x in ["loan", "credit", "finance"]):
        matched_terms = [x for x in ["loan", "credit", "finance"] if x in text]
        detected_type = "finance"
    elif any(x in text for x in ["job", "offer", "recruitment"]):
        matched_terms = [x for x in ["job", "offer", "recruitment"] if x in text]
        detected_type = "employment"
    elif any(x in text for x in ["upi", "payment", "wallet"]):
        matched_terms = [x for x in ["upi", "payment", "wallet"] if x in text]
        detected_type = "payment fraud"

    confidence = 0.45 if detected_type == "other" else min(0.92, 0.58 + len(matched_terms) * 0.11)
    explanation = (
        "No strong scam keywords matched, so this was classified with the fallback rule set."
        if detected_type == "other"
        else f"Matched keywords: {', '.join(matched_terms)}."
    )

    return {
        "type": detected_type,
        "confidence": round(confidence, 3),
        "model_used": "rule_engine",
        "explanation": explanation,
    }


def compute_risk_score(classification: dict, text: str) -> int:
    score = 35
    lowered_text = text.lower()
    score += int(classification["confidence"] * 35)

    if classification["type"] == "phishing":
        score += 20
    elif classification["type"] in {"finance", "payment fraud"}:
        score += 16
    elif classification["type"] == "employment":
        score += 12

    urgency_terms = ["urgent", "immediately", "verify", "suspended", "blocked", "click", "win"]
    score += sum(5 for term in urgency_terms if term in lowered_text)

    return min(score, 100)


def check_virustotal(url: str):
    if not VT_API_KEY or not url:
        return None
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {
            "accept": "application/json",
            "x-apikey": VT_API_KEY,
        }
        with httpx.Client(timeout=4.0) as client:
            response = client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    except Exception:
        pass
    return None


def _risk_level_from_score(risk_score: int) -> str:
    if risk_score >= 80:
        return "critical"
    if risk_score >= 65:
        return "high"
    if risk_score >= 45:
        return "medium"
    return "low"


def build_ai_analysis(text: str, url: str = ""):
    classification = classify_with_rules(text, url)
    risk_score = compute_risk_score(classification, text)
    explanation = classification["explanation"]

    if url:
        vt_stats = check_virustotal(url)
        if vt_stats:
            malicious = vt_stats.get("malicious", 0)
            suspicious = vt_stats.get("suspicious", 0)
            if malicious > 0 or suspicious > 0:
                risk_score += (malicious * 15) + (suspicious * 5)
                classification["confidence"] = min(0.99, classification["confidence"] + 0.2)
                explanation += (
                    f" Threat Intel: VirusTotal flags this URL as malicious ({malicious} engines)."
                )
                if risk_score > 100:
                    risk_score = 100
                if classification["type"] != "phishing":
                    classification["type"] = "phishing"

    return {
        "predicted_type": classification["type"],
        "confidence": classification["confidence"],
        "risk_score": risk_score,
        "risk_level": _risk_level_from_score(risk_score),
        "model_used": classification["model_used"],
        "explanation": explanation,
    }


def build_url_analysis(url: str, context: str = ""):
    phishing_prediction = predict_with_phishing_model(context or url, url)
    if phishing_prediction:
        predicted_type = phishing_prediction["label"]
        confidence = phishing_prediction["confidence"]
        model_used = "phishing_xgbclassifier"
        explanation = (
            f"Predicted from URL features using the XGBClassifier model for "
            f"{phishing_prediction['url']}."
        )
    else:
        lowered = f"{url} {context}".lower()
        predicted_type = (
            "phishing"
            if any(
                term in lowered
                for term in ["login", "verify", "bank", "account", "otp", "secure", "update"]
            )
            else "safe"
        )
        confidence = 0.62 if predicted_type == "phishing" else 0.4
        model_used = "rule_engine"
        explanation = "Used fallback URL rules because the phishing model could not score this input."

    score = 30 + int(confidence * 35)
    if predicted_type == "phishing":
        score += 25
    if any(term in url.lower() for term in ["@", "-", "login", "verify", "secure"]):
        score += 10

    vt_stats = check_virustotal(url)
    if vt_stats:
        malicious = vt_stats.get("malicious", 0)
        suspicious = vt_stats.get("suspicious", 0)
        if malicious > 0 or suspicious > 0:
            score += (malicious * 15) + (suspicious * 5)
            confidence = min(0.99, confidence + 0.2)
            explanation += (
                f" Threat Intel: VirusTotal flags this URL as malicious ({malicious} engines)."
            )
            predicted_type = "phishing"

    risk_score = min(score, 100)

    return {
        "predicted_type": predicted_type,
        "confidence": confidence,
        "risk_score": risk_score,
        "risk_level": _risk_level_from_score(risk_score),
        "model_used": model_used,
        "explanation": explanation,
        "url": url,
    }
