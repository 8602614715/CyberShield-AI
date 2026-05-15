from fastapi import FastAPI, HTTPException, Depends, Header, Query, BackgroundTasks
from pydantic import BaseModel, EmailStr, Field
from pymongo import MongoClient, ReturnDocument
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import base64
import httpx
import hashlib
import math
import os
import re
import pandas as pd

load_dotenv()

import spacy
import tldextract
from geopy.geocoders import Nominatim
import pickle
from pathlib import Path
from urllib.parse import urlparse
from bson import ObjectId
from jose import jwt, JWTError
from passlib.context import CryptContext

try:
    import torch
    from transformers import RobertaForSequenceClassification, RobertaTokenizerFast
except Exception:
    torch = None
    RobertaForSequenceClassification = None
    RobertaTokenizerFast = None

# -------- INIT --------
app = FastAPI()

nlp = spacy.load("en_core_web_sm")
geolocator = Nominatim(user_agent="cyberfraud_app", timeout=3)

# -------- CACHE --------
location_cache = {}

COMMON_CITIES = [
    "delhi", "mumbai", "bangalore", "chennai",
    "hyderabad", "pune", "indore", "bhopal",
    "kolkata", "jaipur", "lucknow"
]

# Approximate centers for distance ranking (km) from user geolocation
METRO_COORDS = {
    "delhi": (28.6139, 77.2090),
    "mumbai": (19.0760, 72.8777),
    "bangalore": (12.9716, 77.5946),
    "chennai": (13.0827, 80.2707),
    "hyderabad": (17.3850, 78.4867),
    "pune": (18.5204, 73.8567),
    "indore": (22.7196, 75.8577),
    "bhopal": (23.2599, 77.4126),
    "kolkata": (22.5726, 88.3639),
    "jaipur": (26.9124, 75.7873),
    "lucknow": (26.8467, 80.9462),
}


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * r * math.atan2(math.sqrt(a), math.sqrt(max(0.0, 1 - a)))

# -------- DB --------
# Set MONGODB_URI in the environment for production; fallback keeps local dev working.
MONGODB_URI = os.environ.get(
    "MONGODB_URI",
    "mongodb+srv://satyamckt56_db_user:sixmarch2005@cluster0.b7icvyv.mongodb.net/cybercrime?appName=Cluster0",
)
client = MongoClient(MONGODB_URI)
db = client["cybercrime"]
collection = db["reports"]
users = db["users"]


def ensure_indexes() -> None:
    """Create indexes idempotently for common queries (safe to call on every startup)."""
    try:
        collection.create_index([("created_at", -1)], name="reports_created_at_desc")
        collection.create_index([("location", 1)], name="reports_location_1")
        collection.create_index([("type", 1)], name="reports_type_1")
        collection.create_index([("created_by", 1)], name="reports_created_by_1")
        users.create_index([("email", 1)], name="users_email_unique", unique=True)
    except Exception:
        # Avoid crashing the app if Atlas permissions or duplicate emails block an index.
        pass


ensure_indexes()

# -------- MODEL FILES --------
MODEL_DIR = Path(__file__).resolve().parent / "models"
TEXT_MODEL_PATH = MODEL_DIR / "model.pkl"
TEXT_VECTORIZER_PATH = MODEL_DIR / "text_vectorizer.pkl"
URL_MODEL_PATH = MODEL_DIR / "url_model.pkl"
COMBINED_MODEL_PATH = MODEL_DIR / "combined_decision_tree.pkl"
PHISHING_MODEL_PATH = MODEL_DIR / "phishing_detector_model.pkl"
SPAM_ROBERTA_DIR = MODEL_DIR / "spam_roberta"


def load_pickle_model(path: Path):
    if not path.exists():
        return None
    try:
        with open(path, "rb") as f:
            return pickle.load(f)
    except Exception:
        return None


def load_roberta_assets(model_dir: Path):
    required_files = [
        model_dir / "config.json",
        model_dir / "tokenizer.json",
        model_dir / "tokenizer_config.json",
        model_dir / "model.safetensors",
    ]
    if (
        torch is None
        or RobertaForSequenceClassification is None
        or RobertaTokenizerFast is None
        or not all(path.exists() for path in required_files)
    ):
        return None, None

    try:
        tokenizer = RobertaTokenizerFast.from_pretrained(model_dir)
        model = RobertaForSequenceClassification.from_pretrained(model_dir)
        return tokenizer, model
    except Exception:
        return None, None


trained_model = load_pickle_model(TEXT_MODEL_PATH)
text_vectorizer = load_pickle_model(TEXT_VECTORIZER_PATH)
url_model = load_pickle_model(URL_MODEL_PATH)
combined_model = load_pickle_model(COMBINED_MODEL_PATH)
phishing_model = load_pickle_model(PHISHING_MODEL_PATH)
spam_tokenizer, spam_model = load_roberta_assets(SPAM_ROBERTA_DIR)
spam_device = torch.device("cuda" if torch and torch.cuda.is_available() else "cpu") if torch else None
if spam_model is not None and spam_device is not None:
    spam_model.to(spam_device)
    spam_model.eval()

# -------- CORS --------
# Wildcard origin is invalid with credentials in browsers; use explicit dev origins by default.
_cors_raw = os.environ.get(
    "CORS_ORIGINS",
    "http://127.0.0.1:5173,http://localhost:5173,http://127.0.0.1:4173,http://localhost:4173",
)
CORS_ORIGINS = [o.strip() for o in _cors_raw.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.environ.get(
    "JWT_SECRET_KEY",
    "a2fbb0ff25ce436c0b415c3ba6443a14e4f260593f69322883c80ee7a8be44d5",
)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
ALLOWED_ROLES = {"viewer", "analyst", "admin"}
CASE_STATUSES = {"new", "under_review", "confirmed_fraud", "false_positive", "closed"}
PHONE_PATTERN = re.compile(r"(?:\+91[-\s]?)?[6-9]\d{9}")
EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b")
UPI_PATTERN = re.compile(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b")
DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[A-Za-z]{2,}\b")

# -------- MODEL --------
class Report(BaseModel):
    title: str = Field(..., min_length=1, max_length=2000)
    location: str = Field(default="", max_length=200)
    url: str = Field(default="", max_length=2048)
    status: str = Field(default="new", max_length=64)
    analyst_notes: str = Field(default="", max_length=8000)


class UrlReport(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    context: str = Field(default="", max_length=8000)


class RegisterUser(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=256)
    role: str = Field(default="viewer", max_length=32)


class LoginUser(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=256)


class ReportUpdate(BaseModel):
    status: str = Field(..., min_length=1, max_length=64)
    analyst_notes: str = Field(default="", max_length=8000)

 # auth dashboard
def normalize_password(password: str) -> str:
    # Pre-hash to a fixed length so bcrypt won't fail on passwords over 72 bytes.
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def hash_password(password: str):
    return pwd_context.hash(normalize_password(password))

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(normalize_password(plain_password), hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    payload = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload.update({"exp": expire})
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.split(" ", 1)[1]

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        raw = payload.get("sub")
        if not raw:
            raise HTTPException(status_code=401, detail="Invalid token")
        email = str(raw).lower().strip()
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = users.find_one({"email": email}, {"_id": 0, "password_hash": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user

@app.post("/auth/register")
def create_user(user: RegisterUser):
    email = user.email.lower().strip()
    role = user.role.lower().strip() if user.role else "viewer"
    if role not in ALLOWED_ROLES:
        raise HTTPException(status_code=400, detail="Invalid role")
    existing = users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    users.insert_one({
        "name": user.name,
        "email": email,
        "password_hash": hash_password(user.password),
        "role": role,
        "created_at": datetime.now(timezone.utc),
    })


    return {"message": "user registered successfully"}

@app.post("/auth/login")
def login(user: LoginUser):
    email = user.email.lower().strip()
    db_user = users.find_one({"email": email})
    if not db_user or not verify_password(user.password, db_user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token({
        "sub": db_user["email"],
        "role": db_user.get("role", "viewer"),
        "name": db_user.get("name", ""),
    })

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "name": db_user.get("name", ""),
            "email": db_user["email"],
            "role": db_user.get("role", "viewer"),
        }
    }

@app.get("/auth/me")
def me(current_user=Depends(get_current_user)):
    return current_user
# -------- UTIL --------

def normalize_location(loc):
    return loc.lower().strip()

# FAST EXTRACTION
def fast_extract(text):
    text = text.lower()
    for city in COMMON_CITIES:
        if city in text:
            return city
    return None

# NLP FALLBACK
def extract_location(text):
    loc = fast_extract(text)
    if loc:
        return loc

    doc = nlp(text)
    for ent in doc.ents:
        if ent.label_ == "GPE":
            return ent.text.lower()

    return "unknown"

# DB CACHE
def get_existing_coords(location):
    existing = collection.find_one({"location": location})
    if existing and "lat" in existing:
        return (existing["lat"], existing["lng"])
    return None

# GEO + MEMORY CACHE
def get_coordinates(location):
    location = normalize_location(location)

    # memory cache
    if location in location_cache:
        return location_cache[location]

    # DB cache
    db_coords = get_existing_coords(location)
    if db_coords:
        location_cache[location] = db_coords
        return db_coords

    try:
        if location == "unknown":
            coords = (20.5937, 78.9629)
        else:
            geo = geolocator.geocode(location + ", India")
            if geo:
                coords = (geo.latitude, geo.longitude)
            else:
                coords = (20.5937, 78.9629)

        location_cache[location] = coords
        return coords

    except Exception:
        return (20.5937, 78.9629)

def predict_with_trained_model(text):
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
    if spam_model is None or spam_tokenizer is None or spam_device is None:
        return None

    try:
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


def extract_url_candidate(text: str, supplied_url: str = ""):
    if supplied_url and supplied_url.strip():
        return supplied_url.strip()

    match = re.search(r"(https?://[^\s]+|www\.[^\s]+)", text, re.IGNORECASE)
    if match:
        return match.group(0).strip()
    return ""


def build_phishing_features(url: str):
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
        "login", "secure", "account", "verify",
        "bank", "update", "free", "urgent",
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


def predict_with_phishing_model(text: str, supplied_url: str = ""):
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


def normalize_case_status(status: str) -> str:
    cleaned = (status or "new").strip().lower().replace(" ", "_")
    if cleaned not in CASE_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid case status")
    return cleaned


def unique_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        normalized = value.strip()
        lowered = normalized.lower()
        if normalized and lowered not in seen:
            seen.add(lowered)
            output.append(normalized)
    return output


def extract_entities(text: str, url: str = "", analyst_notes: str = "") -> dict:
    source = " ".join(part for part in [text, url, analyst_notes] if part).strip()
    lowered = source.lower()
    phones = unique_preserve_order([match.group(0).replace(" ", "").replace("-", "") for match in PHONE_PATTERN.finditer(source)])
    emails = unique_preserve_order([match.group(0).lower() for match in EMAIL_PATTERN.finditer(source)])
    upi_ids = unique_preserve_order([match.group(0).lower() for match in UPI_PATTERN.finditer(source)])
    urls = unique_preserve_order(re.findall(r"(https?://[^\s]+|www\.[^\s]+)", source, flags=re.IGNORECASE))
    domains = []
    for candidate in urls + re.findall(DOMAIN_PATTERN, source):
        extracted = tldextract.extract(candidate if candidate.startswith("http") else f"http://{candidate}")
        if extracted.domain and extracted.suffix:
            domains.append(f"{extracted.domain.lower()}.{extracted.suffix.lower()}")
    domains = unique_preserve_order(domains)

    keywords = []
    for keyword in ["otp", "password", "verify", "bank", "account", "loan", "upi", "wallet", "job", "gift", "click"]:
        if keyword in lowered:
            keywords.append(keyword)

    entity_summary = {
        "phones": phones,
        "emails": emails,
        "upi_ids": upi_ids,
        "urls": urls,
        "domains": domains,
        "keywords": unique_preserve_order(keywords),
    }
    flat_entities = [
        *[f"phone:{value.lower()}" for value in phones],
        *[f"email:{value.lower()}" for value in emails],
        *[f"upi:{value.lower()}" for value in upi_ids],
        *[f"url:{value.lower()}" for value in urls],
        *[f"domain:{value.lower()}" for value in domains],
        *[f"keyword:{value.lower()}" for value in entity_summary["keywords"]],
    ]

    return {
        "entity_summary": entity_summary,
        "entities_flat": unique_preserve_order(flat_entities),
    }


def fetch_related_reports(report_id: ObjectId, entities_flat: list[str], limit: int = 6) -> list[dict]:
    if not entities_flat:
        return []

    cursor = collection.find(
        {
            "_id": {"$ne": report_id},
            "entities_flat": {"$in": entities_flat},
        }
    ).sort("created_at", -1).limit(limit * 4)

    related_reports: list[dict] = []
    seen_ids: set[str] = set()
    for document in cursor:
        serialized = serialize_report(document, include_related=False)
        related_entities = document.get("entities_flat", [])
        shared = [value for value in related_entities if value in entities_flat][:5]
        serialized["shared_evidence"] = shared
        serialized["shared_evidence_count"] = len(shared)
        report_key = serialized["report_id"]
        if report_key not in seen_ids:
            seen_ids.add(report_key)
            related_reports.append(serialized)
        if len(related_reports) >= limit:
            break
    return related_reports


def serialize_report(document: dict, include_related: bool = True) -> dict:
    created_at = document.get("created_at")
    updated_at = document.get("updated_at")
    report_id = document.get("_id")
    entities = document.get("entity_summary", {})
    entities_flat = document.get("entities_flat", [])
    serialized = {
        "report_id": str(report_id),
        "title": document.get("title", ""),
        "url": document.get("url", ""),
        "location": document.get("location", ""),
        "lat": document.get("lat"),
        "lng": document.get("lng"),
        "type": document.get("type", "other"),
        "risk_score": document.get("risk_score"),
        "risk_level": document.get("risk_level"),
        "ai_confidence": document.get("ai_confidence"),
        "model_used": document.get("model_used"),
        "ai_explanation": document.get("ai_explanation"),
        "created_by": document.get("created_by", ""),
        "status": document.get("status", "new"),
        "analyst_notes": document.get("analyst_notes", ""),
        "updated_at": updated_at.isoformat() if isinstance(updated_at, datetime) else updated_at,
        "entity_summary": entities,
        "entities_flat": entities_flat,
    }
    if isinstance(created_at, datetime):
        serialized["created_at"] = created_at.isoformat()
    else:
        serialized["created_at"] = created_at
    if include_related and isinstance(report_id, ObjectId):
        serialized["related_reports"] = fetch_related_reports(report_id, entities_flat)
    return serialized


# -------- CLASSIFICATION --------
def classify_with_rules(text: str, url: str = ""):
    phishing_prediction = predict_with_phishing_model(text, url)
    if phishing_prediction and phishing_prediction["label"] == "phishing":
        return {
            "type": "phishing",
            "confidence": phishing_prediction["confidence"],
            "model_used": "phishing_xgbclassifier",
            "explanation": f"Predicted using the XGBClassifier phishing model on URL: {phishing_prediction['url']}.",
        }

    spam_prediction = predict_with_spam_model(text)
    if spam_prediction and spam_prediction["label"] == "spam":
        lowered_text = text.lower()
        predicted_type = "phishing" if any(
            term in lowered_text for term in ["otp", "password", "verify", "account", "bank", "link"]
        ) else "spam"
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


def compute_risk_score(classification: dict, text: str):
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
    vt_key = os.environ.get("VT_API_KEY")
    if not vt_key or not url:
        return None
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {
            "accept": "application/json",
            "x-apikey": vt_key
        }
        with httpx.Client(timeout=4.0) as client:
            response = client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
            if response.status_code == 200:
                data = response.json()
                return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    except Exception:
        pass
    return None

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
                explanation += f" Threat Intel: VirusTotal flags this URL as malicious ({malicious} engines)."
                if risk_score > 100:
                    risk_score = 100
                if classification["type"] != "phishing":
                    classification["type"] = "phishing"

    if risk_score >= 80:
        risk_level = "critical"
    elif risk_score >= 65:
        risk_level = "high"
    elif risk_score >= 45:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "predicted_type": classification["type"],
        "confidence": classification["confidence"],
        "risk_score": risk_score,
        "risk_level": risk_level,
        "model_used": classification["model_used"],
        "explanation": explanation,
    }


def build_url_analysis(url: str, context: str = ""):
    phishing_prediction = predict_with_phishing_model(context or url, url)
    if phishing_prediction:
        predicted_type = phishing_prediction["label"]
        confidence = phishing_prediction["confidence"]
        model_used = "phishing_xgbclassifier"
        explanation = f"Predicted from URL features using the XGBClassifier model for {phishing_prediction['url']}."
    else:
        lowered = f"{url} {context}".lower()
        predicted_type = "phishing" if any(
            term in lowered for term in ["login", "verify", "bank", "account", "otp", "secure", "update"]
        ) else "safe"
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
            explanation += f" Threat Intel: VirusTotal flags this URL as malicious ({malicious} engines)."
            predicted_type = "phishing"

    risk_score = min(score, 100)

    if risk_score >= 80:
        risk_level = "critical"
    elif risk_score >= 65:
        risk_level = "high"
    elif risk_score >= 45:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "predicted_type": predicted_type,
        "confidence": confidence,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "model_used": model_used,
        "explanation": explanation,
        "url": url,
    }

# -------- ROUTES --------

@app.get("/")
def home():
    return {"message": "Cybercrime Intelligence API Running"}


@app.get("/health")
def health():
    """Readiness: verifies MongoDB connectivity. Use for deploy probes."""
    try:
        client.admin.command("ping")
    except Exception as exc:
        raise HTTPException(status_code=503, detail="MongoDB unreachable") from exc
    return {
        "status": "ok",
        "mongodb": True,
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "models_dir_exists": MODEL_DIR.is_dir(),
    }

def build_reverse_place_names(lat: float, lon: float) -> list[str]:
    try:
        loc = geolocator.reverse(f"{lat}, {lon}", language="en", timeout=8, addressdetails=True)
        if not loc or not getattr(loc, "raw", None):
            return []
        addr = (loc.raw or {}).get("address") or {}
        ordered_keys = (
            "city",
            "town",
            "village",
            "suburb",
            "neighbourhood",
            "county",
            "state_district",
            "state",
        )
        out: list[str] = []
        seen: set[str] = set()
        for key in ordered_keys:
            val = addr.get(key)
            if isinstance(val, str) and val.strip():
                v = val.strip()
                low = v.lower()
                if low not in seen:
                    seen.add(low)
                    out.append(v)
        return out
    except Exception:
        return []


@app.get("/geo/suggestions")
def geo_suggestions(
    lat: float = Query(..., ge=-90, le=90, description="WGS84 latitude"),
    lon: float = Query(..., ge=-180, le=180, description="WGS84 longitude"),
    current_user=Depends(get_current_user),
):
    """
    Return place names near the user's coordinates for incident forms:
    reverse-geocoded labels (when Nominatim succeeds) plus major metros sorted by distance.
    """
    reverse_names = build_reverse_place_names(lat, lon)
    metro_ranked = sorted(
        METRO_COORDS.items(),
        key=lambda item: haversine_km(lat, lon, item[1][0], item[1][1]),
    )
    metro_labels = [name.replace("_", " ").title() for name, _ in metro_ranked[:6]]

    combined: list[str] = []
    seen_lower: set[str] = set()
    for name in reverse_names + metro_labels:
        low = name.lower()
        if low not in seen_lower:
            seen_lower.add(low)
            combined.append(name)

    return {
        "suggestions": combined[:14],
        "reverse_geocoded": len(reverse_names) > 0,
    }


@app.get("/model-status")
def model_status():
    return {
        "text_model_loaded": trained_model is not None,
        "text_vectorizer_loaded": text_vectorizer is not None,
        "url_model_loaded": url_model is not None,
        "combined_model_loaded": combined_model is not None,
        "phishing_model_loaded": phishing_model is not None,
        "spam_roberta_loaded": spam_model is not None and spam_tokenizer is not None,
        "using_trained_model": trained_model is not None and text_vectorizer is not None,
        "model_directory": str(MODEL_DIR),
    }


@app.post("/ai/analyze")
def ai_analyze(report: Report, current_user=Depends(get_current_user)):
    location = normalize_location(report.location) if report.location else extract_location(report.title)
    analysis = build_ai_analysis(report.title, report.url)
    entities = extract_entities(report.title, report.url, report.analyst_notes)

    return {
        "title": report.title,
        "url": report.url,
        "location": location,
        "analysis": analysis,
        "entities": entities["entity_summary"],
        "requested_by": current_user["email"],
    }


@app.post("/ai/analyze-url")
def ai_analyze_url(report: UrlReport, current_user=Depends(get_current_user)):
    analysis = build_url_analysis(report.url, report.context)
    entities = extract_entities(report.context, report.url, "")

    return {
        "url": report.url,
        "context": report.context,
        "analysis": analysis,
        "entities": entities["entity_summary"],
        "requested_by": current_user["email"],
    }

import logging
logging.basicConfig(level=logging.INFO)
alert_logger = logging.getLogger("cyberfraud.alerts")

def send_alert_notification(report_id: str, risk_level: str, details: str):
    if risk_level == "critical":
        alert_logger.warning(f"🚨 CRITICAL ALERT TRIGGERED for Report {report_id} 🚨\nDetails: {details}")

# ADD REPORT
@app.post("/report")
def add_report(report: Report, background_tasks: BackgroundTasks, current_user=Depends(get_current_user)):
    title = report.title
    status = normalize_case_status(report.status)
    analyst_notes = report.analyst_notes.strip()
    entity_bundle = extract_entities(title, report.url, analyst_notes)

    location = normalize_location(report.location)

    if location == "" or location == "unknown":
        location = extract_location(title)

    lat, lng = get_coordinates(location)
    analysis = build_ai_analysis(title, report.url)

    data = {
        "title": title,
        "url": report.url,
        "location": location,
        "lat": lat,
        "lng": lng,
        "type": analysis["predicted_type"],
        "ai_confidence": analysis["confidence"],
        "risk_score": analysis["risk_score"],
        "risk_level": analysis["risk_level"],
        "model_used": analysis["model_used"],
        "ai_explanation": analysis["explanation"],
        "created_at": datetime.now(timezone.utc),
        "created_by": current_user["email"],
        "status": status,
        "analyst_notes": analyst_notes,
        "entity_summary": entity_bundle["entity_summary"],
        "entities_flat": entity_bundle["entities_flat"],
    }

    inserted = collection.insert_one(data)

    if analysis["risk_level"] == "critical":
        background_tasks.add_task(
            send_alert_notification,
            str(inserted.inserted_id),
            "critical",
            f"Type: {analysis['predicted_type']} - Confidence: {analysis['confidence']} - Location: {location}"
        )

    return {
        "report_id": str(inserted.inserted_id),
        "message": "Report added",
        "type": analysis["predicted_type"],
        "risk_score": analysis["risk_score"],
        "risk_level": analysis["risk_level"],
        "confidence": analysis["confidence"],
        "location": location,
        "lat": lat,
        "lng": lng,
        "status": status,
        "analyst_notes": analyst_notes,
        "entities": entity_bundle["entity_summary"],
    }

# ALL REPORTS
@app.get("/reports")
def get_reports(current_user=Depends(get_current_user)):
    documents = collection.find({}).sort("created_at", -1)
    return [serialize_report(document) for document in documents]


@app.patch("/reports/{report_id}")
def update_report(report_id: str, update: ReportUpdate, current_user=Depends(get_current_user)):
    status = normalize_case_status(update.status)
    analyst_notes = update.analyst_notes.strip()

    if current_user.get("role", "viewer") not in {"analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Only analysts or admins can update cases")

    try:
        object_id = ObjectId(report_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid report id") from exc

    existing_report = collection.find_one({"_id": object_id})
    if not existing_report:
        raise HTTPException(status_code=404, detail="Report not found")

    entity_bundle = extract_entities(
        existing_report.get("title", ""),
        existing_report.get("url", ""),
        analyst_notes,
    )

    result = collection.find_one_and_update(
        {"_id": object_id},
        {
            "$set": {
                "status": status,
                "analyst_notes": analyst_notes,
                "entity_summary": entity_bundle["entity_summary"],
                "entities_flat": entity_bundle["entities_flat"],
                "updated_at": datetime.now(timezone.utc),
                "updated_by": current_user["email"],
            }
        },
        return_document=ReturnDocument.AFTER,
    )

    return serialize_report(result)


@app.get("/reports/{report_id}/links")
def report_links(report_id: str, current_user=Depends(get_current_user)):
    try:
        object_id = ObjectId(report_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid report id") from exc

    document = collection.find_one({"_id": object_id})
    if not document:
        raise HTTPException(status_code=404, detail="Report not found")

    entities_flat = document.get("entities_flat", [])
    related_reports = fetch_related_reports(object_id, entities_flat, limit=10)
    return {
        "report_id": report_id,
        "entity_summary": document.get("entity_summary", {}),
        "related_reports": related_reports,
    }

# MAP DATA
@app.get("/reports/map")
def map_reports(current_user=Depends(get_current_user)):
    return list(collection.find(
        {},
        {
            "_id": 0,
            "title": 1,
            "location": 1,
            "lat": 1,
            "lng": 1,
            "type": 1,
            "risk_score": 1,
            "risk_level": 1,
        }
    ))

# FILTER
@app.get("/reports/location/{loc}")
def reports_by_location(loc: str, current_user=Depends(get_current_user)):
    return list(collection.find(
        {"location": normalize_location(loc)},
        {"_id": 0}
    ))

# STATS
@app.get("/stats/type")
def stats_by_type(current_user=Depends(get_current_user)):
    pipeline = [
        {"$group": {"_id": "$type", "count": {"$sum": 1}}}
    ]
    return list(collection.aggregate(pipeline))

# ALERTS
@app.get("/alerts")
def alerts(current_user=Depends(get_current_user)):
    pipeline = [
        {"$group": {"_id": "$location", "count": {"$sum": 1}}},
        {"$match": {"count": {"$gte": 3}}}
    ]
    return list(collection.aggregate(pipeline))

# AI RISK TREND PREDICTION
@app.get("/api/predict/risk_trend")
def predict_risk_trend(current_user=Depends(get_current_user)):
    seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
    
    pipeline = [
        {"$match": {"created_at": {"$gte": seven_days_ago}, "risk_level": {"$in": ["critical", "high"]}}},
        {"$group": {"_id": "$location", "recent_count": {"$sum": 1}}},
        {"$sort": {"recent_count": -1}},
        {"$limit": 5}
    ]
    hotspots = list(collection.aggregate(pipeline))
    
    predictions = []
    for hs in hotspots:
        loc = hs["_id"]
        count = hs["recent_count"]
        predicted_increase = count * 1.5
        predictions.append({
            "location": loc,
            "recent_incidents": count,
            "predicted_next_week": round(predicted_increase, 1),
            "trend": "upward" if count > 2 else "stable"
        })
        
    return {
        "status": "success",
        "predicted_hotspots": predictions,
        "message": "Predictions for locations at risk of increased fraudulent activities based on recent high/critical reports."
    }
