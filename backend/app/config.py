import os
from pathlib import Path

from dotenv import load_dotenv

BACKEND_ROOT = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BACKEND_ROOT.parent

load_dotenv(PROJECT_ROOT / ".env")
load_dotenv(BACKEND_ROOT / ".env")
ARTIFACTS_DIR = BACKEND_ROOT / "artifacts"
MODEL_DIR = ARTIFACTS_DIR / "models"

MONGODB_URI = os.environ.get("MONGODB_URI", "")
MONGODB_DB_NAME = os.environ.get("MONGODB_DB_NAME", "cybercrime")

JWT_SECRET_KEY = os.environ.get(
    "JWT_SECRET_KEY",
    "change-me-in-production-use-openssl-rand-hex-32",
)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

_cors_raw = os.environ.get(
    "CORS_ORIGINS",
    "http://127.0.0.1:5173,"
    "http://localhost:5173,"
    "http://127.0.0.1:4173,"
    "http://localhost:4173,"
    "https://cyber-shield-ai-teal.vercel.app,"
    "https://cyber-shield-jf2fh1rv6-8602614715s-projects.vercel.app",
)
CORS_ORIGINS = [origin.strip() for origin in _cors_raw.split(",") if origin.strip()]
CORS_ORIGIN_REGEX = os.environ.get(
    "CORS_ORIGIN_REGEX",
    r"https://cyber-shield-[a-z0-9-]+\.vercel\.app",
)

VT_API_KEY = os.environ.get("VT_API_KEY", "")

TEXT_MODEL_PATH = MODEL_DIR / "model.pkl"
TEXT_VECTORIZER_PATH = MODEL_DIR / "text_vectorizer.pkl"
URL_MODEL_PATH = MODEL_DIR / "url_model.pkl"
COMBINED_MODEL_PATH = MODEL_DIR / "combined_decision_tree.pkl"
PHISHING_MODEL_PATH = MODEL_DIR / "phishing_detector_model.pkl"
SPAM_ROBERTA_DIR = MODEL_DIR / "spam_roberta"
