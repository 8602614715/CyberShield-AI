import pickle
from pathlib import Path

from app.config import (
    COMBINED_MODEL_PATH,
    PHISHING_MODEL_PATH,
    SPAM_ROBERTA_DIR,
    TEXT_MODEL_PATH,
    TEXT_VECTORIZER_PATH,
    URL_MODEL_PATH,
)

_models_initialized = False
trained_model = None
text_vectorizer = None
url_model = None
combined_model = None
phishing_model = None
spam_tokenizer = None
spam_model = None
spam_device = None


def load_pickle_model(path: Path):
    if not path.exists():
        return None
    try:
        with open(path, "rb") as handle:
            return pickle.load(handle)
    except Exception:
        return None


def load_roberta_assets(model_dir: Path):
    required_files = [
        model_dir / "config.json",
        model_dir / "tokenizer.json",
        model_dir / "tokenizer_config.json",
        model_dir / "model.safetensors",
    ]
    if not all(path.exists() for path in required_files):
        return None, None, None

    try:
        import torch
        from transformers import RobertaForSequenceClassification, RobertaTokenizerFast
    except Exception:
        return None, None, None

    try:
        tokenizer = RobertaTokenizerFast.from_pretrained(model_dir)
        model = RobertaForSequenceClassification.from_pretrained(model_dir)
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model.to(device)
        model.eval()
        return tokenizer, model, device
    except Exception:
        return None, None, None


def ensure_models_loaded() -> None:
    """Load ML artifacts on first use so the web process can bind PORT quickly."""
    global _models_initialized
    global trained_model, text_vectorizer, url_model, combined_model, phishing_model
    global spam_tokenizer, spam_model, spam_device

    if _models_initialized:
        return

    trained_model = load_pickle_model(TEXT_MODEL_PATH)
    text_vectorizer = load_pickle_model(TEXT_VECTORIZER_PATH)
    url_model = load_pickle_model(URL_MODEL_PATH)
    combined_model = load_pickle_model(COMBINED_MODEL_PATH)
    phishing_model = load_pickle_model(PHISHING_MODEL_PATH)

    roberta = load_roberta_assets(SPAM_ROBERTA_DIR)
    if roberta[0] is not None:
        spam_tokenizer, spam_model, spam_device = roberta

    _models_initialized = True
