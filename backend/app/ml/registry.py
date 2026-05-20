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

try:
    import torch
    from transformers import RobertaForSequenceClassification, RobertaTokenizerFast
except Exception:
    torch = None
    RobertaForSequenceClassification = None
    RobertaTokenizerFast = None


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
spam_device = (
    torch.device("cuda" if torch and torch.cuda.is_available() else "cpu") if torch else None
)
if spam_model is not None and spam_device is not None:
    spam_model.to(spam_device)
    spam_model.eval()
