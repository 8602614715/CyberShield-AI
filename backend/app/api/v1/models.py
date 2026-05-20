from fastapi import APIRouter

from app.config import MODEL_DIR
from app.ml import registry as ml_registry

router = APIRouter(tags=["models"])


@router.get("/model-status")
def model_status():
    return {
        "text_model_loaded": ml_registry.trained_model is not None,
        "text_vectorizer_loaded": ml_registry.text_vectorizer is not None,
        "url_model_loaded": ml_registry.url_model is not None,
        "combined_model_loaded": ml_registry.combined_model is not None,
        "phishing_model_loaded": ml_registry.phishing_model is not None,
        "spam_roberta_loaded": ml_registry.spam_model is not None
        and ml_registry.spam_tokenizer is not None,
        "using_trained_model": ml_registry.trained_model is not None
        and ml_registry.text_vectorizer is not None,
        "model_directory": str(MODEL_DIR),
    }
