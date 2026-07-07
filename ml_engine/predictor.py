"""
ml_engine/predictor.py — ML Prediction Engine (v3).

Bug fixes from v2:
  1. Removed incorrect StandardScaler (RF doesn't need scaling)
  2. Use numpy array to avoid sklearn feature-name warnings
  3. Added Rule-Based Security Override for Presentation Mode.
"""
import logging
from pathlib import Path
from typing import Optional
import numpy as np

logger = logging.getLogger(__name__)

TRAINED_FEATURES = [
    "Init Bwd Win Bytes",
    "Fwd IAT Min",
    "Init Fwd Win Bytes",
    "Fwd Seg Size Min",
    "Packet Length Min",
    "Fwd Packet Length Min",
    "Bwd IAT Min",
    "PSH Flag Count",
    "Bwd Packet Length Min",
    "Protocol",
]

_model = None
_model_loaded = False


def _load_model():
    global _model, _model_loaded
    if _model_loaded:
        return _model
    try:
        import joblib
        from config import ML_MODEL_PATH, ML_ENABLED
        if not ML_ENABLED:
            _model_loaded = True
            return None
        if not Path(ML_MODEL_PATH).exists():
            logger.warning("ML model not found at %s", ML_MODEL_PATH)
            _model_loaded = True
            return None
        _model = joblib.load(ML_MODEL_PATH)
        logger.info("ML model loaded from %s", ML_MODEL_PATH)
    except Exception as e:
        logger.error("Failed to load ML model: %s", e)
    _model_loaded = True
    return _model


def _heuristic_fallback(features: dict) -> dict:
    """
    Rule-based fallback used ONLY when the trained model is unavailable
    (missing file, load error, or ML_ENABLED=false). This is explicitly a
    heuristic, not a model prediction — the caller is told so via
    `"ml_enabled": False` so it is never confused with a real ML verdict.
    """
    psh_flag = float(features.get("PSH Flag Count", 0.0))
    fwd_iat = float(features.get("Fwd IAT Min", 100.0))
    init_bwd = float(features.get("Init Bwd Win Bytes", 0.0))

    if psh_flag >= 5.0 or fwd_iat == 0.0:
        return {"prediction": "PortScan (heuristic)", "is_malicious": True, "ml_enabled": False}
    if init_bwd == 0.0 and psh_flag > 1.0:
        return {"prediction": "DDoS-Attack (heuristic)", "is_malicious": True, "ml_enabled": False}
    return {"prediction": "Benign (heuristic)", "is_malicious": False, "ml_enabled": False}


def predict_packet(features: dict) -> Optional[dict]:
    """
    Classify packet/flow features using the trained Random Forest model.
    Falls back to a clearly-labelled heuristic only if the model itself
    could not be loaded — the real model result is always used when available.
    """
    model = _load_model()
    if model is None:
        logger.warning("ML model unavailable — using heuristic fallback, not a real prediction.")
        return _heuristic_fallback(features)
    try:
        row = np.array([[float(features.get(f, 0.0)) for f in TRAINED_FEATURES]])
        prediction = str(model.predict(row)[0])
        is_malicious = prediction.lower() not in ("benign", "normal", "0")
        return {"prediction": prediction, "is_malicious": is_malicious, "ml_enabled": True}
    except Exception as e:
        logger.error("ML prediction error: %s", e)
        return _heuristic_fallback(features)