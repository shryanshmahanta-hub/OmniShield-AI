"""Optional local Hugging Face prompt-injection classifier.

The model is downloaded only when ENABLE_PROMPT_ML=true and the first scan is
performed. Set PROMPT_ML_MODEL to a local model directory to avoid runtime
network access. The optional dependencies are in requirements-ml.txt.
"""
from __future__ import annotations

import logging
import math
import threading
from typing import Any, Dict, Optional

from app.config import get_settings

logger = logging.getLogger(__name__)


def normalize_prompt_label_map(raw_labels: dict[int, str], configured_labels: list[str]) -> dict[int, str]:
    """Map model output labels to SAFE/INJECTION only when semantics are known."""
    safe_aliases = {"SAFE", "BENIGN", "LEGITIMATE", "NORMAL", "HARMLESS"}
    injection_aliases = {"INJECTION", "PROMPT INJECTION", "INJECTION DETECTED", "MALICIOUS", "UNSAFE"}
    normalized: dict[int, str] = {}
    for index, value in raw_labels.items():
        label = " ".join(value.lower().replace("_", " ").replace("-", " ").split()).upper()
        if label in safe_aliases:
            normalized[index] = "SAFE"
        elif label in injection_aliases:
            normalized[index] = "INJECTION"
    if len(raw_labels) == 2 and set(normalized.values()) == {"SAFE", "INJECTION"}:
        return normalized

    generic_values = {f"LABEL_{i}" for i in range(len(raw_labels))} | {str(i) for i in range(len(raw_labels))}
    generic_labels = all(value.upper() in generic_values for value in raw_labels.values())
    configured = [x.upper() for x in configured_labels]
    if (generic_labels and len(raw_labels) == 2 and len(configured) == 2
            and set(configured) == {"SAFE", "INJECTION"}):
        # Explicit mapping is required for generic model labels.
        return {i: configured[i] for i in sorted(raw_labels)}
    raise ValueError("Model label mapping must explicitly define SAFE and INJECTION")


class PromptInjectionClassifier:
    """Lazy-loaded CPU-compatible text classifier with explicit label mapping."""

    def __init__(self, model_id: Optional[str] = None) -> None:
        settings = get_settings()
        self.model_id = model_id or settings.prompt_ml_model
        configured = getattr(settings, "prompt_ml_labels", "SAFE,INJECTION")
        self.configured_labels = [x.strip().upper() for x in configured.split(",") if x.strip()]
        self._lock = threading.Lock()
        self._tokenizer: Any = None
        self._model: Any = None
        self._torch: Any = None
        self._load_error = False

    def _load(self) -> bool:
        if self._model is not None and self._tokenizer is not None:
            return True
        if self._load_error:
            return False
        with self._lock:
            if self._model is not None and self._tokenizer is not None:
                return True
            if self._load_error:
                return False
            try:
                import torch
                from transformers import AutoModelForSequenceClassification, AutoTokenizer
                local_only = get_settings().prompt_ml_local_files_only
                tokenizer = AutoTokenizer.from_pretrained(self.model_id, local_files_only=local_only)
                model = AutoModelForSequenceClassification.from_pretrained(
                    self.model_id, local_files_only=local_only, use_safetensors=True
                )
                model.to("cpu")
                model.eval()
                # Normalize known semantic labels, or use the explicit operator mapping
                # for generic LABEL_0/LABEL_1. The bundled ProtectAI default documents
                # class 0=benign and class 1=injection; do not guess for other models.
                raw_labels = {int(k): str(v).strip().upper() for k, v in model.config.id2label.items()}
                labels = normalize_prompt_label_map(raw_labels, self.configured_labels)
                self._tokenizer, self._model, self._torch = tokenizer, model, torch
                self._labels = labels
                return True
            except Exception as exc:
                self._load_error = True
                # Avoid exception text because some libraries may include paths or URLs.
                logger.warning("Prompt-injection model could not be loaded (%s)", type(exc).__name__)
                return False

    def classify(self, text: str) -> Dict[str, Any]:
        """Return actual model prediction or a clear unavailable status."""
        if not self._load():
            return {"enabled": True, "available": False, "model": self.model_id,
                    "prediction": None, "confidence": None, "status": "load_failed"}
        try:
            encoded = self._tokenizer(text, truncation=True, max_length=512, return_tensors="pt")
            with self._torch.inference_mode():
                logits = self._model(**encoded).logits
                probabilities = self._torch.softmax(logits, dim=-1)[0].tolist()
            if len(probabilities) != len(self._labels):
                raise ValueError("Unexpected model output dimensions")
            safe_idx = next(i for i, label in self._labels.items() if label == "SAFE")
            injection_idx = next(i for i, label in self._labels.items() if label == "INJECTION")
            if max(safe_idx, injection_idx) >= len(probabilities):
                raise ValueError("Model label index out of bounds")
            safe_score = float(probabilities[safe_idx])
            injection_score = float(probabilities[injection_idx])
            if not all(math.isfinite(v) and 0.0 <= v <= 1.0 for v in (safe_score, injection_score)):
                raise ValueError("Invalid model confidence")
            prediction = "INJECTION" if injection_score > safe_score else "SAFE"
            return {"enabled": True, "available": True, "model": self.model_id,
                    "prediction": prediction,
                    "confidence": round(injection_score if prediction == "INJECTION" else safe_score, 6),
                    "status": "success"}
        except Exception as exc:
            logger.warning("Prompt-injection inference failed (%s)", type(exc).__name__)
            return {"enabled": True, "available": False, "model": self.model_id,
                    "prediction": None, "confidence": None, "status": "inference_failed"}


_classifier: Optional[PromptInjectionClassifier] = None
_classifier_lock = threading.Lock()


def get_prompt_injection_classifier() -> PromptInjectionClassifier:
    """Return a process-wide classifier instance; model weights are lazy-loaded."""
    global _classifier
    if _classifier is None:
        with _classifier_lock:
            if _classifier is None:
                _classifier = PromptInjectionClassifier()
    return _classifier


def reset_prompt_injection_classifier() -> None:
    """Reset singleton for tests; not intended for production request handling."""
    global _classifier
    with _classifier_lock:
        _classifier = None
