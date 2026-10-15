"""Optional local Transformer inference for text-like security signals.

Models are loaded lazily, one model per task, and local-only by default. This
module deliberately does not upload scanned text to a third-party service.
"""
from __future__ import annotations

import logging
import math
import threading
from typing import Any, Dict, Optional

from app.config import get_settings

logger = logging.getLogger(__name__)

_POSITIVE = ("phish", "scam", "spam", "fraud", "malicious", "unsafe", "injection", "suspicious", "harmful", "attack")
_NEGATIVE = ("legitimate", "benign", "safe", "ham", "not_spam", "not spam", "normal", "clean", "non-phishing", "non phishing")


class LocalTextClassifier:
    """Generic sequence classifier with explicit class-name handling."""
    def __init__(self, task: str, model_id: str, labels_csv: str, local_only: bool = True):
        self.task = task
        self.model_id = model_id
        self.configured_labels = [x.strip() for x in labels_csv.split(",") if x.strip()]
        self.local_only = local_only
        self._lock = threading.Lock()
        self._tokenizer: Any = None
        self._model: Any = None
        self._torch: Any = None
        self._id_to_label: Dict[int, str] = {}
        self._load_failed = False

    def _load(self) -> bool:
        if self._model is not None and self._tokenizer is not None:
            return True
        if self._load_failed:
            return False
        with self._lock:
            if self._model is not None and self._tokenizer is not None:
                return True
            if self._load_failed:
                return False
            try:
                import torch
                from transformers import AutoModelForSequenceClassification, AutoTokenizer
                tokenizer = AutoTokenizer.from_pretrained(self.model_id, local_files_only=self.local_only)
                model = AutoModelForSequenceClassification.from_pretrained(
                    self.model_id, local_files_only=self.local_only, use_safetensors=True
                )
                model.to("cpu")
                model.eval()
                raw = getattr(model.config, "id2label", {}) or {}
                id_to_label = {int(k): str(v).strip() for k, v in raw.items()}
                count = int(getattr(model.config, "num_labels", 0) or len(id_to_label))
                if count < 2 or len(id_to_label) != count:
                    raise ValueError("Model configuration has no valid class map")
                # Training exports often store LABEL_0/LABEL_1, which has no semantics.
                # In that case we require an explicit task label map with matching length.
                if all(label.upper() in {f"LABEL_{i}" for i in range(count)} for i, label in id_to_label.items()):
                    # Generic LABEL_n outputs have no intrinsic meaning. Only map them
                    # when the operator supplied a complete explicit mapping; otherwise
                    # preserve generic labels and report label_mapping_unknown at inference.
                    if len(self.configured_labels) == count:
                        id_to_label = {i: self.configured_labels[i] for i in range(count)}
                self._torch, self._tokenizer, self._model, self._id_to_label = torch, tokenizer, model, id_to_label
                return True
            except Exception as exc:
                self._load_failed = True
                logger.warning("Optional %s model unavailable (%s)", self.task, type(exc).__name__)
                return False

    def classify(self, text: str) -> Dict[str, Any]:
        if not self._load():
            return {"enabled": True, "available": False, "model": self.model_id,
                    "prediction": None, "confidence": None, "status": "load_failed"}
        try:
            encoded = self._tokenizer(text, truncation=True, max_length=512, return_tensors="pt")
            with self._torch.inference_mode():
                logits = self._model(**encoded).logits
                probs = self._torch.softmax(logits, dim=-1)[0].tolist()
            if len(probs) != len(self._id_to_label):
                raise ValueError("Model output dimensions do not match its label map")
            idx = max(range(len(probs)), key=lambda i: probs[i])
            confidence = float(probs[idx])
            if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
                raise ValueError("Invalid model confidence")
            raw_label = self._id_to_label[idx].strip()
            normalized = self._normalize_label(raw_label)
            if normalized is None:
                return {"enabled": True, "available": False, "model": self.model_id,
                        "prediction": None, "confidence": None, "status": "label_mapping_unknown"}
            return {"enabled": True, "available": True, "model": self.model_id,
                    "prediction": normalized, "confidence": round(confidence, 6), "status": "success"}
        except Exception as exc:
            logger.warning("Optional %s inference failed (%s)", self.task, type(exc).__name__)
            return {"enabled": True, "available": False, "model": self.model_id,
                    "prediction": None, "confidence": None, "status": "inference_failed"}

    def _normalize_label(self, label: str) -> Optional[str]:
        # Do not use substring checks for benign labels: "unsafe" contains "safe".
        # Normalize the whole label, and handle negations before suspicious tokens.
        low = " ".join(label.lower().replace("-", " ").replace("_", " ").split())
        if any(phrase in low for phrase in (
            "not phishing", "non phishing", "not phish", "not spam", "non spam",
            "not scam", "non scam", "not malicious", "not fraud", "not injection",
            "no attack", "no threat", "not harmful", "not suspicious",
        )):
            return "legitimate"
        benign_labels = {"0 benign", "benign", "legitimate", "ham", "safe", "normal", "clean", "nonthreat", "non threat", "legit", "good", "false"}
        if low in benign_labels:
            return "legitimate"
        suspicious_labels = {"phish", "phishing", "spam", "scam", "fraud", "malicious", "unsafe", "injection", "suspicious", "harmful", "attack", "threat", "bad", "true"}
        if low in suspicious_labels:
            return "suspicious"
        # Some model cards use informative labels with prefixes/suffixes.
        tokens = set(low.split())
        if tokens & {"phish", "phishing", "spam", "scam", "fraud", "malicious", "unsafe", "injection", "suspicious", "harmful", "attack", "threat"}:
            return "suspicious"
        if tokens & {"benign", "legitimate", "ham", "safe", "normal", "clean", "legit"}:
            return "legitimate"
        # A generic LABEL_0 or ambiguous label must never create a verdict.
        return None



_classifiers: Dict[str, LocalTextClassifier] = {}
_classifier_lock = threading.Lock()


def classify_text(task: str, text: str) -> Dict[str, Any]:
    """Run the optional task-specific local model and return explicit status."""
    settings = get_settings()
    config = {
        "sms": (settings.enable_sms_ml, settings.sms_ml_model, settings.sms_ml_labels),
        "email": (settings.enable_email_ml, settings.email_ml_model, settings.email_ml_labels),
        "url": (settings.enable_url_ml, settings.url_ml_model, settings.url_ml_labels),
        "invoice": (settings.enable_invoice_ml and bool(settings.invoice_ml_model), settings.invoice_ml_model or "", settings.invoice_ml_labels),
    }
    if task not in config:
        return {"enabled": False, "available": False, "model": None, "prediction": None, "confidence": None, "status": "unsupported_task"}
    enabled, model_id, labels = config[task]
    if not enabled:
        return {"enabled": False, "available": False, "model": None, "prediction": None, "confidence": None, "status": "disabled"}
    key = f"{task}:{model_id}:{labels}:{settings.text_ml_local_files_only}"
    with _classifier_lock:
        classifier = _classifiers.get(key)
        if classifier is None:
            classifier = LocalTextClassifier(task, model_id, labels, settings.text_ml_local_files_only)
            _classifiers[key] = classifier
    return classifier.classify(text)


def reset_text_classifiers() -> None:
    """Test helper. Do not call during concurrent production requests."""
    with _classifier_lock:
        _classifiers.clear()
