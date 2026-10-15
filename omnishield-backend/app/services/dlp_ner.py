"""Optional local NER model used only to augment Data Leak Shield.

It never sends content over the network. This detects common named entities, not every
kind of PII or confidential business data; deterministic detectors remain primary.
"""
from __future__ import annotations
import logging
import threading
from typing import Any, Dict
from app.config import get_settings

logger = logging.getLogger(__name__)
_lock = threading.Lock()
_pipeline = None
_load_failed = False
_loaded_model = None


def analyze_entities(text: str) -> Dict[str, Any]:
    global _pipeline, _load_failed, _loaded_model
    settings = get_settings()
    model_name = settings.dlp_ner_model
    if not settings.enable_dlp_ner:
        return {"enabled": False, "available": False, "model": None, "status": "disabled", "entities": [], "spans": []}
    if _pipeline is None and not _load_failed:
        with _lock:
            if _pipeline is None and not _load_failed:
                try:
                    from transformers import AutoModelForTokenClassification, AutoTokenizer, pipeline
                    tokenizer = AutoTokenizer.from_pretrained(model_name, local_files_only=settings.text_ml_local_files_only)
                    model = AutoModelForTokenClassification.from_pretrained(
                        model_name, local_files_only=settings.text_ml_local_files_only, use_safetensors=True)
                    model.to("cpu")
                    model.eval()
                    _pipeline = pipeline("ner", model=model, tokenizer=tokenizer, device=-1, aggregation_strategy="simple")
                    _loaded_model = model_name
                except Exception as exc:
                    _load_failed = True
                    logger.warning("Optional DLP NER model unavailable (%s)", type(exc).__name__)
    if _pipeline is None or _loaded_model != model_name:
        return {"enabled": True, "available": False, "model": model_name, "status": "load_failed", "entities": [], "spans": []}
    try:
        # The usual encoder limit is 512 tokens. Avoid processing arbitrarily large bodies
        # in the NER model; regex DLP still sees the validated full request.
        truncated_text = text[:12000]
        raw = _pipeline(truncated_text, truncation=True, max_length=512)
        if isinstance(raw, dict):
            raw = [raw]
        groups: Dict[str, int] = {}
        spans = []
        for item in raw or []:
            label = str(item.get("entity_group", item.get("entity", ""))).upper()
            # Common labels used by CoNLL-style NER models; ignore MISC/O labels.
            if label not in {"PER", "PERSON", "ORG", "LOC", "GPE"}:
                continue
            start, end = item.get("start"), item.get("end")
            if not isinstance(start, int) or not isinstance(end, int) or start < 0 or end <= start or end > len(truncated_text):
                continue
            confidence = float(item.get("score", 0.0))
            if not 0 <= confidence <= 1:
                continue
            normalized = "PERSON" if label in {"PER", "PERSON"} else "ORGANIZATION" if label == "ORG" else "LOCATION"
            groups[normalized] = groups.get(normalized, 0) + 1
            spans.append({"start": start, "end": end, "type": normalized, "confidence": round(confidence, 4)})
        return {"enabled": True, "available": True, "model": model_name, "status": "success",
                "entities": [{"type": kind, "count": count} for kind, count in sorted(groups.items())],
                "spans": spans, "truncated": len(text) > len(truncated_text)}
    except Exception as exc:
        logger.warning("Optional DLP NER inference failed (%s)", type(exc).__name__)
        return {"enabled": True, "available": False, "model": model_name, "status": "inference_failed", "entities": [], "spans": []}


def reset_dlp_ner_for_tests() -> None:
    global _pipeline, _load_failed, _loaded_model
    with _lock:
        _pipeline = None
        _load_failed = False
        _loaded_model = None
