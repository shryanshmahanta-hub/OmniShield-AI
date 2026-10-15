"""Active Agent Honeypot: a simulated internal assistant protected by OmniShield's injection defences.

The assistant is a deterministic, scripted decoy. It does not call an LLM and holds only synthetic demo
data, so a judge can safely throw jailbreaks at it. What is real is the defensive pipeline around it:
``detect_injection`` (rules) + optional ``PromptInjectionClassifier`` (ML), conservative fusion, incident
logging, sanitized audit logging and cross-module session correlation.
"""
from __future__ import annotations

import asyncio
import hashlib
import re
from typing import Any, Dict, List

from app.config import get_settings
from app.schemas import HoneypotPersona
from app.services.injection_detector import detect_injection
from app.services.prompt_injection_ml import get_prompt_injection_classifier
from app.services.risk_engine import score_to_risk_level

# Finding description (from injection_detector) -> short machine-readable attack vector + plain-English impact
_VECTORS: Dict[str, tuple[str, str]] = {
    "Override instruction directive": ("instruction_override", "Would have tried to make the assistant ignore its safety and business rules."),
    "Disregard prompt directive": ("instruction_override", "Would have tried to make the assistant ignore its safety and business rules."),
    "Jailbreak persona adoption (DAN/developer mode)": ("jailbreak_persona", "Would have switched the assistant into an unrestricted persona."),
    "Persona hijack attempt": ("persona_hijack", "Would have replaced the assistant's role with an attacker-chosen one."),
    "System prompt exfiltration attempt": ("prompt_exfiltration", "Would have leaked hidden instructions, which often contain internal tools, policies or secrets."),
    "Special delimiter token injection": ("delimiter_injection", "Would have forged system-level message boundaries to smuggle in new instructions."),
    "Explicit bypass/jailbreak terminology": ("safety_bypass", "Would have asked the assistant to disable its content and safety filters."),
    "Obfuscated payload execution command": ("obfuscated_execution", "Would have hidden an instruction in encoded text to slip past filters."),
    "System role boundary spoofing attempt": ("role_boundary_spoofing", "Would have posed as the system or assistant to gain authority."),
    "Pretrained ML classifier flagged possible prompt injection": ("ml_flagged_injection", "A trained classifier judged this input likely to be a prompt-injection attempt."),
}

BLOCK_REPLY = ("I can't help with that request. This conversation has been flagged and recorded for the "
                "security team. If you meant to ask something else, rephrase your question.")

_HR_FAQ = [
    (re.compile(r"(?i)\bleave|vacation|time\s*off|pto\b"), "Demo data: you have 12 casual and 8 earned leave days remaining this year. Submit requests at least 3 working days ahead."),
    (re.compile(r"(?i)\bpay\s*slip|salary\s*date|pay\s*day|payroll\b"), "Demo data: payslips are released on the last working day of each month."),
    (re.compile(r"(?i)\bholiday|festival\b"), "Demo data: the next company holiday is listed in the shared HR calendar."),
]
_INVENTORY = {"SKU-1001": ("USB-C cable 1m", 142), "SKU-1002": ("Phone case, clear", 37), "SKU-1003": ("Power bank 10000mAh", 9)}
_SKU = re.compile(r"(?i)\bSKU-\d{4}\b")


def persona_label(persona: HoneypotPersona) -> str:
    return {"hr": "HR Helper (decoy)", "inventory": "Stock Assistant (decoy)"}[persona.value]


def benign_reply(persona: HoneypotPersona, message: str) -> str:
    """Scripted, synthetic-data answer for benign messages."""
    if persona == HoneypotPersona.HR:
        for pattern, reply in _HR_FAQ:
            if pattern.search(message):
                return reply
        return "I'm the HR helper. I can answer questions about leave balance, payslip dates and holidays."
    sku = _SKU.search(message)
    if sku:
        key = sku.group(0).upper()
        if key in _INVENTORY:
            name, qty = _INVENTORY[key]
            note = " Low stock: consider reordering." if qty < 10 else ""
            return f"Demo data: {key} ({name}) has {qty} units in stock.{note}"
        return f"I couldn't find {key} in the demo catalogue."
    if re.search(r"(?i)\bstock|inventory|reorder|low\b", message):
        return "Demo data: 3 SKUs are tracked. Ask about a SKU such as SKU-1001."
    return "I'm the stock assistant. Ask me about stock levels, for example 'How many SKU-1001 do we have?'"


async def run_injection_pipeline(message: str) -> Dict[str, Any]:
    """Rules first, then optional ML. The ML result can only raise risk; it can never lower or override a rule hit."""
    result = detect_injection(prompt=message)
    result["details"]["rule_score_before_model"] = result["risk_score"]

    settings = get_settings()
    ml: Dict[str, Any] = {"enabled": settings.enable_prompt_ml, "available": False,
                          "model": settings.prompt_ml_model if settings.enable_prompt_ml else None,
                          "prediction": None, "confidence": None,
                          "status": "disabled" if not settings.enable_prompt_ml else "not_checked"}
    if settings.enable_prompt_ml:
        classifier = get_prompt_injection_classifier()
        ml = await asyncio.to_thread(classifier.classify, message)
        ml["enabled"] = True
        confidence = ml.get("confidence")
        if (ml.get("available") and ml.get("prediction") == "INJECTION"
                and isinstance(confidence, (int, float)) and 0.0 <= confidence <= 1.0
                and confidence >= settings.prompt_ml_threshold):
            ml_score = min(0.75, max(0.50, float(confidence) * 0.75))
            result["risk_score"] = max(float(result["risk_score"]), ml_score)
            result["risk_level"] = score_to_risk_level(result["risk_score"])
            result["flagged"] = result["risk_score"] >= 0.50
            finding = "Pretrained ML classifier flagged possible prompt injection"
            if finding not in result["findings"]:
                result["findings"].append(finding)
    result["details"]["ml_policy"] = ("ML can raise risk (capped at 0.75) but cannot lower it or override a "
                                      "deterministic rule match; a SAFE prediction is ignored when rules fired.")
    result["details"]["decision_fusion"] = {
        "method": "conservative_rule_and_model_fusion", "model_can_raise_risk": True,
        "model_can_lower_risk": False, "model_alone_can_set_critical": False,
        "rule_score_before_model": result["details"]["rule_score_before_model"],
    }
    result["ml"] = ml
    return result


def summarize_vectors(findings: List[str]) -> tuple[List[str], List[str]]:
    vectors, explainers = [], []
    for finding in findings:
        if finding in _VECTORS:
            vec, why = _VECTORS[finding]
            if vec not in vectors:
                vectors.append(vec)
                explainers.append(why)
    return vectors, explainers


def message_fingerprint(message: str) -> str:
    """Short hash for de-duplicating repeated attack strings without persisting the text."""
    return hashlib.sha256(message.encode("utf-8")).hexdigest()[:12]
