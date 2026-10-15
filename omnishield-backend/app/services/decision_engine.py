"""Conservative rule + model evidence fusion for normalized scan results."""
from typing import Any, Dict, Optional
from app.config import get_settings
from app.services.risk_engine import score_to_risk_level


def fuse_model_signal(result: Dict[str, Any], model_result: Dict[str, Any], *, signal_name: str) -> Dict[str, Any]:
    """Let a high-confidence adverse model signal raise—but never lower—rule risk.

    The model alone is capped below critical. A 'legitimate' model result never
    overrides known-bad rules or threat-intelligence matches.
    """
    details = result.setdefault("details", {})
    details.setdefault("model_signals", {})[signal_name] = {
        "enabled": bool(model_result.get("enabled")),
        "available": bool(model_result.get("available")),
        "model": model_result.get("model"),
        "prediction": model_result.get("prediction"),
        "confidence": model_result.get("confidence"),
        "status": model_result.get("status", "unknown"),
    }
    confidence = model_result.get("confidence")
    suspicious = model_result.get("prediction") in {"suspicious", "phishing", "spam", "fraud", "malicious", "injection"}
    threshold = get_settings().domain_ml_threshold
    if model_result.get("available") and suspicious and isinstance(confidence, (int, float)) and confidence >= threshold:
        # One ML signal may raise the risk floor to high-ish, but cannot alone issue critical.
        model_floor = min(0.84, max(0.50, 0.40 + float(confidence) * 0.40))
        result["risk_score"] = round(max(float(result.get("risk_score", 0.0)), model_floor), 3)
        result["risk_level"] = score_to_risk_level(result["risk_score"])
        result["flagged"] = result["risk_score"] >= 0.45
        finding = f"Deep-learning {signal_name} model flagged a suspicious pattern"
        if finding not in result.setdefault("findings", []):
            result["findings"].append(finding)
    details["decision_fusion"] = {
        "method": "conservative_rule_and_model_fusion",
        "rule_score_before_model": details.get("rule_score_before_model", result.get("risk_score", 0.0)),
        "model_can_raise_risk": True,
        "model_can_lower_risk": False,
        "model_alone_can_set_critical": False,
        "threshold": threshold,
    }
    return result


def add_verdict(result: Dict[str, Any], *, checked_artifact: bool = True) -> str:
    """Human-readable verdict; low score is not proof of safety."""
    if not checked_artifact:
        return "unknown"
    score = float(result.get("risk_score", 0.0))
    if score >= 0.88:
        return "critical_risk"
    if score >= 0.70:
        return "high_risk"
    if score >= 0.45:
        return "suspicious"
    if not result.get("findings") and result.get("details", {}).get("scanner_status") == "unavailable":
        return "unknown"
    return "no_high_risk_signal_detected"
