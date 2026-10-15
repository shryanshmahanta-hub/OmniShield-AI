"""Risk calculation engine."""

from typing import Dict, List
from app.schemas import RiskLevel


def score_to_risk_level(score: float) -> RiskLevel:
    """Map a normalized 0.0 - 1.0 risk score to a categorical RiskLevel."""
    clamped = max(0.0, min(1.0, score))
    if clamped < 0.20:
        return RiskLevel.SAFE
    elif clamped < 0.45:
        return RiskLevel.LOW
    elif clamped < 0.70:
        return RiskLevel.MEDIUM
    elif clamped < 0.88:
        return RiskLevel.HIGH
    else:
        return RiskLevel.CRITICAL


def calculate_composite_score(indicators: Dict[str, float], weights: Dict[str, float]) -> float:
    """Calculate weighted composite score from multiple detection indicators."""
    if not indicators:
        return 0.0

    total_weight = 0.0
    weighted_sum = 0.0

    for key, val in indicators.items():
        w = weights.get(key, 1.0)
        total_weight += w
        weighted_sum += min(1.0, max(0.0, val)) * w

    if total_weight <= 0:
        return 0.0

    return round(min(1.0, weighted_sum / total_weight), 3)
