"""Prompt injection and jailbreak detector for LLM applications."""

import re
from typing import Any, Dict, List, Optional
from app.services.risk_engine import score_to_risk_level

INJECTION_PATTERNS = [
    (r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|rules|prompts)", 0.90, "Override instruction directive"),
    (r"(?i)disregard\s+(all\s+)?(previous|prior|system)\s+(instructions|directives|prompts)", 0.90, "Disregard prompt directive"),
    (r"(?i)you\s+are\s+now\s+(unrestricted|in\s+developer\s+mode|dan|evilbot|jailbroken)", 0.85, "Jailbreak persona adoption (DAN/developer mode)"),
    (r"(?i)from\s+now\s+on\s+you\s+(will|must)\s+(act|pretend|behave)\s+as", 0.70, "Persona hijack attempt"),
    (r"(?i)(repeat|print|reveal|output|display)\s+(the\s+)?(system\s+prompt|above\s+text|initial\s+instructions)", 0.80, "System prompt exfiltration attempt"),
    (r"(?i)<\|im_start\|>|<\|im_end\|>|\[SYSTEM\]|\[INST\]|<system>", 0.85, "Special delimiter token injection"),
    (r"(?i)do\s+anything\s+now|bypass\s+safety\s+filters|jailbreak", 0.80, "Explicit bypass/jailbreak terminology"),
    (r"(?i)base64\s+decode|execute\s+this\s+code\s+silently", 0.65, "Obfuscated payload execution command"),
]


def detect_injection(prompt: str, context: Optional[str] = None) -> Dict[str, Any]:
    """Detect prompt injection and jailbreak attacks in user prompts."""
    full_text = f"{context or ''} {prompt}".strip()
    detected_patterns: List[Dict[str, Any]] = []
    max_pattern_score = 0.0

    for pattern, weight, description in INJECTION_PATTERNS:
        match = re.search(pattern, full_text)
        if match:
            detected_patterns.append({
                "description": description,
                "matched_text": match.group(0),
                "weight": weight
            })
            if weight > max_pattern_score:
                max_pattern_score = weight

    # Check for excessive repetition or boundary escapes
    boundary_score = 0.0
    if "---" in full_text and ("system" in full_text.lower() or "assistant" in full_text.lower()):
        boundary_score = 0.40
        detected_patterns.append({
            "description": "System role boundary spoofing attempt",
            "matched_text": "---",
            "weight": 0.40
        })

    final_score = max(max_pattern_score, boundary_score)
    normalized_score = round(min(1.0, final_score), 3)
    risk_level = score_to_risk_level(normalized_score)
    flagged = normalized_score >= 0.50

    findings = [p["description"] for p in detected_patterns]
    recommendation = "Prompt is safe to process."
    if flagged:
        recommendation = "Reject or sanitize prompt; direct override of system instructions detected."

    return {
        "risk_score": normalized_score,
        "risk_level": risk_level,
        "flagged": flagged,
        "findings": findings,
        "details": {
            "matches": detected_patterns,
            "patterns_checked": len(INJECTION_PATTERNS),
        },
        "recommendation": recommendation,
    }
