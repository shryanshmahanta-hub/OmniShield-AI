"""Data Loss Prevention (DLP) scanner for PII and credential leaks."""

import re
from typing import Any, Dict, List
from app.services.risk_engine import score_to_risk_level

CREDIT_CARD_REGEX = re.compile(r'\b(?:\d{4}[ -]?){3}\d{4}\b')
SSN_REGEX = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b')

KEY_PATTERNS = [
    ("AWS Access Key", re.compile(r'\bAKIA[0-9A-Z]{16}\b'), 0.95),
    ("GitHub Personal Access Token", re.compile(r'\bghp_[A-Za-z0-9]{36}\b'), 0.95),
    ("OpenAI API Key", re.compile(r'\bsk-[A-Za-z0-9]{32,64}\b'), 0.95),
    ("Google API Key", re.compile(r'\bAIza[0-9A-Za-z-_]{35}\b'), 0.95),
    ("RSA/Private Key Header", re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----'), 1.0),
]


def luhn_validate(card_number: str) -> bool:
    """Validate a credit card number using Luhn algorithm."""
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) not in (15, 16):
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


def detect_dlp(content: str, redact: bool = False) -> Dict[str, Any]:
    """Scan content for credentials, secrets, and personally identifiable information."""
    findings: List[str] = []
    entities_found: List[Dict[str, Any]] = []
    max_score = 0.0
    redacted_content = content

    # 1. API Keys and Secrets
    for name, pattern, weight in KEY_PATTERNS:
        matches = pattern.findall(content)
        if matches:
            findings.append(f"Detected secret: {name}")
            entities_found.append({"type": name, "count": len(matches)})
            max_score = max(max_score, weight)
            if redact:
                redacted_content = pattern.sub(f"[{name.upper()}_REDACTED]", redacted_content)

    # 2. Credit Cards with Luhn check
    cc_matches = CREDIT_CARD_REGEX.findall(content)
    valid_cards = [cc for cc in cc_matches if luhn_validate(cc)]
    if valid_cards:
        findings.append("Detected valid credit card number(s)")
        entities_found.append({"type": "Credit Card", "count": len(valid_cards)})
        max_score = max(max_score, 0.90)
        if redact:
            for card in valid_cards:
                redacted_content = redacted_content.replace(card, "[CREDIT_CARD_REDACTED]")

    # 3. SSN
    ssn_matches = SSN_REGEX.findall(content)
    if ssn_matches:
        findings.append("Detected Social Security Number(s)")
        entities_found.append({"type": "SSN", "count": len(ssn_matches)})
        max_score = max(max_score, 0.85)
        if redact:
            redacted_content = SSN_REGEX.sub("[SSN_REDACTED]", redacted_content)

    # 4. Emails
    email_matches = EMAIL_REGEX.findall(content)
    if email_matches:
        findings.append(f"Detected {len(email_matches)} email address(es)")
        entities_found.append({"type": "Email", "count": len(email_matches)})
        max_score = max(max_score, 0.25)
        if redact:
            redacted_content = EMAIL_REGEX.sub("[EMAIL_REDACTED]", redacted_content)

    normalized_score = round(min(1.0, max_score), 3)
    risk_level = score_to_risk_level(normalized_score)
    flagged = normalized_score >= 0.45

    recommendation = "No sensitive data detected."
    if flagged:
        recommendation = "Do not transmit content externally; sensitive secrets or PII detected."

    details: Dict[str, Any] = {
        "entities": entities_found,
        "total_sensitive_items": sum(e["count"] for e in entities_found),
    }
    if redact:
        details["redacted_content"] = redacted_content

    return {
        "risk_score": normalized_score,
        "risk_level": risk_level,
        "flagged": flagged,
        "findings": findings,
        "details": details,
        "recommendation": recommendation,
    }
