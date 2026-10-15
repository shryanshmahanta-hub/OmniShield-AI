"""Phishing and social engineering analyzer."""

from typing import Any, Dict, List, Optional
from app.services.risk_engine import score_to_risk_level
from app.services.text_utils import extract_urgency_signals, extract_urls
from app.services.url_analyzer import analyze_url

TARGET_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "wells fargo", "chase", "bank of america", "dhl", "fedex"
]


def analyze_phishing(
    text: str,
    sender: Optional[str] = None,
    subject: Optional[str] = None,
    explicit_urls: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Analyze communication for phishing, brand impersonation, and malicious links."""
    combined_text = f"{subject or ''} {text}".strip()
    urgency_signals = extract_urgency_signals(combined_text)

    # Check for brand mentions
    lower_text = combined_text.lower()
    brands_detected = [b for b in TARGET_BRANDS if b in lower_text]

    # Check sender discrepancies if sender provided
    sender_flags = []
    if sender:
        sender_lower = sender.lower()
        for b in brands_detected:
            # If text mentions "paypal" but sender domain is not paypal.com
            brand_token = b.replace(" ", "")
            if brand_token in lower_text and brand_token not in sender_lower:
                sender_flags.append(f"brand_mention_mismatch_{brand_token}")

    # Gather URLs from text + explicit URLs
    extracted = extract_urls(combined_text)
    all_urls = list(set((explicit_urls or []) + extracted))

    url_results = [analyze_url(u) for u in all_urls]
    max_url_score = max([r["score"] for r in url_results], default=0.0)

    # Compute risk score
    score = 0.0
    findings: List[str] = []

    if urgency_signals:
        score += min(0.35, len(urgency_signals) * 0.15)
        findings.append(f"High urgency / pressure cues detected: {', '.join(urgency_signals[:3])}")

    if sender_flags:
        score += 0.40
        findings.append("Potential sender brand impersonation / spoofing detected")

    if max_url_score > 0:
        score += max_url_score * 0.55
        suspicious_urls = [r["url"] for r in url_results if r["is_suspicious"]]
        if suspicious_urls:
            findings.append(f"Suspicious link(s) found: {', '.join(suspicious_urls[:2])}")

    normalized_score = round(min(1.0, score), 3)
    risk_level = score_to_risk_level(normalized_score)
    flagged = normalized_score >= 0.45

    recommendation = "Message appears legitimate."
    if flagged:
        recommendation = "Do not click links or provide credentials. Verify the sender through a trusted secondary channel."

    return {
        "risk_score": normalized_score,
        "risk_level": risk_level,
        "flagged": flagged,
        "findings": findings,
        "details": {
            "urgency_signals": urgency_signals,
            "brands_detected": brands_detected,
            "sender_flags": sender_flags,
            "url_analysis": url_results,
        },
        "recommendation": recommendation,
    }
