"""Text analysis utilities for security scanning."""

import math
import re
from typing import List, Set


# Common Cyrillic and Greek homoglyphs used in spoofing attacks
HOMOGLYPH_MAP = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'ѕ': 's',
    'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j', 'ԛ': 'q', 'ԁ': 'd'
}

URGENCY_KEYWORDS = {
    "immediately", "urgent", "action required", "account suspended", "verify your account",
    "wire transfer", "unauthorized activity", "final notice", "immediate payment",
    "password expired", "click here", "reset password", "security alert"
}


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string (useful for detecting obfuscated tokens/keys)."""
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def find_homoglyphs(text: str) -> List[str]:
    """Find suspicious mixed-script homoglyphs in text or domain names."""
    detected = []
    for char in text:
        if char in HOMOGLYPH_MAP:
            detected.append(char)
    return detected


def extract_urgency_signals(text: str) -> List[str]:
    """Detect urgency and social engineering cues in text."""
    lower_text = text.lower()
    signals = []
    for kw in URGENCY_KEYWORDS:
        if kw in lower_text:
            signals.append(kw)
    return signals


def extract_urls(text: str) -> List[str]:
    """Extract http/https URLs from arbitrary text."""
    pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    return re.findall(pattern, text)
