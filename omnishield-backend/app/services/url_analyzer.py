"""URL and domain threat analyzer."""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse
from app.services.text_utils import calculate_entropy, find_homoglyphs

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz",
    ".country", ".work", ".click", ".link", ".kim", ".party"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "is.gd", "cutt.ly"
}

LOGIN_KEYWORDS = {
    "login", "signin", "verify", "update-account", "secure", "banking",
    "wallet", "password", "credential", "auth", "confirm", "portal"
}

IP_PATTERN = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


def analyze_url(url: str) -> Dict[str, Any]:
    """Analyze URL structure only. Never resolves DNS or fetches the submitted URL."""
    original = (url or "").strip()
    if not original or len(original) > 4096:
        return {"url": original[:200], "hostname": "", "flags": ["invalid_url"], "score": 0.0, "is_suspicious": False, "valid": False}
    # Do not silently reinterpret executable or local schemes as web links.
    if "://" not in original:
        candidate = "http://" + original
    else:
        candidate = original
    try:
        parsed = urlparse(candidate)
        raw_hostname = (parsed.hostname or "").rstrip(".").lower()
        if parsed.scheme.lower() not in {"http", "https"} or not raw_hostname or parsed.username or parsed.password:
            raise ValueError("unsupported URL shape")
        if len(raw_hostname) > 253:
            raise ValueError("hostname too long")
        # IDNA conversion lets the heuristic inspect the ASCII host while we still
        # flag non-ASCII characters in the original host as a visual-spoofing hint.
        hostname = raw_hostname.encode("idna").decode("ascii").lower()
        _ = parsed.port  # trigger urlparse's malformed-port validation
    except Exception:
        return {"url": original[:200], "hostname": "", "flags": ["invalid_or_unsupported_url"], "score": 0.0, "is_suspicious": False, "valid": False}
    url = candidate
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()

    flags: List[str] = []
    threat_score = 0.0

    # 1. IP address instead of domain
    if IP_PATTERN.match(hostname):
        flags.append("raw_ip_address_used")
        threat_score += 0.45

    # 2. Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            flags.append(f"suspicious_tld_{tld}")
            threat_score += 0.35
            break

    # 3. Shortener service
    if hostname in SHORTENERS:
        flags.append("url_shortener_detected")
        threat_score += 0.25

    # 4. Excessive subdomain nesting
    parts = hostname.split('.')
    if len(parts) > 4:
        flags.append("excessive_subdomain_depth")
        threat_score += 0.20

    # 5. Phishing / credential keywords in path or query
    detected_keywords = [kw for kw in LOGIN_KEYWORDS if kw in path or kw in query]
    if detected_keywords:
        flags.append(f"credential_keywords_{','.join(detected_keywords[:3])}")
        threat_score += 0.30

    # 6. Homoglyphs in hostname
    homoglyphs = find_homoglyphs(raw_hostname)
    if any(ord(ch) > 127 for ch in raw_hostname):
        homoglyphs = True
    if homoglyphs:
        flags.append(f"homoglyph_characters_in_domain")
        threat_score += 0.50

    # 7. Entropy of query string
    if query and calculate_entropy(query) > 4.5:
        flags.append("high_entropy_query_string")
        threat_score += 0.15

    return {
        "url": url,
        "hostname": hostname,
        "flags": flags,
        "score": round(min(1.0, threat_score), 3),
        "is_suspicious": threat_score >= 0.40,
        "valid": True,
    }
