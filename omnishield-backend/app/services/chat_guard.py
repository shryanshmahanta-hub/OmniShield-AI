"""WhatsApp / SMS Order Guard analysis.

Layers (all deterministic, no network calls):
1. ``analyze_phishing`` (existing PhishingAnalyzer) for urgency cues, brand/sender mismatch and URL heuristics.
2. Chat-specific lookalike-domain detection (typosquats, leetspeak, brand-in-subdomain, brand-embedded hosts).
3. Chat-specific social-engineering patterns for small retail: fake payment receipts, overpayment/refund
   scams, QR/"collect request" scams, OTP/PIN requests, supplier bank-detail changes, untraceable payment.

Risk fusion is conservative. Components combine monotonically (noisy-OR), and a *hard rule* sets a score
floor that nothing downstream (including optional ML) can lower.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from app.schemas import (
    AlertNotification,
    ChatChannel,
    LookalikeDomain,
    RiskLevel,
    StoreOwnerAlert,
)
from app.services.phishing_analyzer import analyze_phishing
from app.services.risk_engine import score_to_risk_level
from app.services.text_utils import extract_urls

FLAG_THRESHOLD = 0.45

# Registrable domains that small shops commonly see impersonated.
PROTECTED_DOMAINS: Set[str] = {
    "paypal.com", "stripe.com", "razorpay.com", "paytm.com", "phonepe.com", "google.com",
    "amazon.com", "amazon.in", "flipkart.com", "meesho.com", "whatsapp.com", "instagram.com",
    "facebook.com", "shopify.com", "dhl.com", "fedex.com", "ups.com", "bluedart.com",
    "delhivery.com", "indiapost.gov.in", "sbi.co.in", "hdfcbank.com", "icicibank.com",
    "axisbank.com", "venmo.com", "squareup.com", "apple.com", "microsoft.com", "netflix.com",
}

_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu", "nic"}
_KNOWN_TLDS = {
    "com", "net", "org", "info", "biz", "io", "co", "in", "app", "shop", "store", "online", "site",
    "live", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "click", "link", "work", "kim",
    "party", "country", "me", "us", "uk", "de", "fr", "ae", "sg", "au", "ca", "pk", "bd", "lk",
    "np", "cc", "ws", "to", "ly", "pay", "support", "help", "services", "cloud", "vip", "icu",
}
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})
_BARE_DOMAIN = re.compile(
    r"(?<![@\w.\-/])((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![\w@\-])(?:/[^\s]*)?", re.I)


def registrable_domain(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if len(parts[-1]) == 2 and parts[-2] in _SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _edit_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _normalise_label(label: str) -> str:
    return label.lower().translate(_LEET).replace("rn", "m").replace("vv", "w")


def detect_lookalike(hostname: str, trusted: Set[str]) -> Optional[LookalikeDomain]:
    """Return a LookalikeDomain when ``hostname`` imitates a protected brand domain."""
    host = hostname.lower().strip(".")
    if not host or "." not in host:
        return None
    reg = registrable_domain(host)
    if reg in PROTECTED_DOMAINS or reg in trusted or any(host == t or host.endswith("." + t) for t in trusted):
        return None

    # Brand domain used as a subdomain of something else: paypal.com.secure-login.xyz
    for protected in sorted(PROTECTED_DOMAINS):
        if f".{protected}." in f".{host}.":
            return LookalikeDomain(hostname=host, impersonates=protected,
                                   technique="protected domain used as a subdomain of an unrelated site")

    if any(lbl.startswith("xn--") for lbl in host.split(".")):
        return LookalikeDomain(hostname=host, impersonates="unknown", technique="punycode / look-alike Unicode host")

    raw = reg.split(".")[0]
    norm = _normalise_label(raw)
    flat = norm.replace("-", "")
    tokens = set(norm.split("-"))
    for protected in sorted(PROTECTED_DOMAINS):
        brand = protected.split(".")[0]
        if raw == brand:
            return LookalikeDomain(hostname=host, impersonates=protected,
                                   technique="brand name registered under a different domain suffix")
        if raw != brand and (norm == brand or flat == brand):
            return LookalikeDomain(hostname=host, impersonates=protected,
                                   technique="character substitution (e.g. 1 for l, 0 for o, rn for m)")
        if len(brand) >= 6:
            max_edits = 1 if len(brand) < 9 else 2
            if 0 < _edit_distance(flat, brand) <= max_edits:
                return LookalikeDomain(hostname=host, impersonates=protected,
                                       technique="typosquat (one or two characters changed)")
        if brand in tokens or (len(brand) >= 6 and brand in flat):
            return LookalikeDomain(hostname=host, impersonates=protected,
                                   technique="brand name embedded in an unrelated domain")
    return None


def extract_hosts(text: str) -> List[str]:
    """Hostnames from scheme/www URLs and bare domains typed into chat (e.g. 'paytm-pay.xyz/receipt')."""
    urls = extract_urls(text)
    candidates: List[str] = list(urls)
    for match in _BARE_DOMAIN.finditer(text):
        domain = match.group(1)
        if domain.rsplit(".", 1)[-1].lower() in _KNOWN_TLDS:
            candidates.append(match.group(0).rstrip(".,);:!?"))
    seen: Dict[str, None] = {}
    for item in candidates:
        cleaned = item.rstrip(".,);:!?")
        seen.setdefault(cleaned, None)
    return list(seen)


# (regex, weight, tactic, hard_floor)
_RULES: List[Tuple[re.Pattern, float, str, float]] = [
    (re.compile(r"(?i)\b(?:scan\s+(?:this|the)\s+qr(?:\s+code)?\s+to\s+(?:receive|get|collect|claim)"
                r"|(?:approve|accept)\s+(?:the\s+)?(?:upi\s+)?(?:collect|payment)\s+request\s+to\s+(?:receive|get)"
                r"|enter\s+(?:your\s+)?(?:upi\s+)?pin\s+to\s+receive)"),
     0.80, "qr_or_collect_request_scam", 0.80),
    (re.compile(r"(?i)\b(?:share|send|tell|give|forward|read\s+out)\s+(?:me\s+)?(?:the\s+|your\s+)?"
                r"(?:otp|upi\s+pin|pin|cvv|password|verification\s+code)\b"),
     0.75, "credential_or_otp_request", 0.75),
    (re.compile(r"(?i)\b[\w\-]*(?:receipt|payment|invoice|proof|slip|screenshot)[\w\-]*\.(?:apk|exe|scr|bat|vbs|js|jar)\b"),
     0.85, "malicious_receipt_attachment", 0.85),
    (re.compile(r"(?i)\b(?:new|changed|updated|different)\s+(?:bank|account|payment)\s+(?:details|account|number|info)\b"
                r"|\b(?:bank|account)\s+details\s+(?:have\s+)?(?:changed|updated)\b"
                r"|\bpay\s+(?:to|into)\s+(?:this|the\s+new)\s+account\b|\buse\s+(?:the\s+)?new\s+(?:account|iban)\b"),
     0.70, "supplier_bank_detail_change", 0.70),
    (re.compile(r"(?i)\b(?:sent|paid|transferred)\s+(?:you\s+)?(?:too\s+much|extra|more\s+than|by\s+mistake|wrongly)\b"
                r"|\b(?:refund|return|send\s+back)\s+(?:me\s+)?(?:the\s+)?(?:extra|difference|balance|excess)\b"),
     0.60, "overpayment_refund_scam", 0.0),
    (re.compile(r"(?i)\bgift\s*cards?\b|\bitunes\b|\bgoogle\s+play\s+card\b|\bsteam\s+card\b|\bbitcoin\b|\busdt\b|\bcrypto\b"),
     0.55, "untraceable_payment_method", 0.0),
    (re.compile(r"(?i)\b(?:advance|token|booking|registration|delivery|customs|shipping)\s+(?:fee|payment|amount|charge)s?\s+"
                r"(?:first|upfront|in\s+advance|before)\b|\bpay\s+(?:the\s+)?(?:advance|deposit)\s+first\b"),
     0.50, "advance_fee_request", 0.0),
    (re.compile(r"(?i)\bdon'?t\s+(?:call|phone|verify|tell)\b|\bdo\s+not\s+(?:call|verify|tell)\b|\bonly\s+(?:chat|whatsapp|text)\b"
                r"|\bkeep\s+(?:this|it)\s+(?:confidential|secret|between\s+us)\b|\bcan(?:'|no)t\s+(?:talk|call)\b"),
     0.45, "pressure_to_skip_verification", 0.0),
    (re.compile(r"(?i)\b(?:this\s+is|i\s+am|i'm|im)\s+(?:the\s+|your\s+)?(?:ceo|owner|boss|manager|director|"
                r"accounts?\s+(?:dept|department|team)|supplier|vendor|courier|delivery\s+agent|bank\s+(?:manager|officer))\b"),
     0.30, "authority_or_identity_claim", 0.0),
    (re.compile(r"(?i)\b(?:asap|right\s+now|within\s+\d+\s*(?:min|mins|minutes|hour|hours)|today\s+only|before\s+(?:eod|end\s+of\s+day))\b"),
     0.25, "time_pressure", 0.0),
]
_RECEIPT_LANGUAGE = re.compile(
    r"(?i)\b(?:(?:payment|transaction|transfer|upi|neft|imps|bank)\s+(?:receipt|screenshot|proof|confirmation|slip)"
    r"|receipt|proof\s+of\s+payment|payment\s+slip|i\s+(?:have\s+)?(?:already\s+)?(?:paid|sent|transferred)"
    r"|payment\s+(?:done|completed|successful|sent))\b")


def _noisy_or(values: List[float]) -> float:
    remaining = 1.0
    for v in values:
        remaining *= 1.0 - max(0.0, min(1.0, v))
    return round(1.0 - remaining, 3)


def analyze_chat(
    text: str,
    *,
    sender: Optional[str] = None,
    sender_role: str = "unknown",
    trusted_domains: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Deterministic analysis returning a normalized scan result dict plus chat-specific fields."""
    trusted = {registrable_domain(d.lower().strip().lstrip(".")) for d in (trusted_domains or []) if d.strip()}
    hosts_raw = extract_hosts(text)

    # 1. Existing PhishingAnalyzer (urgency / brand-sender mismatch / URL heuristics)
    base = analyze_phishing(text=text, sender=sender, subject=None, explicit_urls=hosts_raw)
    url_results = base["details"].get("url_analysis", [])
    max_url_all = max([r["score"] for r in url_results], default=0.0)
    # Trusted domains must not be penalised by URL heuristics (e.g. a courier 'portal' path).
    for row in url_results:
        host = row.get("hostname", "")
        if host and registrable_domain(host) in trusted:
            row["flags"], row["score"], row["is_suspicious"] = ["trusted_by_store_owner"], 0.0, False
    max_url_untrusted = max([r["score"] for r in url_results], default=0.0)
    # The analyzer adds 0.55 * (worst URL score); swap that term for the untrusted-URL worst case.
    base_score = max(0.0, min(1.0, round(base["risk_score"] - 0.55 * max_url_all + 0.55 * max_url_untrusted, 3)))

    components: List[float] = [base_score]
    floors: List[float] = []
    findings: List[str] = list(base["findings"])
    keywords: List[str] = list(base["details"].get("urgency_signals", []))
    tactics: List[str] = []
    rule_hits: List[Dict[str, Any]] = []

    # 2. Lookalike domains
    lookalikes: List[LookalikeDomain] = []
    seen_hosts: Set[str] = set()
    for row in url_results:
        host = row.get("hostname", "")
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)
        hit = detect_lookalike(host, trusted)
        if hit:
            lookalikes.append(hit)
    if lookalikes:
        floors.append(0.85)
        components.append(0.85)
        tactics.append("lookalike_domain")
        for hit in lookalikes:
            findings.append(f"Lookalike domain {defang(hit.hostname)} imitates {hit.impersonates} ({hit.technique})")
            keywords.append(defang(hit.hostname))

    # 3. Social-engineering patterns
    for pattern, weight, tactic, floor in _RULES:
        match = pattern.search(text)
        if not match:
            continue
        tactics.append(tactic)
        components.append(weight)
        if floor:
            floors.append(floor)
        phrase = " ".join(match.group(0).lower().split())[:40]
        keywords.append(phrase)
        rule_hits.append({"tactic": tactic, "weight": weight, "hard_rule": bool(floor)})
        findings.append(_TACTIC_FINDINGS[tactic])

    # Fake payment receipt link = receipt language + a link that the owner has not whitelisted
    untrusted_hosts = [r.get("hostname") for r in url_results if r.get("hostname") and registrable_domain(r["hostname"]) not in trusted]
    if untrusted_hosts and _RECEIPT_LANGUAGE.search(text):
        tactics.append("fake_payment_receipt_link")
        components.append(0.75)
        floors.append(0.75)
        keywords.append("payment receipt + link")
        rule_hits.append({"tactic": "fake_payment_receipt_link", "weight": 0.75, "hard_rule": True})
        findings.append(_TACTIC_FINDINGS["fake_payment_receipt_link"])

    # Supplier chats asking for bank changes are the classic BEC opener; make that explicit.
    if sender_role == "vendor" and "supplier_bank_detail_change" in tactics:
        components.append(0.80)
        floors.append(0.80)
        findings.append("Vendor chat requests changed payment details (business email compromise pattern)")

    rule_score = _noisy_or(components)
    floor = max(floors, default=0.0)
    score = round(min(0.99, max(rule_score, floor)), 3)
    deduped_tactics = list(dict.fromkeys(tactics))
    deduped_findings = list(dict.fromkeys(findings))
    deduped_keywords = list(dict.fromkeys(k for k in keywords if k))[:20]

    flagged = score >= FLAG_THRESHOLD
    return {
        "risk_score": score,
        "risk_level": score_to_risk_level(score),
        "flagged": flagged,
        "findings": deduped_findings,
        "details": {
            "rule_score_before_model": score,
            "deterministic_floor": floor,
            "urgency_signals": base["details"].get("urgency_signals", []),
            "brands_detected": base["details"].get("brands_detected", []),
            "sender_flags": base["details"].get("sender_flags", []),
            "url_analysis": url_results,
            "chat_rule_hits": rule_hits,
            "tactics": deduped_tactics,
            "fusion_policy": ("noisy-OR of rule components with a hard-rule floor; "
                              "optional AI can raise risk but never lower it or override a floor"),
        },
        "recommendation": ("Do not click links, share OTP/PIN, or release goods/refunds until the payment is "
                           "visible in YOUR bank or UPI app and the sender is verified on a known number."
                           if flagged else "No high-risk signal detected by the configured checks; still confirm payment in your own bank app."),
        "tactics": deduped_tactics,
        "flagged_keywords": deduped_keywords,
        "lookalikes": lookalikes,
        "floor": floor,
    }


_TACTIC_FINDINGS = {
    "qr_or_collect_request_scam": "Asks you to scan a QR / approve a collect request to 'receive' money (receiving never needs a PIN)",
    "credential_or_otp_request": "Asks for an OTP, PIN, CVV or password",
    "malicious_receipt_attachment": "Receipt/payment file with an executable or app extension (possible malware)",
    "supplier_bank_detail_change": "Requests new or changed bank/payment details",
    "overpayment_refund_scam": "Overpayment / 'send back the difference' pattern",
    "untraceable_payment_method": "Mentions gift cards or crypto as payment",
    "advance_fee_request": "Asks for an advance / token / customs fee first",
    "pressure_to_skip_verification": "Pressures you not to call or verify",
    "authority_or_identity_claim": "Claims to be an owner, supplier, courier or bank official",
    "time_pressure": "Time-pressure wording",
    "fake_payment_receipt_link": "Payment 'receipt/proof' delivered as a link to an unverified site",
}


def defang(hostname: str) -> str:
    return hostname.replace(".", "[.]")


def mask_sender(sender: Optional[str]) -> Optional[str]:
    if not sender:
        return None
    value = sender.strip()
    digits = re.sub(r"\D", "", value)
    if len(digits) >= 7:
        prefix = "+" if value.startswith("+") else ""
        return f"{prefix}{'•' * (len(digits) - 3)}{digits[-3:]}"
    if "@" in value:
        local, _, domain = value.partition("@")
        return f"{local[:1]}•••@{domain}"
    return value[:2] + "•" * max(0, min(len(value) - 2, 6))


_SEVERITY = {RiskLevel.SAFE: "info", RiskLevel.LOW: "info", RiskLevel.MEDIUM: "warning",
             RiskLevel.HIGH: "high", RiskLevel.CRITICAL: "critical"}

_ACTIONS = {
    "lookalike_domain": "Do not open the link or enter payment details: the domain imitates a trusted brand.",
    "fake_payment_receipt_link": "Ignore the 'receipt' link. Confirm the credit inside your own bank/UPI app before shipping anything.",
    "malicious_receipt_attachment": "Do not install or open the attachment; delete it and report the sender.",
    "qr_or_collect_request_scam": "Never scan a QR or approve a collect request to RECEIVE money; receiving never needs a PIN.",
    "credential_or_otp_request": "Never share an OTP, PIN, CVV or password with anyone.",
    "supplier_bank_detail_change": "Call the supplier on a phone number you already have before changing any bank details.",
    "overpayment_refund_scam": "Do not refund any 'extra' amount until the original payment shows in your account.",
    "untraceable_payment_method": "Decline gift-card or crypto payment requests.",
    "advance_fee_request": "Do not pay upfront fees to an unverified party.",
    "pressure_to_skip_verification": "Pressure not to verify is itself a warning sign. Verify through a second channel.",
}


def build_store_owner_alert(
    result: Dict[str, Any], *, channel: ChatChannel, sender: Optional[str],
    store_name: Optional[str], text_fingerprint_source: str,
) -> StoreOwnerAlert:
    level: RiskLevel = result["risk_level"]
    severity = _SEVERITY[level]
    flagged = result["flagged"]
    tactics: List[str] = result.get("tactics", [])
    masked = mask_sender(sender)
    hosts = [defang(h.hostname) for h in result.get("lookalikes", [])]
    channel_name = {"whatsapp": "WhatsApp", "sms": "SMS", "other": "chat"}[channel.value]
    who = f" from {masked}" if masked else ""
    shop = f"[{store_name}] " if store_name else ""

    if flagged:
        title = f"{severity.title()} scam risk in {channel_name} chat"
        headline = f"{shop}Suspicious {channel_name} message{who}. Do not click, pay, or ship yet."
    else:
        title = f"{channel_name} message checked"
        headline = f"{shop}No high-risk signal found in the {channel_name} message{who}."

    actions = [_ACTIONS[t] for t in tactics if t in _ACTIONS]
    if flagged:
        actions.append("Reply only after verifying the sender through a number or channel you already trust.")
        actions.append("Consider blocking and reporting the sender on the platform.")
    else:
        actions.append("Confirm any payment in your own bank/UPI app before releasing goods.")

    do_not = ["Click links or open attachments in this chat", "Share OTP, PIN, card or login details"] if flagged else []
    if "supplier_bank_detail_change" in tactics:
        do_not.append("Update supplier bank details based on a chat message")

    automation = {
        "hold_pending_orders_from_sender": flagged and any(t in tactics for t in (
            "fake_payment_receipt_link", "overpayment_refund_scam", "lookalike_domain", "qr_or_collect_request_scam")),
        "freeze_supplier_payments": "supplier_bank_detail_change" in tactics,
        "suggest_blocking_sender": severity in {"high", "critical"},
        "attach_to_incident_center": flagged,
    }
    urgent = severity in {"high", "critical"}
    sms = f"OmniShield: {severity.upper()} scam risk in {channel_name} chat{who}. Don't click/pay. Verify first."[:160]
    dedupe = hashlib.sha256("|".join([masked or "", ",".join(sorted(tactics)), ",".join(sorted(hosts)),
                                      text_fingerprint_source]).encode()).hexdigest()[:12]
    return StoreOwnerAlert(
        dedupe_key=dedupe,
        severity=severity,  # type: ignore[arg-type]
        requires_immediate_attention=urgent,
        title=title,
        headline=headline,
        channel=channel,
        sender_masked=masked,
        reasons=result["findings"][:6],
        recommended_actions=list(dict.fromkeys(actions)),
        do_not=do_not,
        suggested_automation=automation,
        notification=AlertNotification(
            priority="urgent" if urgent else "normal",
            channels=(["push", "whatsapp", "sms"] if urgent else ["push"]) if flagged else [],
            push_title=title,
            push_body=headline,
            sms_text=sms,
            whatsapp_text=f"*OmniShield alert*\n{headline}\nTop reason: {result['findings'][0] if result['findings'] else 'n/a'}",
        ),
    )
