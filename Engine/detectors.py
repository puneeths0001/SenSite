"""Sensitive-information detection (problem statement CB-02).

Every detector is rule based, so the project runs with no API key.
Where a number has a checksum (Aadhaar, cards) we validate it, which removes
most false positives.
"""
import re
from dataclasses import dataclass

# ---------- checksum helpers ----------
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_valid(num: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(num: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])


def luhn_valid(num: str) -> bool:
    total, alt = 0, False
    for ch in reversed(num):
        n = int(ch)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


# ---------- detectors ----------
@dataclass
class Finding:
    kind: str
    label: str
    start: int
    end: int
    text: str
    severity: str  # high / medium / low
    reason: str


def _digits(s):
    return re.sub(r"\D", "", s)


# (kind, label, regex, severity, validator or None, reason)
RULES = [
    ("private_key", "Crypto private key", r"\b(?:0x)?[a-fA-F0-9]{64}\b", "high", None,
     "64 hex characters look like a wallet private key"),
    ("api_key", "API key / secret", r"\b(?:sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,})\b", "high", None,
     "matches a known secret-key format"),
    ("aadhaar", "Aadhaar number", r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b", "high",
     lambda s: verhoeff_valid(_digits(s)), "12 digits and passes the Verhoeff checksum"),
    ("card", "Credit / debit card", r"\b\d(?:[ -]?\d){12,18}\b", "high",
     lambda s: 13 <= len(_digits(s)) <= 19 and luhn_valid(_digits(s)), "passes the Luhn card checksum"),
    ("pan", "PAN card", r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", "high", None, "matches the PAN format AAAAA9999A"),
    ("passport", "Passport number", r"\b[A-PR-WY][1-9]\d{6}\b", "medium", None, "matches the Indian passport format"),
    ("ifsc", "Bank IFSC code", r"\b[A-Z]{4}0[A-Z0-9]{6}\b", "medium", None, "matches the IFSC format"),
    ("account", "Bank account number", r"(?i)(?:a/c|acc(?:ount)?)(?:\s*(?:no|number|#))?\.?\s*[:\-]?\s*(\d{9,18})", "high",
     None, "number labelled as a bank account"),
    ("upi", "UPI ID", r"\b[\w.\-]{2,}@(?:ybl|okaxis|oksbi|okhdfcbank|paytm|upi|ibl|axl|apl)\b", "medium", None,
     "matches a UPI handle"),
    ("email", "Email address", r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", "low", None, "email address (personal data)"),
    ("phone", "Phone number", r"(?<!\d)(?:\+91[ -]?)?[6-9]\d{9}(?!\d)", "medium", None, "Indian mobile number"),
    ("salary", "Salary / income", r"(?i)(?:salary|ctc|income)\s*(?:is|of|:)?\s*(?:rs\.?|inr|₹)?\s*[\d,.]+\s*(?:lpa|lakhs?|k|per\s*(?:month|annum))?",
     "medium", None, "income information"),
    ("wallet", "Wallet address", r"\b0x[a-fA-F0-9]{40}\b", "low", None, "public wallet address (check who it belongs to)"),
]

PRIORITY = {"private_key": 0, "api_key": 1, "aadhaar": 2, "card": 3, "pan": 4, "account": 5, "upi": 6,
            "passport": 7, "ifsc": 8, "phone": 9, "salary": 10, "email": 11, "wallet": 12}


def scan(text: str):
    found = []
    for kind, label, pattern, sev, validator, reason in RULES:
        for m in re.finditer(pattern, text):
            span = m.group(1) if (kind == "account" and m.groups()) else m.group(0)
            start = m.start(1) if (kind == "account" and m.groups()) else m.start()
            if validator and not validator(span):
                continue
            found.append(Finding(kind, label, start, start + len(span), span, sev, reason))
    # resolve overlaps: keep the higher priority, then the longer match
    found.sort(key=lambda f: (PRIORITY[f.kind], -(f.end - f.start)))
    kept = []
    for f in found:
        if all(f.end <= k.start or f.start >= k.end for k in kept):
            kept.append(f)
    return sorted(kept, key=lambda f: f.start)


def risk_score(findings) -> int:
    weight = {"high": 25, "medium": 10, "low": 3}
    return min(100, sum(weight[f.severity] for f in findings))


def redact(text: str, findings, mode: str = "tag") -> str:
    out, last = [], 0
    for f in findings:
        out.append(text[last:f.start])
        if mode == "mask":
            keep = f.text[-4:] if len(f.text) > 8 else ""
            out.append("█" * (len(f.text) - len(keep)) + keep)
        else:
            out.append(f"[{f.label.upper()}]")
        last = f.end
    out.append(text[last:])
    return "".join(out)
