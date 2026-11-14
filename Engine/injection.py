"""Prompt-injection and hidden-content detection for documents an AI agent reads."""
import re

PHRASES = [
    (r"ignore (?:all |any )?(?:the )?(?:previous|prior|above) (?:instructions|rules|prompts?)", 40, "tries to override earlier instructions"),
    (r"disregard (?:all |any )?(?:the )?(?:previous|prior|above|your)", 40, "tries to override earlier instructions"),
    (r"you are now|new instructions?:|system prompt|developer mode", 30, "tries to re-define the agent's role"),
    (r"send (?:all|every|the entire|your) (?:funds?|balance|money|tokens?|eth)", 45, "asks to move the whole balance"),
    (r"transfer (?:all|everything|the remaining)", 40, "asks to move the whole balance"),
    (r"(?:reveal|share|print|send|reply with|output)\s+(?:your\s+|the\s+)?(?:private key|seed phrase|mnemonic|secret|password|api key)", 50, "tries to extract secrets"),
    (r"do not (?:tell|inform|notify|alert) (?:the )?(?:user|owner|human)", 35, "asks the agent to hide its actions"),
    (r"(?:urgent|immediately|asap|within the hour).{0,60}(?:transfer|pay|send)", 20, "creates pressure to pay quickly"),
    (r"without (?:verification|approval|confirmation|checking)", 25, "asks to skip checks"),
]

HIDDEN = [
    (r"<!--.*?-->", 30, "HTML comment hiding text from humans"),
    (r"font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden", 30, "CSS that hides text from humans"),
    (r"color\s*:\s*(?:#fff(?:fff)?|white)\b", 25, "white-on-white text"),
    (r"[\u200b\u200c\u200d\u2060\ufeff]", 30, "invisible zero-width characters"),
]


def analyze(text: str, strict: bool = False):
    """Returns (score 0-100, list of reasons)."""
    reasons, score = [], 0
    for pattern, pts, why in PHRASES + HIDDEN:
        flags = re.I | re.S
        if re.search(pattern, text, flags):
            score += pts
            reasons.append(why)
    if strict:
        addrs = set(re.findall(r"0x[a-fA-F0-9]{40}", text))
        if len(addrs) >= 2:
            score += 35
            reasons.append("document mentions several different wallet addresses")
        if re.search(r"(?i)(?:new|updated|changed)\s+(?:payout|payment|wallet|bank)", text):
            score += 30
            reasons.append("announces a changed payment destination")
    return min(100, score), sorted(set(reasons))
