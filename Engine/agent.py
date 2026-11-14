"""A deliberately gullible payment agent (simulation).

It reads an invoice and pays whatever address and amount appear LAST in the text.
That is a simplified stand-in for an LLM agent that follows instructions hidden
in the content it reads. No real model or real money is involved.
"""
import re

INJECTION_HINT = re.compile(r"(?i)ignore|disregard|new instructions|system:|send all|transfer all|"
                            r"payout wallet|updated wallet|going forward|without verification")


def naive_agent(doc: str, balance: float):
    """Returns dict(recipient, amount, fooled) or None if nothing to pay."""
    addrs = re.findall(r"0x[a-fA-F0-9]{40}", doc)
    amounts = re.findall(r"(\d+(?:\.\d+)?)\s*ETH", doc)
    if not addrs:
        return None
    amount = float(amounts[-1]) if amounts else 0.1
    if re.search(r"(?i)send all|transfer (?:all|everything)|entire balance", doc):
        amount = balance
    return {"recipient": addrs[-1], "amount": amount, "fooled": bool(INJECTION_HINT.search(doc))}
