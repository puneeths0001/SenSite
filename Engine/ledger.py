"""Hash-chained audit log and trust score.

Each entry stores the hash of the previous entry, so changing any old record
breaks every hash after it. This is the same idea a blockchain uses.
"""
import hashlib
import json
import time

GENESIS = "0" * 64


def _hash(prev: str, body: dict) -> str:
    return hashlib.sha256((prev + json.dumps(body, sort_keys=True)).encode()).hexdigest()


def add_entry(chain: list, body: dict) -> dict:
    prev = chain[-1]["hash"] if chain else GENESIS
    body = {**body, "time": time.strftime("%H:%M:%S")}
    entry = {"index": len(chain), "prev": prev, "body": body, "hash": _hash(prev, body)}
    chain.append(entry)
    return entry


def verify(chain: list):
    """Returns (ok, index of first broken entry or None)."""
    prev = GENESIS
    for i, e in enumerate(chain):
        if e["prev"] != prev or e["hash"] != _hash(prev, e["body"]):
            return False, i
        prev = e["hash"]
    return True, None


def trust_score(chain: list) -> int:
    """0-100. Stopped by Guardian = full credit, saved only by the contract = partial,
    funds lost = zero. Good invoices paid = full, good invoices blocked = half."""
    if not chain:
        return 50
    pts = []
    for e in chain:
        b = e["body"]
        o, mal = b["outcome"], b["malicious"]
        if o == "guardian_block":
            pts.append(1.0 if mal else 0.5)
        elif o == "contract_block":
            pts.append(0.6 if mal else 0.5)
        elif o == "paid":
            pts.append(0.0 if mal else 1.0)
        else:
            pts.append(1.0)
    return round(100 * sum(pts) / len(pts))
