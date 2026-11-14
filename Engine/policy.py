"""Python mirror of AgentPolicy.sol.

The rules live outside the AI, so even a fully fooled agent cannot break them.
"""
import time
from dataclasses import dataclass, field


@dataclass
class Policy:
    max_per_tx: float = 0.5
    daily_limit: float = 1.0
    cooldown_s: int = 0
    allowlist: list = field(default_factory=lambda: [
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        "0x3333333333333333333333333333333333333333",
    ])
    spent_today: float = 0.0
    last_tx_time: float = 0.0

    def check(self, recipient: str, amount: float):
        """Returns (allowed, reason)."""
        if recipient.lower() not in [a.lower() for a in self.allowlist]:
            return False, "recipient is not on the allowlist"
        if amount > self.max_per_tx:
            return False, f"amount {amount} ETH is above the per-payment limit of {self.max_per_tx} ETH"
        if self.spent_today + amount > self.daily_limit:
            return False, f"would pass the daily limit of {self.daily_limit} ETH"
        if self.cooldown_s and time.time() - self.last_tx_time < self.cooldown_s:
            return False, "cooldown between payments has not finished"
        return True, "within all spending rules"

    def record(self, amount: float):
        self.spent_today += amount
        self.last_tx_time = time.time()
