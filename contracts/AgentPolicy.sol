// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Spending rules that live OUTSIDE the AI. Even a fully fooled agent cannot break them.
/// Optional extension: deploy on a testnet (e.g. Sepolia) with Remix. engine/policy.py mirrors this logic.
contract AgentPolicy {
    address public owner;
    address public agent;
    uint256 public maxPerTx;
    uint256 public dailyLimit;
    uint256 public cooldown;
    uint256 public lastTx;
    uint256 public dayStart;
    uint256 public spentToday;
    mapping(address => bool) public allowed;

    event Paid(address indexed to, uint256 amount);
    event Blocked(address indexed to, uint256 amount, string reason);

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    constructor(address _agent, uint256 _maxPerTx, uint256 _dailyLimit, uint256 _cooldown) payable {
        owner = msg.sender;
        agent = _agent;
        maxPerTx = _maxPerTx;
        dailyLimit = _dailyLimit;
        cooldown = _cooldown;
        dayStart = block.timestamp;
    }

    function setAllowed(address a, bool ok) external onlyOwner { allowed[a] = ok; }

    /// The agent calls this instead of sending funds itself. Returns false (and logs why) when blocked.
    function tryPay(address payable to, uint256 amount) external returns (bool) {
        require(msg.sender == agent, "only agent");
        if (block.timestamp >= dayStart + 1 days) { dayStart = block.timestamp; spentToday = 0; }
        if (!allowed[to]) { emit Blocked(to, amount, "recipient not allowlisted"); return false; }
        if (amount > maxPerTx) { emit Blocked(to, amount, "above per-payment limit"); return false; }
        if (spentToday + amount > dailyLimit) { emit Blocked(to, amount, "above daily limit"); return false; }
        if (block.timestamp < lastTx + cooldown) { emit Blocked(to, amount, "cooldown active"); return false; }
        if (address(this).balance < amount) { emit Blocked(to, amount, "insufficient balance"); return false; }
        spentToday += amount;
        lastTx = block.timestamp;
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "transfer failed");
        emit Paid(to, amount);
        return true;
    }

    receive() external payable {}
}
