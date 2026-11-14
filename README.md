# Sensite: the last line of defense for AI agents that hold wallets

Hackshastra 2K26 · Cybersecurity & Blockchain · **CB-02 Sensitive Information Detection in Documents**

AI agents that read emails and invoices and then pay can be tricked by one hidden line of text.
Sensite assumes the AI **will** be fooled and adds layers around it.

| Layer | What it does | File |
|---|---|---|
| Red-team agent | Attacks with injections, hidden text, fake invoices, random mutations | `engine/attacks.py` |
| Document scanner | Finds Aadhaar (Verhoeff check), PAN, cards (Luhn), IFSC, UPI, phone, email, salary, API keys, private keys | `engine/detectors.py` |
| Guardian | Detects prompt injection, hidden text, secret-extraction attempts | `engine/injection.py` |
| Policy contract | Allowlist, per-payment limit, daily limit, cooldown. Enforced outside the AI | `engine/policy.py`, `contracts/AgentPolicy.sol` |
| Audit ledger | Hash-chained log plus a trust score | `engine/ledger.py` |

## Run locally
```
pip install -r requirements.txt
streamlit run app.py
```

## Deploy free on Streamlit Community Cloud
1. Upload this whole folder to a new public GitHub repository.
2. Go to share.streamlit.io and sign in with GitHub.
3. Choose New app, pick your repository, set the main file to `app.py`, and press Deploy.

## Demo script (3 minutes)
1. Run **Normal invoice**: paid correctly.
2. Run **Classic injection** with Guardian Off and contract off: the wallet is drained.
3. Switch the Guardian to Standard: blocked.
4. Run **Subtle wallet swap**: the Guardian misses it, the contract refuses. Say: "the AI was fooled, the rules were not."
5. Open **Document scanner** and show the sample KYC form being redacted.
6. Open **Audit ledger**, press Simulate tampering, and show the chain break.

## Honest limits
- The payment agent is a **simulated gullible agent** (rule based), not a real LLM. No API key or real money is involved.
- The ledger is a hash chain inside the app. `contracts/AgentPolicy.sol` is an optional testnet extension and has not been deployed or audited.
- Detection is rule based, so unusual formats can be missed.

## Ideas to extend (if you have time)
Connect a real LLM as the target agent and as the attacker, deploy the contract on Sepolia with Remix, add DOCX support.
