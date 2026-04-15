# Security Policy 🛡️

## Our Philosophy
We believe in the power of the community and the principle of **"Polite Defense"**. ShieldWall is designed to learn from attacks, and we apply the same adaptive approach to our own security. If you found a way to bypass our filters, crash the engine, or trick the anomaly detector — you’ve found a way to make the world safer.

## Supported Versions
We only provide security updates for the latest stable release.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | ✅ Yes             |
| < 1.0   | ❌ No              |

## Reporting a Vulnerability or Contributing Rules
**Do not open a Public Issue for security vulnerabilities.** This would be like handing the keys to a $KID before the lock is fixed.

We encourage security researchers and "polite admins" to reach out directly for:
1. **Vulnerability Reports:** Bypasses, engine exploits, or DoS vectors.
2. **Rule Contributions:** If your local heuristic engine (the "shot" mechanism) caught a new pattern, send it to us to make the global community safer.

### Contact Information
* **Email:** [xaosgod@proton.me](mailto:xaosgod@proton.me)
* **Encrypted Communication:** If you prefer, we can exchange PGP keys via email first.

### What to include in your report:
* **For Bypasses:** Include a PoC (Proof of Concept), the specific rule being evaded, and any relevant logs or TLS fingerprints.
* **For New Rules:** Send the YARA-compliant pattern or the raw payload captured by the anomaly engine.
* **For Engine Issues:** Details on how to trigger resource exhaustion or logic flaws in `_generateAutoRule`.

## We are particularly interested in:
* **Bypass techniques:** Methods to evade our YARA rules using unknown encoding or logic flaws.
* **False Positives:** Patterns that block legitimate enterprise traffic.
* **Engine Exploits:** Vulnerabilities in `engine.js` or the auto-generation logic.
* **Resource Exhaustion:** Ways to trigger DoS via the `_generateAutoRule` method.

## Response Pipeline
1.  **Acknowledgement:** We will respond within **24-48 hours**.
2.  **Fix / Integration:** A patch or a new signature will be developed in a private branch.
3.  **Verification:** We may ask you to verify the fix or the effectiveness of the new rule.
4.  **Disclosure:** Once merged and a new version is tagged, we will credit you in the `CHANGELOG`.

## Hall of Fame
Researchers and admins who provide high-quality reports or rules that result in core improvements will be featured in our **Insight Contributors** list.
