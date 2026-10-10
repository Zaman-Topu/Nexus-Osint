# 🛡️ Security Policy

NexusOSINT is an open-source reconnaissance and intelligence gathering framework designed for defensive security assessments, penetration testing, and digital investigations.

We take the security of this project and its users seriously. If you discover a security vulnerability within NexusOSINT, please follow the guidelines below to report it responsibly.

---

## 📦 Supported Versions

Only the latest release and the current `main` branch receive active security updates:

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0.0 | :x:                |

---

## 🚨 Reporting a Vulnerability

If you believe you have discovered a vulnerability (such as remote code execution, uncontrolled command injection, unintended credential leakage, or unsafe deserialization):

1. **Do NOT open a public GitHub issue** for undisclosed security vulnerabilities.
2. Please open a confidential report via **GitHub Security Advisories**:
   - Go to the repository's **Security** tab.
   - Click on **Report a vulnerability**.
3. Alternatively, contact the maintainer directly:
   - **GitHub Profile:** [@zaman-topu](https://github.com/zaman-topu)
   - **Subject Line:** `[SECURITY] NexusOSINT Vulnerability Report`

### What to Include in Your Report:
- A clear description of the vulnerability and its potential impact.
- Step-by-step instructions or a safe Proof-of-Concept (PoC) to reproduce the behavior.
- Affected operating system, Python version, and dependency versions.
- Any suggested remediation or patch, if available.

### Disclosure Timeline:
- **Initial Response:** Within 48 hours of receipt.
- **Triage & Assessment:** Within 5 business days.
- **Fix & Public Advisory:** Coordinated release once a patch is tested and verified.

---

## 🔒 Operational Security (OPSEC) Guidance for Users

- **Target Authorization:** Always verify that you possess authorized permission or legitimate defensive intelligence mandates before conducting queries on external infrastructures.
- **API Keys & Secrets:** NexusOSINT modules operate without requiring paid API keys by default. Never commit hardcoded personal credentials or internal target tokens into public repositories.
- **Safe Outputs:** Ensure you review the contents of generated `results/` folders prior to publishing or distributing reports, as they may contain sensitive IP addresses, DNS hostnames, or personal profiles.
