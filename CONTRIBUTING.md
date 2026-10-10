# 🤝 Contributing to NexusOSINT

Thank you for your interest in contributing to **NexusOSINT**! As an open-source project, community contributions help keep reconnaissance engines robust, up-to-date, and accurate.

---

## 🚀 How to Contribute

### 1. Reporting Bugs
- Check the [Issues](https://github.com/zaman-topu/nexusosint/issues) page to confirm your problem hasn't already been reported.
- If it hasn't, open a new issue with a clear description, reproduction steps, your Python version, and Termux/Linux environment specs.

### 2. Suggesting Enhancements
- Open a feature request describing the new intelligence vector, API integration, or CLI usability improvement.
- Explain why the feature would benefit the OSINT community.

### 3. Submitting Pull Requests (PRs)
1. **Fork** the repository: `https://github.com/zaman-topu/nexusosint`
2. **Create a branch** for your feature or bug fix:
   ```bash
   git checkout -b feature/new-recon-vector
   ```
3. **Write clean, type-hinted Python code** (PEP 8 compliant, Python 3.10+).
4. **Ensure cross-platform compatibility** with Android Termux (e.g. no reliance on `/etc/resolv.conf` without fallback, pure-Python dependencies).
5. **Commit your changes**:
   ```bash
   git commit -m "feat: add support for new platform in username recon"
   ```
6. **Push to your fork** and submit a **Pull Request**.

---

## 📜 Code Style & Quality Standards
- Preserve modular design under `nexus_osint/modules/`.
- Use the Rich console logging utilities from `nexus_osint.ui` for terminal output.
- All scan modules must return a structured dictionary (`Dict[str, Any]`) so the Case Manager can export it to JSON, Markdown, and text summaries.

---

## 👤 Maintainer
- **Toufique Zaman Topu** ([@zaman-topu](https://github.com/zaman-topu))
