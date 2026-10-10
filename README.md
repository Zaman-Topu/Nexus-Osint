<div align="center">

# ⚡ NexusOSINT

### *Next-Gen Modular Open-Source Intelligence & Autonomous Chained Reconnaissance Suite*

[![GitHub Release](https://img.shields.io/badge/release-v2.0.0-0ea5e9?style=for-the-badge&logo=github)](https://github.com/zaman-topu/nexusosint)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-10b981?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Termux%20%7C%20Linux-f59e0b?style=for-the-badge&logo=linux&logoColor=white)](https://termux.dev)
[![API Keys Required](https://img.shields.io/badge/API%20Keys-Zero%20Required-8b5cf6?style=for-the-badge&logo=shield)](README.md)
[![Maintained By](https://img.shields.io/badge/Maintainer-zaman--topu-ec4899?style=for-the-badge&logo=github)](https://github.com/zaman-topu)

<p align="center">
  <b>A unified, high-speed OSINT framework engineered for Termux (Android) and Linux.</b><br>
  Execute deep reconnaissance across 10 specialized intelligence modules with autonomous cross-vector pivoting, interactive HTML network graphs, and automated dedicated case investigations.
</p>

---

[🚀 Quick Start](#-quick-start) •
[🌟 Intelligence Matrix](#-intelligence-matrix) •
[💻 CLI Usage](#-cli-usage--command-cheatsheet) •
[📁 Case Manager](#-automated-case-folder-architecture) •
[🌐 Graph Visualizer](#-interactive-network-graph-visualizer) •
[🛡️ Security](#-security--opsec) •
[👤 Credits](#-author--credits)

</div>

---

## 🧭 Architecture Overview

```
                          ┌──────────────────────────┐
                          │   NEXUSOSINT CLI ENGINE   │
                          │   (nexusosint <cmd> <tgt>)│
                          └─────────────┬────────────┘
                                        │
           ┌────────────────────────────┼───────────────────────────┐
           ▼                            ▼                           ▼
 ┌──────────────────┐         ┌──────────────────┐        ┌──────────────────┐
 │ IDENTITIES & ACC │         │ NETWORK & THREAT │        │ INFRA & ASSETS   │
 ├──────────────────┤         ├──────────────────┤        ├──────────────────┤
 │ • Username Recon │         │ • IP Geolocation │        │ • Domain Recon   │
 │ • GitHub Deep    │         │ • Shodan Ports   │        │ • Cloud Buckets  │
 │ • Email Intel    │         │ • Reverse DNS    │        │ • Passive URLs   │
 │ • Phone Carrier  │         │ • CVE Detection  │        │ • EXIF GPS       │
 └─────────┬────────┘         └─────────┬────────┘        └─────────┬────────┘
           │                            │                           │
           └────────────────────────────┼───────────────────────────┘
                                        ▼
                       ┌─────────────────────────────────┐
                       │   AUTONOMOUS DOSSIER ENGINE     │
                       │   (Chained Pivot & Correlation) │
                       └────────────────┬────────────────┘
                                        │
                                        ▼
             ┌─────────────────────────────────────────────────────┐
             │       DEDICATED CASE FOLDER (results/target_*)      │
             ├───────────────────┬─────────────────────────────────┤
             │ 📄 report.md      │ Executive Markdown Dossier      │
             │ 🗃️ data.json      │ Structured Raw Intelligence     │
             │ 📝 summary.txt    │ Instant Terminal Overview       │
             │ 🌐 visual_graph.html│ Vis.js Interactive Topology   │
             └───────────────────┴─────────────────────────────────┘
```

---

## 🌟 Intelligence Matrix

NexusOSINT provides complete multi-vector reconnaissance across **10 native modules** plus the autonomous **Master Dossier Chaining Engine**:

| Vector | Command | Description | Zero API Key? |
|---|---|---|:---:|
| 🎯 **Master Dossier** | `nexusosint all <seed>` | Autonomous auto-pivot across Email, Username, Domain, IP, and Phone. Chains discoveries and compiles full dossiers with interactive entity graphs. | :white_check_mark: |
| 📍 **IP Intelligence** | `nexusosint ip <ip>` | Country flags, city, state, postal code, GPS coordinates, Google Maps links, ASN, ISP, organization, timezone, and PTR reverse DNS. | :white_check_mark: |
| 🌐 **Domain Recon** | `nexusosint domain <domain>` | Full DNS query (`A`, `AAAA`, `MX`, `NS`, `TXT`, `SOA`), RDAP registrar query, server profile & security headers audit (`HSTS`, `CSP`, etc.), plus subdomain discovery. | :white_check_mark: |
| 👤 **Username Recon** | `nexusosint user <handle>` | Asynchronously scans 50+ websites & social networks (GitHub, GitLab, Steam, Reddit, Keybase, etc.) with rate-limiting and progress tracking. | :white_check_mark: |
| ✉️ **Email Intelligence** | `nexusosint email <email>` | RFC syntax validation, disposable/temporary email provider check, active MX record verification, SPF/DMARC checks, and Gravatar identity pivoting. | :white_check_mark: |
| 📞 **Phone Intelligence** | `nexusosint phone <number>` | E.164 formatting, carrier/operator lookup, geographic region, timezone, and line classification (Mobile, VoIP, Landline). | :white_check_mark: |
| 🐙 **GitHub Deep Recon** | `nexusosint github <user>` | User profile extraction, public SSH keys (`.keys`), GPG keys, and commit patch scraping to uncover commit author emails. | :white_check_mark: |
| 🛡️ **Shodan Threat Recon** | `nexusosint shodan <ip>` | Queries Shodan InternetDB for open ports, running banners, CPEs, and unpatched CVE vulnerabilities. | :white_check_mark: |
| ☁️ **Cloud Bucket Hunter** | `nexusosint cloud <keyword>` | Probes permutation names across AWS S3, Google Cloud Storage, and Azure Blob Storage for exposed buckets (200 OK / 403 Forbidden). | :white_check_mark: |
| 🕷️ **Passive URLs Recon** | `nexusosint urls <domain>` | Queries AlienVault OTX passive telemetry for historical URLs, indexing sensitive paths (`.env`, `.git`, `.sql`, `admin`, `api`, `tokens`). | :white_check_mark: |
| 📸 **Image EXIF Forensics** | `nexusosint exif <image>` | Extracts hardware/camera metadata and converts embedded GPS coordinates into clickable Google Maps and OpenStreetMap links. | :white_check_mark: |
| 📁 **Case Manager** | `nexusosint cases` | Browse and view all stored target case folders, summaries, reports, and interactive graphs. | :white_check_mark: |

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/zaman-topu/nexusosint.git
cd nexusosint

# Install pure-Python dependencies
pip install -r requirements.txt

# (Optional) Install as global CLI tool
pip install -e .
```

> [!TIP]
> In Termux (Android), you can run `nexusosint` directly from **any terminal folder** after installation!

---

## 💻 CLI Usage & Command Cheatsheet

NexusOSINT features a unified, intuitive command interface:

```bash
nexusosint <command> <target> [options]
```

### 🎯 Primary Reconnaissance Commands
```bash
# 🎯 Run Autonomous Master Dossier on ANY target seed:
nexusosint all 1.1.1.1
nexusosint all example.com
nexusosint all torvalds
nexusosint all target@example.com

# 📍 IP Geolocation & ASN Intelligence:
nexusosint ip 8.8.8.8

# 🌐 Domain Reconnaissance & Subdomains:
nexusosint domain github.com

# 👤 Username Scan across 50+ platforms:
nexusosint user admin

# ✉️ Email Intelligence & Gravatar Pivot:
nexusosint email target@example.com

# 📞 Phone Carrier & Location:
nexusosint phone +14155552671

# 🐙 Deep GitHub Recon (Commit emails & SSH keys):
nexusosint github torvalds

# 🛡️ Shodan InternetDB Ports & CVE Vulnerabilities:
nexusosint shodan 1.1.1.1

# ☁️ Cloud Storage Bucket Hunter (AWS, GCP, Azure):
nexusosint cloud acme_corp

# 🕷️ Historical Archive URLs & Sensitive Endpoints:
nexusosint urls example.com

# 📸 Image EXIF Camera & GPS Forensics:
nexusosint exif /path/to/photo.jpg

# 📁 View All Saved Investigation Case Folders:
nexusosint cases

# 🖥️ Launch Interactive Terminal Menu:
nexusosint menu
# or simply execute without arguments:
nexusosint
```

### ⚙️ Available Options & Flags

| Flag | Long Flag | Description | Default |
|---|---|---|:---:|
| `-o` | `--output-dir` | Custom destination folder for case results | `results/` |
| `-t` | `--timeout` | Network request timeout in seconds | `6.0` |
| `-c` | `--concurrency` | Concurrent worker count for async routines | `15` |
| | `--no-banner` | Suppress ASCII banner for clean output | `False` |
| | `--no-save` | Display findings on-screen only (skip writing files) | `False` |
| `-h` | `--help` | Display comprehensive help documentation | |

---

## 📁 Automated Case Folder Architecture

Every scan executed through NexusOSINT **automatically creates an isolated investigation directory** inside [`results/`](results/) labeled by target, scan mode, and timestamp:

```text
results/1.1.1.1_all_20261010_080808/
├── 📄 report.md        # Comprehensive Markdown Dossier
├── 🗃️ data.json        # Structured Findings (Machine-readable JSON)
├── 📝 summary.txt      # Terminal-Friendly Quick Summary
└── 🌐 visual_graph.html # Interactive Vis.js Network Graph
```

### ⚡ Quick View Workflow
```bash
# Instant terminal inspection:
cat results/1.1.1.1_all_20261010_080808/summary.txt

# Or browse past cases through the CLI:
nexusosint cases
```

---

## 🌐 Interactive Network Graph Visualizer

When executing `nexusosint all <target>`, NexusOSINT compiles all correlated entities into a standalone interactive HTML graph rendered via **Vis.js**:

- **Physics-Based Force Simulation:** Nodes self-organize with smooth collision and spring dynamics.
- **Draggable & Zoomable Canvas:** Pan, zoom, and inspect relationships across clusters.
- **Color-Coded Legend:**
  - 🟡 **Yellow:** Target Seed
  - 🔵 **Cyan:** Online Handles & Identities
  - 🟢 **Green:** Discovered Social Profiles & Phone
  - 🔷 **Blue:** Domains, Subdomains & Reverse DNS
  - 🟠 **Orange:** IP Addresses
  - 🔴 **Red:** Open Ports & Vulnerabilities (CVEs)
  - 🟣 **Purple:** Cloud Storage Assets
- **Zero Local Server Required:** Open the generated `visual_graph.html` directly in Chrome, Firefox, Safari, or mobile browsers via `file:///path/to/visual_graph.html`.

---

## 📱 Termux / Android Optimization

In Android Termux environments, `/etc/resolv.conf` does not exist by default, which causes standard DNS lookups in many tools to fail.

NexusOSINT includes a custom DNS Resolver engine ([`resolver.py`](nexus_osint/resolver.py)) that automatically falls back to hardened public DNS providers (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`), ensuring 100% reliable name resolution on mobile devices without root privileges.

---

## 🛡️ Security & OPSEC

Please review our [SECURITY.md](SECURITY.md) for information regarding vulnerability reporting, supported versions, and operational security recommendations.

> [!IMPORTANT]
> NexusOSINT is developed strictly for authorized security assessments, defensive telemetry, digital investigations, and open-source intelligence research. Always obtain authorization before evaluating third-party infrastructure.

---

## 🤝 Contributing

Contributions from the open-source security community are warmly welcomed! Please check our [CONTRIBUTING.md](CONTRIBUTING.md) for pull request guidelines, coding standards, and issue reporting.

---

## 👤 Author & Credits

<div align="center">

Developed and maintained with ❤️ by:

### **Toufique Zaman Topu**
**GitHub:** [@zaman-topu](https://github.com/zaman-topu)

[![Follow on GitHub](https://img.shields.io/github/followers/zaman-topu?label=Follow%20%40zaman--topu&style=social)](https://github.com/zaman-topu)

*Special thanks to the global OSINT community and open-source intelligence maintainers.*

</div>

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for complete details.

<div align="center">
  <sub>NexusOSINT © 2026 Toufique Zaman Topu (zaman-topu). All rights reserved.</sub>
</div>
