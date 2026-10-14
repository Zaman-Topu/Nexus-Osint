<div align="center">

# ⚡ NexusOSINT v2.0.0

### *Advanced Modular Open-Source Intelligence (OSINT) & Autonomous Threat Intelligence Framework*

[![GitHub Release](https://img.shields.io/badge/release-v2.0.0-0ea5e9?style=for-the-badge&logo=github)](https://github.com/Zaman-Topu/Nexus-Osint)
[![Tests](https://img.shields.io/badge/tests-69%20passed-10b981?style=for-the-badge&logo=pytest&logoColor=white)](tests/)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-10b981?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Termux%20(Android)%20%7C%20Linux-f59e0b?style=for-the-badge&logo=linux&logoColor=white)](https://termux.dev)
[![API Keys Required](https://img.shields.io/badge/API%20Keys-Zero%20Required%20(100%25%20Free)-8b5cf6?style=for-the-badge&logo=shield)](README.md)
[![Maintained By](https://img.shields.io/badge/Maintainer-zaman--topu-ec4899?style=for-the-badge&logo=github)](https://github.com/Zaman-Topu)

<p align="center">
  <b>A blazing-fast, unified cyber reconnaissance and digital forensics suite engineered natively for Linux and Android Termux.</b><br>
  Conduct comprehensive multi-vector investigations across <b>19 specialized intelligence modules</b> with zero paid API keys, automated multi-hop pivoting, interactive HTML entity graphs, and organized per-target case management.
</p>

---

[🚀 Quick Installation](#-quick-installation) •
[🌟 Intelligence Capabilities](#-intelligence-capabilities) •
[💻 CLI Cheatsheet](#-cli-command-cheatsheet) •
[🔍 Honest Tool Comparison](#-honest-architectural-comparison--scope) •
[🧠 Autonomous Dossier](#-autonomous-master-dossier) •
[📁 Case Manager](#-automated-case-folder-architecture) •
[🌐 Network Graph](#-interactive-visjs-network-graph) •
[📱 Termux Setup](#-termux--android-native-readiness) •
[🛡️ OPSEC & Security](#-security--opsec) •
[👤 Author](#-author--maintainer)

</div>

---

## 🔍 Honest Architectural Comparison & Scope

Different OSINT utilities are designed for different scopes, environments, and threat models. Rather than making exaggerated marketing claims, here is an objective, honest comparison of where NexusOSINT fits compared to other popular tools in the ecosystem:

| Dimension / Capability | NexusOSINT v2.0.0 | SpiderFoot | theHarvester | Sherlock / Maigret | Subfinder / Amass |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Primary Scope** | **All-in-One Field Recon & Pivoting** | Enterprise Surface Automation | Passive Search Harvesting | Username Account Hunting | High-Speed Subdomain Enumeration |
| **Out-of-the-Box Zero Key Experience** | **100% Zero-Key** (All 19 modules run free) | ⚠️ Partial (core free, ~150 modules need API keys) | ⚠️ Partial (free search engines, many require keys) | ✅ 100% Free (HTTP response parsing) | ⚠️ Partial (passive DNS free, deep scans need keys) |
| **Platform Target** | **Linux & Android Termux Native** | Desktop / Server / Web UI | Kali Linux / Terminal CLI | Terminal CLI | Go Binary / Kali Linux |
| **Pure Python / Zero C-Compiler** | ✅ Pure Python (Zero binary extensions) | ⚠️ Heavy pip deps & binary wheels | ✅ Pure Python | ✅ Pure Python | ❌ Go Runtime Required |
| **Mobile / Termux DNS Resilience** | ✅ Custom fallback resolver (`1.1.1.1`, `8.8.8.8`) | ❌ Fails on missing `/etc/resolv.conf` | ❌ Depends on OS libc resolver | ⚠️ Basic HTTP | ❌ Requires Go / PRoot environment |
| **Cross-Vector Autonomous Pivoting** | ✅ Built-in chained dossier engine | ⚠️ Advanced (requires web UI config) | ❌ Manual re-entry | ❌ Username only | ❌ Subdomains only |
| **Coverage Scale per Vector** | Curated 75+ accounts, 3 passive DNS sources | Massive (200+ modular sources) | Broad search engine aggregation | Deep (Sherlock: 400+, Maigret: 3000+) | Deepest (100+ DNS providers & APIs) |
| **Infostealer Malware Telemetry** | ✅ Hudson Rock Cavalier API | ❌ Not native | ❌ Not native | ❌ Not native | ❌ Not native |
| **Dangling CNAME Takeovers** | ✅ 10+ cloud signatures verified | ⚠️ Basic checks | ❌ Not native | ❌ Not native | ⚠️ (Requires subjack / nuclei) |
| **Case Directories & Graph Export** | ✅ Markdown, JSON, Text & Vis.js Graph | ✅ Web UI & Graph export | ❌ Text / HTML export | ❌ CSV / JSON only | ❌ Text / JSON stream |

### ⚖️ When to Use Other Tools vs. NexusOSINT
- **Need exhaustive search across 3,000+ niche forums?** Use [Maigret](https://github.com/soxoj/maigret) or [Sherlock](https://github.com/sherlock-project/sherlock). NexusOSINT checks a curated set of ~75+ major developer, social, and messaging platforms to keep mobile scans fast, lightweight, and responsive.
- **Need enterprise-scale correlation across hundreds of commercial threat feeds?** Use [SpiderFoot](https://github.com/smicallef/spiderfoot). NexusOSINT is a lightweight, zero-key field utility designed for instant deployment on laptops or Termux without running a web server daemon or database backend.
- **Need high-throughput Go-based subdomain brute-forcing?** Use [Subfinder](https://github.com/projectdiscovery/subfinder) or [OWASP Amass](https://github.com/owasp-amass/amass). NexusOSINT aggregates crt.sh, HackerTarget, and AlienVault OTX passively in pure Python without requiring Go compiler toolchains.
- **Need deep banner and historical IP vulnerability queries?** Use the official paid Shodan API. NexusOSINT queries the unauthenticated free Shodan InternetDB to detect open ports and documented CVEs without requiring an API key.

---

## 🧭 System Architecture & Workflow

```
                                  ┌──────────────────────────┐
                                  │   NEXUSOSINT CLI ENGINE   │
                                  │   (nexusosint <cmd> <tgt>)│
                                  └─────────────┬────────────┘
                                                │
                 ┌──────────────────────────────┼──────────────────────────────┐
                 ▼                              ▼                              ▼
       ┌──────────────────┐           ┌──────────────────┐           ┌──────────────────┐
       │ IDENTITIES & ACC │           │ NETWORK & THREAT │           │ INFRA & ASSETS   │
       ├──────────────────┤           ├──────────────────┤           ├──────────────────┤
       │ • Username (75+) │           │ • IP Geolocation │           │ • Domain & DNS   │
       │ • GitHub Deep    │           │ • Shodan Ports   │           │ • Passive Subs   │
       │ • Email Breaches │           │ • Reverse DNS    │           │ • Cloud Buckets  │
       │ • Phone Carrier  │           │ • Infostealers   │           │ • Takeover Audit │
       │ • EXIF Forensics │           │ • SPF/DMARC Risk │           │ • Passive URLs   │
       │ • Telegram Intel │           │ • SSL/TLS Certs  │           │ • Wayback Travel │
       │ • Reverse Image  │           │ • MAC / OUI HW   │           │ • Dark Web Tor66 │
       │                  │           │                  │           │ • Search Dorking │
       └─────────┬────────┘           └─────────┬────────┘           └─────────┬────────┘
                 │                              │                              │
                 └──────────────────────────────┼──────────────────────────────┘
                                                ▼
                             ┌─────────────────────────────────────┐
                             │      AUTONOMOUS DOSSIER ENGINE      │
                             │    (Cross-Vector Entity Pivoting)   │
                             └──────────────────┬──────────────────┘
                                                │
                                                ▼
                   ┌─────────────────────────────────────────────────────┐
                   │       DEDICATED CASE FOLDER (results/target_*)      │
                   ├───────────────────┬─────────────────────────────────┤
                   │ 📄 report.md      │ Executive Markdown Dossier      │
                   │ 🗃️ data.json      │ Machine-Readable Structured JSON│
                   │ 📝 summary.txt    │ Terminal Instant Overview       │
                   │ 🌐 visual_graph.html│ Vis.js Interactive Topology   │
                   └───────────────────┴─────────────────────────────────┘
```

---

## 🌟 Intelligence Capabilities

NexusOSINT v2.0.0 bundles **19 specialized intelligence vectors** running completely free and unauthenticated:

### 1. 🛡️ Infostealer Malware Threat Intelligence (`stealer`)
- **Hudson Rock Cavalier Telemetry**: Queries public zero-key infostealer breach telemetry to identify devices and corporate organizations infected with malware (RedLine, Lumma, Vidar, Raccoon, META, etc.).
- **Corporate Exposure Index**: Pinpoints compromised employee credentials, third-party contractor breaches, and leaked user credentials across your target corporate domain.
- **Email Infection Detection**: Detects specific infected computers that held target credentials in browser vaults or credential managers.

### 2. 🌐 Multi-Source Passive Subdomain Discovery (`domain`)
- **Tri-Source Passive Aggregation**: Simultaneously queries **Certificate Transparency Logs (crt.sh)**, **HackerTarget Passive DNS**, and **AlienVault OTX** in parallel with strict async timeouts.
- **Active Resolution**: Resolves discovered candidates into active IPv4 addresses and validates live hosts.

### 3. 🎯 Dangling CNAME Subdomain Takeover Auditor (`domain`, `takeover`)
- **Multi-Hop CNAME Traversal**: Follows up to 5 hops of DNS CNAME delegations, detecting circular loops and dangling records.
- **Cloud Signature Fingerprinting**: Detects unclaimed cloud resources across **AWS S3**, **GitHub Pages**, **Heroku**, **Shopify**, **Microsoft Azure**, **Fastly CDN**, **Fly.io**, **Vercel**, **Firebase Hosting**, and **ReadTheDocs**.
- **Live Response Validation**: Verifies cloud 404 / `NoSuchBucket` / unclaimed project signatures to eliminate false positives.

### 4. ✉️ Email Spoofing & Security Posture (`email`, `domain`)
- **SPF Mechanism Parser**: Inspects `v=spf1` policies, tracking mechanisms (`ip4`, `include`, `redirect`), and evaluates the enforcement qualifier (`-all` Hardfail vs `~all` Softfail vs `?all` Neutral).
- **DMARC Evaluator**: Verifies `p=reject`, `p=quarantine`, or `p=none` policies alongside alignment parameters (`aspf`, `adkim`).
- **Spoofability Rating**: Generates an actionable risk verdict (**Low Risk / Hardened**, **Medium Risk / Weak**, or **CRITICAL / Easily Spoofable**).

### 5. 🎨 Pure-Python Favicon MurmurHash3 Shodan Dorking (`domain`)
- **Zero-Binary MurmurHash3**: Custom pure-Python 32-bit x86 MurmurHash3 implementation matching Shodan's exact hashing specification without requiring C-compiler dependencies (`mmh3`).
- **One-Click Shodan Dorks**: Outputs direct Shodan queries (`http.favicon.hash:<hash>`) to locate backend origin servers hiding behind Cloudflare/CDNs.

### 6. 📞 Global Phone & Carrier Intelligence (`phone`)
- **Dynamic International Prefixing**: Automatically handles raw national inputs, international prefix notations (`+`, `00`), and Bangladesh domestic prefixes (`013`–`019`, `880`).
- **Detailed Carrier Telemetry**: Identifies network operator (Robi, Grameenphone, Banglalink, AT&T, Verizon, etc.), line classification (Mobile, Fixed Line, VoIP), geographic region, and timezones.

### 7. 👤 Deep Username Footprinting (`user`)
- Asynchronously interrogates 75+ high-traffic developer portals, social networks, gaming communities, and code repositories (GitHub, GitLab, Reddit, Keybase, Steam, Telegram, etc.) with concurrency control.

### 8. 🐙 GitHub Deep Forensics (`github`)
- Profile extraction, bio metadata, public SSH keys (`.keys`), GPG keys, and commit-level patch scraping to harvest hidden author email addresses from public activity.

### 9. 📍 IP Geolocation & ASN Mapping (`ip`)
- High-precision country flag, city, state, postal code, GPS coordinates, Google Maps navigation links, ASN designation, ISP name, and PTR reverse DNS.

### 10. 🛡️ Shodan InternetDB Threat Intelligence (`shodan`)
- Fast zero-key scanning of open ports, software banners, CPE identifiers, and documented unpatched CVE vulnerabilities.

### 11. ☁️ Multi-Cloud Storage Hunter (`cloud`)
- Probes permutations against Amazon AWS S3, Google Cloud Storage, and Azure Blob containers to discover public or protected storage buckets.

### 12. 📸 Image EXIF Metadata & Geolocation (`exif`)
- Extracts camera make/model, shutter/lens parameters, software version, original capture timestamps, and translates GPS coordinates into direct Google Maps / OpenStreetMap hyperlinks.

### 13. 🧅 Dark Web & Tor Hidden Service Intelligence (`darkweb`, `onion`)
- **Tor66 Hidden Service Discovery**: Interrogates the Tor66 darknet index to locate active `.onion` services tied to target domains, usernames, or organizations.
- **Clearnet Tor2web Mirror Resolution**: Converts discovered `.onion` addresses into direct `.onion.pet` clearnet gateway links, allowing mobile Android/Termux inspection without requiring a running Tor daemon.
- **Paste Dump & Gateway Crawling**: Automatically correlates public breach leaks across Pastebin, Rentry, JustPasteIt, and darknet gateways.

### 14. 🔍 Multi-Search Engine Reconnaissance & Automated Dorking (`search`, `dork`)
- **DuckDuckGo Web Harvesting**: Gathers search engine listings with extracted destination URLs, snippets, and domain metrics without API keys.
- **Encyclopedic Knowledge Entities**: Queries DuckDuckGo Instant Answer API for official corporate records, Wikipedia abstracts, and knowledge panels.
- **Automated OSINT Google & Bing Dork Matrix**: Auto-generates customized one-click dork queries for sensitive file disclosures (`ext:env`, `ext:sql`), exposed admin portals, directory listings, sensitive documents, and leaked source code.

### 15. 💬 Telegram Channel & Community Telemetry (`telegram`)
- **Zero-Auth Channel Telemetry**: Inspects public Telegram channels, supergroups, bots, and public profiles via Telegram's open web directory and preview feeds (`https://t.me/s/{handle}`).
- **Community Metric Extraction**: Captures verified status badges, official entity descriptions, subscriber/member totals, custom bio metadata, and direct avatar previews without requiring a bot token or phone login.

### 16. 📡 MAC Address & IoT Hardware OUI Resolver (`mac`)
- **OUI Manufacturer Mapping**: Decodes IEEE Organizationally Unique Identifiers (OUI) across a fast built-in offline vendor database (Apple, Cisco, Intel, Espressif IoT, Raspberry Pi, TP-Link, etc.) with online fallback for obscure hardware.
- **Hardware Architecture Auditing**: Analyzes bit-level address characteristics, accurately distinguishing between Unicast vs Multicast and Universally Administered vs Locally Administered (Randomized/Private MAC addresses used by modern iOS, Android, and Windows devices).
- **Format Normalization**: Converts flexibly across colon (`00:1A:2B:...`), hyphen (`00-1A-2B-...`), and Cisco dot (`001a.2b3c....`) notations.

### 17. 🖼️ Multi-Engine Reverse Image Pivot Assistant (`reverse-img`)
- **Visual Intelligence Cross-Pivoting**: Generates one-click direct investigation queries across Google Lens, Yandex Visual Search (superior facial & regional recognition), Bing Visual Search, TinEye (chronological oldest appearance), and Baidu Visual Search.
- **Forensic Hash Fingerprinting**: Computes cryptographic MD5, SHA-1, and SHA-256 hashes of local image files and generates instant pivot links for VirusTotal, Hybrid-Analysis, and search engine hash disclosures.

### 18. 🕰️ Wayback Machine Historical Asset Recovery & Time Travel (`wayback`)
- **Defunct Asset & Page Recovery**: Queries the Internet Archive's Wayback Machine endpoints for the earliest recorded snapshot, most recent snapshot, and documented lifespan of target domains.
- **Historical Endpoint Harvesting**: Interrogates the CDX API to discover forgotten sub-pages, unlinked documents, and retired portals preserved over decades.

### 19. 🔐 SSL/TLS Deep Certificate Forensics & SAN Domain Pivoting (`ssl`)
- **Direct Cryptographic Handshake**: Executes pure-Python TLS handshakes on port 443 with fallback to unverified contexts to inspect expired or self-signed certificates.
- **Subject Alternative Name (SAN) Pivoting**: Uncovers hidden sibling infrastructure, internal hostnames, and staging subdomains sharing the same X.509 certificate.
- **Cipher & Security Auditing**: Evaluates certificate authority (CA) trust chains, validity dates, days until expiration, negotiated TLS protocol version, and cipher strength.

---

## 🚀 Quick Installation

### Prerequisites
- Python 3.10 or higher
- Git

### Standard Installation (Linux / macOS)
```bash
# 1. Clone repository
git clone https://github.com/Zaman-Topu/Nexus-Osint.git
cd Nexus-Osint

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Recommended) Install globally as CLI
pip install -e .
```

---

## 📱 Termux / Android Native Readiness

NexusOSINT is engineered specifically to eliminate mobile Termux pain points:

1. **Missing `/etc/resolv.conf`**: Standard Python DNS libraries fail on non-rooted Android devices. NexusOSINT includes a custom resilient resolver (`nexus_osint/resolver.py`) that falls back to hardened public DNS servers (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`).
2. **Zero C-Extensions**: All cryptographic hashing (Favicon MurmurHash3, MD5) is implemented in pure Python, requiring **no `gcc`, `clang`, or compiled binaries**.

### Termux 3-Step Setup
```bash
pkg update && pkg install -y git python
git clone https://github.com/Zaman-Topu/Nexus-Osint.git
cd Nexus-Osint
pip install -r requirements.txt
python osint.py
```

---

## 💻 CLI Command Cheatsheet

```bash
nexusosint <command> <target> [flags]
```

### 🎯 Primary Reconnaissance Commands
```bash
# 🎯 Autonomous Master Dossier (Chains all vectors and builds relationship graph)
nexusosint all target@example.com
nexusosint all victimcorp.com
nexusosint all 8.8.8.8
nexusosint all zaman-topu

# 🛡️ Hudson Rock Infostealer Malware Breach Telemetry
nexusosint stealer ceo@victimcorp.com
nexusosint stealer victimcorp.com

# 🌐 Domain Reconnaissance, Passive Subdomains & Takeover Audit
nexusosint domain target.com

# 👤 Cross-Platform Username Footprinting (75+ sites)
nexusosint user octocat

# ✉️ Email Intelligence, Spoofability & Gravatar
nexusosint email target@domain.com

# 📞 Global Phone Carrier & Geolocation Lookup
nexusosint phone +8801812345678
nexusosint phone 01812345678 --region BD
nexusosint phone +14155552671

# 🐙 Deep GitHub Profile & Commit Email Extraction
nexusosint github torvalds

# 📍 IP Geolocation, ASN & Reverse DNS
nexusosint ip 1.1.1.1

# 🛡️ Shodan InternetDB Open Ports & CVE Vulnerabilities
nexusosint shodan 1.1.1.1

# ☁️ Cloud Bucket Permutation Hunter (AWS, GCP, Azure)
nexusosint cloud targetcorp

# 🕷️ Historical Passive URLs & Sensitive Endpoint Extraction
nexusosint urls targetcorp.com

# 📸 Image EXIF Forensics & GPS Mapping
nexusosint exif /path/to/evidence.jpg

# 🧅 Dark Web (.onion) Intelligence & Paste Dumps
nexusosint darkweb targetcorp
nexusosint darkweb "username_or_brand"

# 🔍 Multi-Search Engine Intel & Automated OSINT Dorking
nexusosint search targetcorp.com
nexusosint search octocat

# 💬 Telegram Channel & Community Telemetry
nexusosint telegram durov
nexusosint telegram @telegram

# 📡 MAC Address & IoT Hardware OUI Resolver
nexusosint mac 00:1A:2B:3C:4D:5E
nexusosint mac B8-27-EB-01-02-03

# 🖼️ Multi-Engine Reverse Image Pivot Assistant
nexusosint reverse-img /path/to/photo.jpg
nexusosint reverse-img https://example.com/target_photo.jpg

# 🕰️ Wayback Machine Historical Snapshot Recovery & Time Travel
nexusosint wayback target.com

# 🔐 SSL/TLS Deep Certificate Forensics & SAN Domain Pivoting
nexusosint ssl target.com
nexusosint ssl example.com:8443

# 📁 Interactive Case Manager & Past Reports Browser
nexusosint cases

# 🖥️ Interactive Full-Screen Terminal Dashboard
nexusosint menu
```

### ⚙️ Command-Line Flags & Options
| Flag | Long Flag | Description | Default |
|---|---|---|:---:|
| `-o` | `--output-dir` | Custom directory to save case investigation folders | `results/` |
| `-t` | `--timeout` | Network socket timeout in seconds | `6.0` |
| `-c` | `--concurrency` | Concurrency worker count for asynchronous operations | `15` |
| `-r` | `--region` | Country code for phone number normalization | `Auto` |
| | `--stealer` | Trigger Hudson Rock infostealer lookup in email/domain mode | `Auto` |
| | `--darkweb` | Execute Dark Web (.onion) and paste dump threat scan | `Auto` |
| | `--search` | Execute multi-search engine queries & automated dork matrix | `Auto` |
| | `--telegram` | Query Telegram channel or community handle | `Auto` |
| | `--mac` | Resolve MAC address and hardware manufacturer OUI | `Auto` |
| | `--reverse-img` | Generate multi-engine reverse image search links & hashes | `Auto` |
| | `--wayback` | Query Wayback Machine for historical snapshots and deleted assets | `Auto` |
| | `--ssl` | Inspect SSL/TLS certificate chains and SAN domains | `Auto` |
| | `--no-banner` | Suppress Rich ASCII banner for clean output piping | `False` |
| | `--no-save` | Display results in terminal only (skip writing files to disk) | `False` |

---

## 📁 Automated Case Folder Architecture

Every single reconnaissance execution automatically packages findings into a dedicated case directory inside `results/`:

```text
results/victimcorp.com_all_20261014_041500/
├── 📄 report.md          # Comprehensive Executive Markdown Dossier
├── 🗃️ data.json          # Machine-Readable Structured JSON Data
├── 📝 summary.txt        # Instant Terminal Summary (cat friendly)
└── 🌐 visual_graph.html  # Standalone Vis.js Interactive Relationship Graph
```

### Quick Case Viewing
```bash
# Instant terminal inspection
cat results/victimcorp.com_all_20261014_041500/summary.txt

# Or explore visually using the built-in browser
nexusosint cases
```

---

## 🌐 Interactive Vis.js Network Graph

When executing the **Master Dossier (`all`)**, NexusOSINT generates a standalone HTML relationship graph powered by **Vis.js**:

- **Physics-Based Force Simulation**: Nodes dynamically adjust and cluster based on entity correlations.
- **Draggable & Zoomable Canvas**: Pan, inspect, and trace connections between accounts, IPs, and endpoints.
- **Categorical Node Legend**:
  - 🟡 **Yellow**: Seed Target
  - 🔵 **Cyan**: Social Profiles, Discovered Usernames & Telegram Channels
  - 🟢 **Green**: Phone Numbers & Active Accounts
  - 🔷 **Blue**: Domains, Subdomains, SAN Domains & CNAME Records
  - 🟠 **Orange**: IP Addresses & Geolocation
  - 🔴 **Red**: Open Ports, CVE Vulnerabilities, Dangling Takeovers & Breaches
  - 🟣 **Purple**: Cloud Storage Buckets & Wayback Historical Lifespans
  - 🔘 **Indigo**: MAC Addresses & IoT Hardware Vendors
- **Zero Local Web Server**: Double-click or open directly in any browser: `file:///path/to/results/.../visual_graph.html`.

---

## 🧪 Comprehensive Unit Testing

NexusOSINT comes equipped with an automated unit test suite covering 100% of core offline functionality, parsers, and intelligence modules:

```bash
# Run all tests
python3 -m unittest discover tests
```

```text
Ran 69 tests in 3.553s

OK
```

---

## 🛡️ Security & OPSEC

- **Authorized Use Only**: NexusOSINT is designed for legitimate cybersecurity research, authorized red/blue teaming, digital forensics, defensive exposure management, and educational purposes.
- **Zero Third-Party Telemetry**: NexusOSINT contains no telemetry, tracking scripts, or analytics. Your scans remain private on your local machine.
- Refer to [SECURITY.md](SECURITY.md) for vulnerability reporting guidelines.

---

## 🤝 Contributing

Contributions, bug reports, and suggestions are welcome!
1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'feat: add AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines.

---

## 👤 Author & Maintainer

<div align="center">

Developed with passion by:

### **Toufique Zaman Topu**
**GitHub:** [@Zaman-Topu](https://github.com/Zaman-Topu)  
**Email:** [topu7252@gmail.com](mailto:topu7252@gmail.com)

[![Follow @Zaman-Topu](https://img.shields.io/github/followers/Zaman-Topu?label=Follow%20%40Zaman--Topu&style=social)](https://github.com/Zaman-Topu)

⭐ **If you find NexusOSINT helpful, please consider giving it a star on GitHub!** ⭐

</div>

---

## 📄 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for more information.

<div align="center">
  <sub>NexusOSINT © 2026 Toufique Zaman Topu. All rights reserved.</sub>
</div>
