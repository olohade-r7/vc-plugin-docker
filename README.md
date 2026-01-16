# Security Vulnerability Management Pipeline

A complete end-to-end solution for vulnerability intelligence gathering, system inventory, and security assessment.

---

## What is This Project?

This pipeline automates the process of identifying security vulnerabilities in software systems. It answers a critical question: **"Is my system at risk?"**

### The Problem
- New CVEs (Common Vulnerabilities and Exposures) are published daily
- Organizations need to know which vulnerabilities affect their systems
- Manual checking is time-consuming and error-prone

### The Solution
A three-stage automated pipeline that:
1. **Collects** vulnerability data from security advisories
2. **Inventories** installed software on local/remote systems
3. **Correlates** installed software against known vulnerabilities

---

## Pipeline Architecture

```
┌─────────────────────┐     ┌─────────────────────┐     ┌─────────────────────┐
│   WEB SCRAPER       │     │  FINGERPRINTING     │     │    SCAN ENGINE      │
│   (Stage 1)         │     │     AGENT           │     │    (Stage 3)        │
│                     │     │   (Stage 2)         │     │                     │
│  Collects CVE data  │────▶│  Detects installed  │────▶│  Matches & Reports  │
│  from advisories    │     │  software versions  │     │  vulnerabilities    │
└──────────┬──────────┘     └──────────┬──────────┘     └──────────┬──────────┘
           │                           │                           │
           ▼                           ▼                           ▼
      VCK/XML Files            fingerprint.json             scan_results.json
```

---

## Quick Start

```bash
# 1. Setup
cd scrapper
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Fingerprint system
cd fingerprinting_agent && python main.py --local

# 3. Run vulnerability scan
cd ../scan_engine && python main.py --scan

# 4. Or use web dashboard
python main.py --web   # Open http://127.0.0.1:5000
```

---

## Project Structure

```
scrapper/
├── requirements.txt          # Unified dependencies
│
├── web_scraper/              # Stage 1: CVE Data Collection
│   ├── scraper.py            # Web scraping logic
│   ├── transformers.py       # VCK/XML/SOL generators
│   └── Content/              # Output: vulnerability definitions
│
├── fingerprinting_agent/     # Stage 2: System Inventory
│   ├── config.py             # Software detection rules
│   ├── modules/              # SSH, detection logic
│   └── output/               # Output: fingerprint_report.json
│
└── scan_engine/              # Stage 3: Vulnerability Assessment
    ├── engine.py             # Version comparison logic
    ├── app.py                # Flask web dashboard
    ├── config.py             # VCK source selection
    └── output/               # Output: scan_results.json
```

---

## Dependencies

| Package | Project | Purpose |
|---------|---------|---------|
| `beautifulsoup4`, `requests`, `lxml` | Web Scraper | HTML parsing, HTTP, XML |
| `paramiko` | Fingerprinting Agent | SSH remote connections |
| `flask`, `packaging` | Scan Engine | Web UI, version comparison |
| `pydantic` | All | Data validation |

---

## Key Concepts

| Term | Definition |
|------|------------|
| **CVE** | Common Vulnerabilities and Exposures - unique ID for security flaws (e.g., CVE-2025-1234) |
| **VCK** | Vulnerability Check - rules defining vulnerable product + version conditions |
| **Fingerprint** | System inventory listing installed software with exact versions |
| **CVSS** | Severity score from 0.0 (none) to 10.0 (critical) |

---

## Common Commands

| Task | Command |
|------|---------|
| Local scan | `cd fingerprinting_agent && python main.py --local` |
| Remote scan | `python main.py --remote <IP> --user <USER> --password <PASS>` |
| Vulnerability check | `cd scan_engine && python main.py --scan` |
| Web dashboard | `python main.py --web` |
| Switch VCK source | Edit `scan_engine/config.py` → `ACTIVE_VCK_SOURCE` |

---

## Output

**Scan Results Summary:**
```
Scan ID:      SCAN-20260116120000
Total:        7 software items
Vulnerable:   2
Secure:       5

⚠️ Docker v29.1.3 - CVE-2025-23266 (Medium)
   Solution: Update to latest version
```

---

## Documentation

- [Web Scraper README](web_scraper/README.md) - CVE collection details
- [Fingerprinting Agent README](fingerprinting_agent/README.md) - System scanning details
- [Scan Engine README](scan_engine/README.md) - Vulnerability matching details
