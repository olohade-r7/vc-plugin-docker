# Vulnerability Management Pipeline

Complete automated system for CVE detection, system fingerprinting, and vulnerability scanning.

## Overview

This project contains two main modules:

1. **Web Scraper** - Scrapes Docker security advisories and generates vulnerability content files
2. **Fingerprinting Agent** - Detects system specifications and installed software (local/remote)

## Project Structure

```
scrapper/
├── web_scraper/              # CVE data collection module
│   ├── main.py              # Entry point
│   ├── scraper.py           # Web scraping logic
│   ├── transformers.py      # HTML to JSON parser
│   ├── models.py            # Data models
│   ├── Content/             # Generated vulnerability files
│   └── raw_data/            # Scraped HTML and JSON data
│
├── fingerprinting_agent/    # System fingerprinting module
│   ├── main.py              # Entry point
│   ├── fingerprinting_agent.py
│   ├── modules/             # Core modules
│   └── output/              # Fingerprint reports
│
├── venv/                    # Python virtual environment
└── requirements.txt         # Dependencies
```

## Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r fingerprinting_agent/requirements.txt
```

## Usage

### Web Scraper Module

### Web Scraper Module

Scrapes Docker security advisories and generates vulnerability content files.

```bash
cd web_scraper
python main.py
```

**Output:**
- `raw_data/html/` - Raw HTML files
- `raw_data/json/all_vulnerabilities.json` - Parsed CVE data
- `Content/Docker/` - .xml, .vck, .sol files

---

### Fingerprinting Agent Module

Detects system information and installed software.

**Local Scan:**
```bash
cd fingerprinting_agent
python main.py --local
```

**Remote Scan (SSH):**
```bash
python main.py --remote 192.168.1.100 --user admin --key ~/.ssh/id_rsa
```

**Output:** `output/fingerprint_report.json`

---

## Pipeline Workflow

```
Step 1: Web Scraper
  ↓ Collects CVE vulnerability data
  
Step 2: Fingerprinting Agent
  ↓ Detects installed software on systems
  
Step 3: Scanner (Future)
  ↓ Matches CVEs with installed software
  
Step 4: Reporter (Future)
  ↓ Generates security reports and alerts
```

## Documentation

- **Web Scraper:** See `web_scraper/README.md`
- **Fingerprinting Agent:** See `fingerprinting_agent/README.md`
- **Remote Setup Guide:** See `fingerprinting_agent/REMOTE_SETUP_GUIDE.md`

## Requirements

- Python 3.8+
- Docker (for remote testing)
- SSH access (for remote scanning)
```

## File Formats

### .xml Files
Contains vulnerability metadata and details in XML format following Rapid7 standards.

### .vck Files
Vulnerability check files containing detection logic and patterns.

### .sol Files
Solution files with remediation steps and patch information.
