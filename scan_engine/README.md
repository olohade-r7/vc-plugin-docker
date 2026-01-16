# Scan Engine - Vulnerability Assessment System

The correlation engine that matches installed software against known vulnerabilities and provides actionable security reports.

---

## What is Vulnerability Scanning?

**Vulnerability scanning** compares what you have installed against a database of known security flaws. It answers: "Which of my software has known vulnerabilities?"

### The Matching Problem

Given:
- **Fingerprint:** Docker v29.1.3 is installed
- **VCK Rule:** Docker versions < 30.0.0 are vulnerable to CVE-2025-99002

**Result:** Docker is VULNERABLE (29.1.3 < 30.0.0)

### Why Version Comparison is Tricky

Simple string comparison fails:
- "1.10.0" vs "1.9.0" → String says "1.10.0" < "1.9.0" (WRONG)
- "2.0.0-beta" vs "2.0.0" → Which is newer?

This project uses the `packaging` library for **semantic version comparison**.

---

## How It Works

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  fingerprint.json│     │   Compare        │     │   scan_results   │
│  (installed sw)  │────▶│   Versions       │────▶│   .json          │
│                  │     │                  │     │                  │
├──────────────────┤     │  For each SW:    │     │  VULNERABLE: 2   │
│  VCK Files       │────▶│  installed < vck │     │  SECURE: 5       │
│  (vuln rules)    │     │  threshold?      │     │                  │
└──────────────────┘     └──────────────────┘     └──────────────────┘
```

**Algorithm:**
```
for each installed_software:
    for each vck_rule:
        if product_name_matches AND installed_version < vulnerable_threshold:
            mark as VULNERABLE
            break
    else:
        mark as SECURE
```

---

## Usage

### CLI Mode

```bash
cd scan_engine

# Run scan (uses existing fingerprint)
python main.py --scan

# Run fingerprinting first, then scan
python main.py --fingerprint-local
python main.py --scan

# Show configuration
python main.py --config
```

### Web Dashboard

```bash
python main.py --web
# Open http://127.0.0.1:5000
```

**Dashboard Features:**
- Current configuration display
- "Start Scan" button
- Results table with severity colors
- Links to CVE details

---

## VCK Data Sources

The engine can use three different vulnerability databases:

| Source | Path | Description |
|--------|------|-------------|
| `scraped` | `web_scraper/Content/` | Real CVEs from web scraper |
| `synthetic` | `scan_engine/Content/synthetic_data/` | Test data for demos |
| `external` | `scan_engine/Content/external_data/` | Your own datasets |

### Switching Sources

Edit `config.py` line ~36:
```python
# Change this value to switch VCK source:
ACTIVE_VCK_SOURCE = "scraped"    # Real data
ACTIVE_VCK_SOURCE = "synthetic"  # Test data (more vulnerabilities)
ACTIVE_VCK_SOURCE = "external"   # Your data
```

---

## Output Format

**scan_results.json:**
```json
{
  "scan_id": "SCAN-20260116120000",
  "timestamp": "2026-01-16T12:00:00Z",
  "summary": {
    "total_software": 7,
    "vulnerable_count": 2,
    "secure_count": 5
  },
  "results": [
    {
      "software": "Docker",
      "installed": "29.1.3",
      "status": "VULNERABLE",
      "cve": "CVE-2025-99002",
      "severity": "High",
      "solution": "Update Docker to version 30.0.0 or later"
    },
    {
      "software": "Git",
      "installed": "2.45.0",
      "status": "SECURE",
      "cve": null,
      "severity": "0.0",
      "solution": "No action required"
    }
  ]
}
```

---

## Project Structure

```
scan_engine/
├── main.py           # CLI entry point (--scan, --web, --config)
├── app.py            # Flask web application
├── engine.py         # Core scanning logic
├── config.py         # VCK source, paths, settings
│
├── templates/
│   ├── index.html    # Dashboard home page
│   └── results.html  # Results display page
│
├── Content/
│   ├── synthetic_data/   # 7 test VCK files
│   │   ├── vscode_cve-2025-99001.xml
│   │   ├── docker_cve-2025-99002.xml
│   │   └── ...
│   └── external_data/    # Your own datasets
│       └── README.md
│
├── output/
│   └── scan_results.json
│
└── logs/
    └── scan_engine.log
```

---

## Version Comparison Logic

### Using packaging.version

```python
from packaging import version

v1 = version.parse("29.1.3")
v2 = version.parse("30.0.0")

v1 < v2  # True → 29.1.3 is older, potentially vulnerable
```

### Supported Operators

VCK files can specify conditions:
- `< 30.0.0` - Less than (vulnerable if installed < threshold)
- `<= 30.0.0` - Less than or equal
- `> 1.0.0` - Greater than
- `== 2.0.0` - Exact match

### Version Normalization

The engine handles various formats:
- `"29.1.3"` → 29.1.3
- `"v29.1.3"` → 29.1.3
- `"Docker version 29.1.3"` → 29.1.3
- `"Git-155)"` → extracts numeric portion

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard home page |
| `/scan` | POST | Trigger vulnerability scan |
| `/results` | GET | Get scan results as JSON |
| `/dashboard` | GET | Results visualization page |
| `/api/config` | GET | Current configuration |
| `/api/vck-files` | GET | List loaded VCK files |
| `/health` | GET | Service health check |

---

## Logging

All scan activity is logged to `logs/scan_engine.log`:

```
[2026-01-16 12:00:01] INFO - VULNERABILITY SCAN STARTED
[2026-01-16 12:00:02] INFO - Found 7 software items in fingerprint
[2026-01-16 12:00:02] INFO - Loaded 10 vulnerability rules
[2026-01-16 12:00:02] WARNING - VULNERABLE: Docker 29.1.3 < 30.0.0 - CVE-2025-99002
[2026-01-16 12:00:02] INFO - SAFE: Git 2.45.0 does not match condition < 2.44.0
[2026-01-16 12:00:03] INFO - SCAN COMPLETED
```

---

## Adding External VCK Data

1. Place XML files in `Content/external_data/`
2. Use this structure:

```xml
<?xml version="1.0" encoding="utf-8"?>
<vulnerability version="1.0">
  <metadata>
    <id>CVE-2025-XXXXX</id>
    <title>Vulnerability Title</title>
    <severity>Critical|High|Medium|Low</severity>
  </metadata>
  <affected_versions>
    <product>
      <name>ProductName</name>
      <version_affected>&lt; 1.0.0</version_affected>
      <fixed_in>1.0.0</fixed_in>
    </product>
  </affected_versions>
  <solution>How to fix</solution>
</vulnerability>
```

3. Set `ACTIVE_VCK_SOURCE = "external"` in config.py

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `flask` | Web dashboard server |
| `packaging` | Semantic version comparison |
| `pydantic` | Data validation |

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Fingerprint not found" | Run `python main.py --fingerprint-local` first |
| "No VCK files found" | Check `ACTIVE_VCK_SOURCE` path in config |
| Version comparison error | Check `logs/scan_engine.log` for details |
| Web server won't start | Check port 5000 is free |
