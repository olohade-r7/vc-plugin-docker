# Web Scraper - Vulnerability Content Generator

Automated tool for collecting CVE data from security advisories and generating vulnerability check files.

---

## What is Web Scraping?

**Web scraping** is the automated extraction of data from websites. Instead of manually copying information, a program visits web pages, parses the HTML, and extracts structured data.

### Why Scrape Security Advisories?

Security vendors (Docker, Microsoft, etc.) publish vulnerability announcements on their websites. This data needs to be:
- Collected systematically
- Parsed into structured format
- Converted to machine-readable rules for scanners

This project automates that entire process.

---

## How It Works

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Security        │     │   Parse &        │     │   Generate       │
│  Advisory Page   │────▶│   Validate       │────▶│   VCK/XML/SOL    │
│  (HTML)          │     │   (Pydantic)     │     │   Files          │
└──────────────────┘     └──────────────────┘     └──────────────────┘
```

**Data Flow:**
1. `scraper.py` fetches HTML from Docker security pages
2. `models.py` validates extracted CVE data (ID, severity, versions)
3. `transformers.py` generates three file types per vulnerability

---

## Output File Types

| Extension | Name | Purpose |
|-----------|------|---------|
| `.xml` | Vulnerability Descriptor | Full CVE details, CVSS, references |
| `.vck` | Vulnerability Check | Detection rules (product + version conditions) |
| `.sol` | Solution File | Remediation steps and workarounds |

**Example Output:**
```
Content/Docker/
├── docker_cve-2025-23266.xml   # What is this vulnerability?
├── docker_cve-2025-23266.vck   # How to detect it?
└── docker_cve-2025-23266.sol   # How to fix it?
```

---

## Usage

```bash
cd web_scraper
python main.py
```

**What Happens:**
1. Fetches Docker security announcements page
2. Extracts all CVE links
3. Scrapes each CVE detail page
4. Saves raw HTML to `raw_data/html/`
5. Parses and validates data
6. Generates VCK/XML/SOL files to `Content/Docker/`

---

## Project Structure

```
web_scraper/
├── main.py           # Entry point - runs full pipeline
├── scraper.py        # BeautifulSoup scraping logic
├── models.py         # Pydantic models for CVE data
├── transformers.py   # XML/VCK/SOL file generators
├── config.py         # URLs, paths, settings
│
├── raw_data/
│   ├── html/         # Cached HTML pages
│   └── json/         # Parsed JSON data
│
└── Content/
    └── Docker/       # Generated vulnerability files
```

---

## Key Components

### scraper.py
- Uses `requests` to fetch web pages
- Uses `BeautifulSoup` to parse HTML
- Extracts: CVE ID, title, severity, affected versions, solution

### models.py
- `VulnerabilityDetail` - CVE metadata (title, severity, dates)
- `VulnerabilityCheck` - Detection logic (product, version range)
- `Solution` - Remediation steps
- Uses Pydantic for validation (ensures CVE format, severity levels)

### transformers.py
- `XMLTransformer` - Generates structured XML with all CVE details
- `VCKTransformer` - Generates check rules for scanner
- `SOLTransformer` - Generates remediation documentation

---

## VCK File Format

The `.vck` file defines how to detect a vulnerability:

```ini
[CHECK_INFO]
check_id = docker-cve-2025-23266
cve_id = CVE-2025-23266
severity = Medium
check_type = version

[DETECTION]
vulnerable_versions = ["< 4.38.0"]
safe_versions = ["4.38.0", "4.38.1"]

[CHECK_LOGIC]
# If product matches AND version < threshold → VULNERABLE
```

---

## XML File Structure

```xml
<vulnerability version="1.0">
  <metadata>
    <id>CVE-2025-23266</id>
    <title>Docker Desktop Vulnerability</title>
    <severity>Medium</severity>
  </metadata>
  <affected_versions>
    <product>
      <name>Docker Desktop</name>
      <version_affected>&lt; 4.38.0</version_affected>
      <fixed_in>4.38.0</fixed_in>
    </product>
  </affected_versions>
  <solution>Update Docker Desktop to 4.38.0 or later</solution>
</vulnerability>
```

---

## Adding New Products

To scrape vulnerabilities for a new product:

1. Add scraping logic in `scraper.py` for the new advisory page
2. Map data to models in `models.py`
3. Create product folder: `Content/<ProductName>/`
4. Update `main.py` pipeline

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `beautifulsoup4` | HTML parsing |
| `requests` | HTTP requests |
| `lxml` | XML generation |
| `pydantic` | Data validation |

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Request blocked | Add User-Agent header, respect rate limits |
| Parse error | Check if website HTML structure changed |
| Validation error | Review Pydantic model constraints |
