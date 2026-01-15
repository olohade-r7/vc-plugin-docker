# Docker Security Advisory VC Plugin

This project scrapes Docker security advisories and generates Rapid7 vulnerability content files.

## Overview

This VC Plugin:
1. Scrapes vulnerability data from Docker's security announcements page
2. Stores raw data in HTML and JSON formats
3. Validates data using Pydantic models
4. Generates Rapid7-compliant content files (.xml, .vck, .sol)
5. Organizes files under Content/Docker directory structure

## Requirements

- Python 3.8+
- Dependencies listed in requirements.txt

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python main.py
```

This will:
- Scrape all Docker security advisories
- Store raw data in `raw_data/`
- Generate content files in `Content/Docker/`

## Project Structure

```
scrapper/
├── main.py                 # Main orchestration script
├── scraper.py             # Web scraping module
├── models.py              # Pydantic data models
├── transformers.py        # File format transformers
├── requirements.txt       # Python dependencies
├── raw_data/             # Raw scraped data (HTML/JSON)
└── Content/              # Generated content files
    └── Docker/           # Docker product folder
        ├── *.xml         # Vulnerability XML files
        ├── *.vck         # Vulnerability check files
        └── *.sol         # Solution files
```

## File Formats

### .xml Files
Contains vulnerability metadata and details in XML format following Rapid7 standards.

### .vck Files
Vulnerability check files containing detection logic and patterns.

### .sol Files
Solution files with remediation steps and patch information.
