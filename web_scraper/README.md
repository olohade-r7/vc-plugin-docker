# Web Scraper Module

## Overview
Scrapes CVE vulnerability data from security websites and converts to structured JSON format.

## Files
- `scraper.py` - Web scraping logic
- `transformers.py` - Parse HTML to JSON
- `models.py` - Data models
- `config.py` - Configuration
- `main.py` - Entry point

## Usage
```bash
cd web_scraper
python main.py
```

## Output
- `raw_data/html/` - Raw HTML files
- `raw_data/json/` - Parsed JSON data
- `Content/Docker/` - Docker-specific vulnerability files
