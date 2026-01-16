# External VCK Dataset Folder
=============================

This folder is for **external/third-party vulnerability datasets** that you want to use.

## How to Use

1. Place your VCK/XML files in this folder
2. Update `config.py` to use external data:
   ```python
   ACTIVE_VCK_SOURCE = "external"  # Change from "scraped" to "external"
   ```
3. Run the scan: `python main.py --scan`

## Expected Format

The scan engine expects XML files with this structure:

```xml
<?xml version="1.0" encoding="utf-8"?>
<vulnerability version="1.0" generated_at="2026-01-16T00:00:00">
  <metadata>
    <id>CVE-2025-XXXXX</id>
    <title>Vulnerability Title</title>
    <severity>Critical|High|Medium|Low</severity>
  </metadata>
  <description>Description of the vulnerability</description>
  <affected_versions>
    <product>
      <name>ProductName</name>
      <version_affected>&lt; 1.0.0</version_affected>
      <fixed_in>1.0.0</fixed_in>
    </product>
  </affected_versions>
  <solution>How to fix the vulnerability</solution>
</vulnerability>
```

## Data Sources

You can download vulnerability data from:
- NVD (National Vulnerability Database): https://nvd.nist.gov/
- CVE Details: https://cvedetails.com/
- Vulners: https://vulners.com/
- Rapid7 Vulnerability Database: https://www.rapid7.com/db/

## Notes

- Ensure XML files are properly formatted
- The `name` in `<product>` should match software names in your fingerprint
- Use operators: `<`, `<=`, `>`, `>=`, `==` for version conditions
