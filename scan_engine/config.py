"""
Configuration for Vulnerability Scan Engine
============================================
This file contains all configurable settings for the scan engine.
Easy to modify paths, enable/disable features, and switch VCK data sources.

HOW TO SWITCH VCK DATA SOURCES:
-------------------------------
Change the ACTIVE_VCK_SOURCE variable below to use different VCK folders:
    - "scraped"    : Uses real data from web_scraper (Docker CVEs we scraped)
    - "synthetic"  : Uses synthetic/POC data for testing
    - "external"   : Uses external datasets (you add your own)
"""

import os
from pathlib import Path

# =============================================================================
# BASE PATHS
# =============================================================================
BASE_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = BASE_DIR.parent  # Points to /scrapper folder

# =============================================================================
# VCK DATA SOURCE CONFIGURATION
# =============================================================================
# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  TO SWITCH VCK FOLDER: Change the value of ACTIVE_VCK_SOURCE below        ║
# ║                                                                            ║
# ║  Options:                                                                  ║
# ║    "scraped"   - Real CVE data from web_scraper/Content folder             ║
# ║    "synthetic" - Sample/POC data for testing                               ║
# ║    "external"  - Your own external datasets                                ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

ACTIVE_VCK_SOURCE = "scraped"  # <-- CHANGE THIS TO SWITCH VCK SOURCE

# VCK folder paths
VCK_SOURCES = {
    # Real scraped data from web_scraper project
    "scraped": PROJECT_ROOT / "web_scraper" / "Content",
    
    # Synthetic POC data for testing
    "synthetic": BASE_DIR / "Content" / "synthetic_data",
    
    # External datasets (you put your data here)
    "external": BASE_DIR / "Content" / "external_data",
}

# Get the active VCK content directory
def get_vck_content_dir() -> Path:
    """Returns the currently active VCK content directory"""
    return VCK_SOURCES.get(ACTIVE_VCK_SOURCE, VCK_SOURCES["scraped"])


# =============================================================================
# FINGERPRINT INPUT CONFIGURATION
# =============================================================================
# Default fingerprint file path (from fingerprinting_agent)
DEFAULT_FINGERPRINT_PATH = PROJECT_ROOT / "fingerprinting_agent" / "output" / "fingerprint_report.json"

# Alternative: Custom fingerprint path (set this if using a different location)
CUSTOM_FINGERPRINT_PATH = None  # Set to a path if needed

def get_fingerprint_path() -> Path:
    """Returns the fingerprint file path to use"""
    if CUSTOM_FINGERPRINT_PATH and Path(CUSTOM_FINGERPRINT_PATH).exists():
        return Path(CUSTOM_FINGERPRINT_PATH)
    return DEFAULT_FINGERPRINT_PATH


# =============================================================================
# OUTPUT CONFIGURATION
# =============================================================================
OUTPUT_DIR = BASE_DIR / "output"
SCAN_RESULTS_FILE = OUTPUT_DIR / "scan_results.json"

# Create output directory if it doesn't exist
OUTPUT_DIR.mkdir(exist_ok=True)


# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "scan_engine.log"

# Create logs directory if it doesn't exist
LOG_DIR.mkdir(exist_ok=True)

# Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_LEVEL = "DEBUG"


# =============================================================================
# FLASK WEB SERVER CONFIGURATION
# =============================================================================
FLASK_CONFIG = {
    "DEBUG": True,
    "HOST": "127.0.0.1",
    "PORT": 5000,
    "SECRET_KEY": "your-secret-key-change-in-production"
}


# =============================================================================
# SCAN ENGINE SETTINGS
# =============================================================================
SCAN_CONFIG = {
    # How to handle version parsing errors
    "strict_version_parsing": False,  # If False, non-parseable versions are skipped
    
    # Include software with no matching VCK rules in results
    "include_unmatched_software": True,
    
    # Default status for software without vulnerabilities
    "default_status": "SECURE",
    
    # Severity thresholds (for filtering/reporting)
    "severity_levels": {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
        "Info": 0
    }
}


# =============================================================================
# FILE FORMAT SETTINGS
# =============================================================================
# Supported file extensions for vulnerability checks
SUPPORTED_VCK_FORMATS = [".vck", ".xml"]

# Primary format to parse (xml has more structured data)
PRIMARY_VCK_FORMAT = ".xml"


# =============================================================================
# PRINT CURRENT CONFIGURATION (for debugging)
# =============================================================================
def print_config():
    """Print current configuration for debugging"""
    print("\n" + "="*60)
    print("SCAN ENGINE CONFIGURATION")
    print("="*60)
    print(f"Active VCK Source: {ACTIVE_VCK_SOURCE}")
    print(f"VCK Content Dir:   {get_vck_content_dir()}")
    print(f"Fingerprint Path:  {get_fingerprint_path()}")
    print(f"Output File:       {SCAN_RESULTS_FILE}")
    print(f"Log File:          {LOG_FILE}")
    print("="*60 + "\n")


if __name__ == "__main__":
    print_config()
