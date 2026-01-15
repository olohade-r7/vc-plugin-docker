# Configuration for Docker Security Advisory VC Plugin

# Scraper settings
SCRAPER_DELAY = 1.0  # Delay between requests in seconds
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"

# Data directories
RAW_DATA_DIR = "raw_data"
CONTENT_DIR = "Content/Docker"

# Product information
PRODUCT_NAME = "Docker"
PRODUCT_VENDOR = "Docker Inc."
PRODUCT_TYPES = [
    "Docker Desktop",
    "Docker Engine",
    "Docker Hub",
    "BuildKit",
    "runc",
    "Moby"
]

# URLs
DOCKER_SECURITY_URL = "https://docs.docker.com/security/security-announcements/"
CVE_BASE_URL = "https://cve.org/CVERecord?id="

# Content generation
CONTENT_VERSION = "1.0"
GENERATOR_NAME = "Docker Security Advisory VC Plugin"

# Severity mapping
SEVERITY_KEYWORDS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "moderate": "Medium",
    "low": "Low",
    "info": "Info"
}
