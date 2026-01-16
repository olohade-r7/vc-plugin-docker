"""
Vulnerability Scan Engine
=========================
The core scanning logic that:
1. Loads fingerprint data (what software is installed)
2. Loads VCK files (vulnerability definitions)
3. Compares versions using packaging.version library
4. Generates vulnerability reports

This is the "Brain" of the security scanning pipeline.
"""

import json
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from packaging import version
from dataclasses import dataclass, asdict

from config import (
    get_vck_content_dir, 
    get_fingerprint_path,
    SCAN_RESULTS_FILE,
    LOG_FILE,
    LOG_LEVEL,
    SCAN_CONFIG,
    PRIMARY_VCK_FORMAT
)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class VulnerabilityRule:
    """Represents a single vulnerability check rule from VCK/XML files"""
    cve_id: str
    title: str
    product: str
    vulnerable_condition: str  # e.g., "< 4.27.1" or "<= 2023.2.0"
    fixed_version: Optional[str]
    severity: str
    description: str
    solution: str
    source_file: str


@dataclass 
class ScanResult:
    """Result for a single software item"""
    software: str
    installed: str
    vendor: str
    status: str  # VULNERABLE, SECURE, UNKNOWN
    cve: Optional[str]
    severity: str
    description: Optional[str]
    solution: str


# =============================================================================
# LOGGING SETUP
# =============================================================================

def setup_logging() -> logging.Logger:
    """Configure logging to file and console"""
    logger = logging.getLogger("scan_engine")
    logger.setLevel(getattr(logging, LOG_LEVEL))
    
    # Clear existing handlers
    logger.handlers = []
    
    # File handler
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter('[%(asctime)s] %(levelname)s - %(message)s', 
                                     datefmt='%Y-%m-%d %H:%M:%S')
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter('[%(levelname)s] %(message)s')
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    
    return logger


# =============================================================================
# VERSION COMPARISON UTILITIES
# =============================================================================

def normalize_version(version_str: str) -> str:
    """
    Normalize version string for comparison
    Handles various formats like:
    - "29.1.3" 
    - "v1.2.3"
    - "Docker version 29.1.3"
    - "Git-155)"
    """
    if not version_str or version_str == "unknown":
        return "0.0.0"
    
    # Remove common prefixes
    version_str = version_str.strip()
    version_str = re.sub(r'^v\.?', '', version_str, flags=re.IGNORECASE)
    version_str = re.sub(r'^version\s*', '', version_str, flags=re.IGNORECASE)
    
    # Extract version-like pattern (numbers and dots)
    match = re.search(r'(\d+(?:\.\d+)*(?:[-.]?\w+)?)', version_str)
    if match:
        return match.group(1)
    
    return "0.0.0"


def parse_version_safely(version_str: str) -> Optional[version.Version]:
    """
    Safely parse a version string using packaging.version
    Returns None if parsing fails
    """
    try:
        normalized = normalize_version(version_str)
        return version.parse(normalized)
    except Exception:
        return None


def parse_condition(condition_str: str) -> Tuple[str, str]:
    """
    Parse a version condition string like "< 4.27.1" or "<= 2023.2.0"
    Returns (operator, version_string)
    """
    condition_str = condition_str.strip()
    
    # Match patterns like: "< 4.27.1", "<= 2023.2.0", "> 1.0", etc.
    match = re.match(r'([<>=!]+)\s*(.+)', condition_str)
    if match:
        return match.group(1), match.group(2)
    
    # If no operator, assume "less than"
    return "<", condition_str


def is_version_vulnerable(installed: str, condition: str, logger: logging.Logger) -> bool:
    """
    Check if installed version meets the vulnerability condition
    
    Args:
        installed: The installed version (e.g., "29.1.3")
        condition: The vulnerability condition (e.g., "< 4.27.1")
        logger: Logger instance
    
    Returns:
        True if the installed version is vulnerable
    """
    try:
        operator, threshold = parse_condition(condition)
        
        installed_ver = parse_version_safely(installed)
        threshold_ver = parse_version_safely(threshold)
        
        if installed_ver is None or threshold_ver is None:
            logger.debug(f"Could not parse versions: installed={installed}, threshold={threshold}")
            return False
        
        # Perform comparison based on operator
        if operator == "<":
            return installed_ver < threshold_ver
        elif operator == "<=":
            return installed_ver <= threshold_ver
        elif operator == ">":
            return installed_ver > threshold_ver
        elif operator == ">=":
            return installed_ver >= threshold_ver
        elif operator == "==" or operator == "=":
            return installed_ver == threshold_ver
        elif operator == "!=":
            return installed_ver != threshold_ver
        else:
            # Default to less than
            return installed_ver < threshold_ver
            
    except Exception as e:
        logger.error(f"Version comparison error: {e}")
        return False


# =============================================================================
# VCK/XML PARSER
# =============================================================================

def load_vck_rules_from_xml(xml_path: Path, logger: logging.Logger) -> List[VulnerabilityRule]:
    """
    Load vulnerability rules from XML file
    """
    rules = []
    
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        # Extract CVE ID
        cve_id = ""
        metadata = root.find('metadata')
        if metadata is not None:
            id_elem = metadata.find('id')
            if id_elem is not None and id_elem.text:
                cve_id = id_elem.text
        
        # Extract title
        title = ""
        title_elem = root.find('.//title')
        if title_elem is not None and title_elem.text:
            title = title_elem.text
        
        # Extract severity
        severity = "Medium"
        severity_elem = root.find('.//severity')
        if severity_elem is not None and severity_elem.text:
            severity = severity_elem.text
        
        # Extract description
        description = ""
        desc_elem = root.find('description')
        if desc_elem is not None and desc_elem.text:
            description = desc_elem.text
        
        # Extract solution
        solution = "Update to the latest version"
        sol_elem = root.find('solution')
        if sol_elem is not None and sol_elem.text:
            solution = sol_elem.text
        
        # Extract affected versions
        affected_section = root.find('affected_versions')
        if affected_section is not None:
            for product_elem in affected_section.findall('product'):
                product_name = product_elem.find('name')
                version_affected = product_elem.find('version_affected')
                fixed_in = product_elem.find('fixed_in')
                
                if product_name is not None and version_affected is not None:
                    rule = VulnerabilityRule(
                        cve_id=cve_id,
                        title=title,
                        product=product_name.text or "",
                        vulnerable_condition=version_affected.text or "",
                        fixed_version=fixed_in.text if fixed_in is not None else None,
                        severity=severity,
                        description=description,
                        solution=solution,
                        source_file=str(xml_path)
                    )
                    rules.append(rule)
                    logger.debug(f"Loaded rule: {cve_id} for {product_name.text}")
        
        # If no affected_versions section, create a generic rule for Docker
        if not rules and "docker" in str(xml_path).lower():
            rule = VulnerabilityRule(
                cve_id=cve_id,
                title=title,
                product="Docker",
                vulnerable_condition="< 99.99.99",  # Very high version to mark as potentially affected
                fixed_version=None,
                severity=severity,
                description=description,
                solution=solution,
                source_file=str(xml_path)
            )
            rules.append(rule)
            logger.debug(f"Created generic Docker rule: {cve_id}")
    
    except ET.ParseError as e:
        logger.error(f"XML parse error in {xml_path}: {e}")
    except Exception as e:
        logger.error(f"Error loading {xml_path}: {e}")
    
    return rules


def load_all_vck_rules(logger: logging.Logger) -> List[VulnerabilityRule]:
    """
    Load all vulnerability rules from the configured VCK content directory
    """
    content_dir = get_vck_content_dir()
    logger.info(f"Loading VCK rules from: {content_dir}")
    
    all_rules = []
    
    if not content_dir.exists():
        logger.warning(f"VCK content directory not found: {content_dir}")
        return all_rules
    
    # Find all XML files (they have the structured data)
    xml_files = list(content_dir.rglob("*.xml"))
    logger.info(f"Found {len(xml_files)} XML files")
    
    for xml_file in xml_files:
        rules = load_vck_rules_from_xml(xml_file, logger)
        all_rules.extend(rules)
    
    logger.info(f"Total rules loaded: {len(all_rules)}")
    return all_rules


# =============================================================================
# FINGERPRINT LOADER
# =============================================================================

def load_fingerprint(logger: logging.Logger, custom_path: str = None) -> Dict[str, Any]:
    """
    Load fingerprint data from JSON file
    
    Args:
        logger: Logger instance
        custom_path: Optional custom path to fingerprint file
    
    Returns:
        Parsed fingerprint data as dictionary
    """
    fingerprint_path = Path(custom_path) if custom_path else get_fingerprint_path()
    
    logger.debug(f"Loading fingerprint from: {fingerprint_path}")
    
    if not fingerprint_path.exists():
        logger.error(f"Fingerprint file not found: {fingerprint_path}")
        raise FileNotFoundError(f"Fingerprint file not found: {fingerprint_path}")
    
    with open(fingerprint_path, 'r') as f:
        data = json.load(f)
    
    # Extract software inventory
    software_inventory = data.get('software_inventory', [])
    logger.info(f"Found {len(software_inventory)} software items in fingerprint")
    
    return data


# =============================================================================
# MAIN SCAN ENGINE CLASS
# =============================================================================

class VulnerabilityScanner:
    """
    Main scanner class that orchestrates the vulnerability scanning process
    """
    
    def __init__(self, fingerprint_path: str = None):
        """
        Initialize the scanner
        
        Args:
            fingerprint_path: Optional custom path to fingerprint JSON file
        """
        self.logger = setup_logging()
        self.fingerprint_path = fingerprint_path
        self.rules: List[VulnerabilityRule] = []
        self.fingerprint: Dict[str, Any] = {}
        self.results: List[ScanResult] = []
    
    def load_data(self) -> None:
        """Load VCK rules and fingerprint data"""
        self.logger.info("="*50)
        self.logger.info("VULNERABILITY SCAN STARTED")
        self.logger.info("="*50)
        
        # Load VCK rules
        self.rules = load_all_vck_rules(self.logger)
        
        # Load fingerprint
        self.fingerprint = load_fingerprint(self.logger, self.fingerprint_path)
    
    def _match_product(self, software_name: str, rule_product: str) -> bool:
        """
        Check if software name matches rule product
        Uses fuzzy matching to handle variations
        """
        software_lower = software_name.lower().strip()
        rule_lower = rule_product.lower().strip()
        
        # Direct match
        if software_lower == rule_lower:
            return True
        
        # Partial match (software name contains rule product or vice versa)
        if software_lower in rule_lower or rule_lower in software_lower:
            return True
        
        # Common aliases
        aliases = {
            "docker": ["docker desktop", "docker engine", "docker"],
            "chrome": ["google chrome", "chromium", "chrome"],
            "vscode": ["vs code", "visual studio code", "code"],
            "node": ["node.js", "nodejs", "node"],
            "python": ["python3", "python", "cpython"],
            "pycharm": ["pycharm professional", "pycharm community", "pycharm"]
        }
        
        for key, names in aliases.items():
            if software_lower in names or any(n in software_lower for n in names):
                if rule_lower in names or any(n in rule_lower for n in names):
                    return True
        
        return False
    
    def scan(self) -> Dict[str, Any]:
        """
        Perform the vulnerability scan
        
        Returns:
            Complete scan report as dictionary
        """
        self.load_data()
        
        software_inventory = self.fingerprint.get('software_inventory', [])
        self.logger.info(f"Checking {len(software_inventory)} software items against {len(self.rules)} rules")
        
        self.results = []
        
        for software in software_inventory:
            software_name = software.get('productName', 'Unknown')
            software_version = software.get('versionNumber', 'unknown')
            vendor = software.get('vendor', 'Unknown')
            
            self.logger.debug(f"Checking: {software_name} v{software_version}")
            
            # Find matching vulnerability rules
            matched_vulnerable = False
            matched_rule = None
            
            for rule in self.rules:
                if self._match_product(software_name, rule.product):
                    self.logger.debug(f"  Product match found: {rule.cve_id} ({rule.product})")
                    
                    # Check if version is vulnerable
                    if is_version_vulnerable(software_version, rule.vulnerable_condition, self.logger):
                        self.logger.warning(
                            f"VULNERABLE: {software_name} {software_version} "
                            f"{rule.vulnerable_condition} - {rule.cve_id}"
                        )
                        matched_vulnerable = True
                        matched_rule = rule
                        break
                    else:
                        self.logger.info(
                            f"SAFE: {software_name} {software_version} "
                            f"does not match condition {rule.vulnerable_condition}"
                        )
            
            # Create result
            if matched_vulnerable and matched_rule:
                result = ScanResult(
                    software=software_name,
                    installed=software_version,
                    vendor=vendor,
                    status="VULNERABLE",
                    cve=matched_rule.cve_id,
                    severity=matched_rule.severity,
                    description=matched_rule.description,
                    solution=matched_rule.solution
                )
            else:
                result = ScanResult(
                    software=software_name,
                    installed=software_version,
                    vendor=vendor,
                    status="SECURE",
                    cve=None,
                    severity="0.0",
                    description=None,
                    solution="No action required."
                )
            
            self.results.append(result)
        
        # Generate report
        report = self._generate_report()
        
        self.logger.info("="*50)
        self.logger.info("SCAN COMPLETED")
        self.logger.info(f"Total scanned: {len(self.results)}")
        self.logger.info(f"Vulnerable: {sum(1 for r in self.results if r.status == 'VULNERABLE')}")
        self.logger.info(f"Secure: {sum(1 for r in self.results if r.status == 'SECURE')}")
        self.logger.info("="*50)
        
        return report
    
    def _generate_report(self) -> Dict[str, Any]:
        """Generate the final scan report"""
        report = {
            "scan_id": f"SCAN-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "timestamp": datetime.now().isoformat(),
            "scan_source": {
                "fingerprint_file": str(self.fingerprint_path or get_fingerprint_path()),
                "vck_source": str(get_vck_content_dir()),
                "rules_loaded": len(self.rules)
            },
            "system_info": self.fingerprint.get('system_info', {}),
            "summary": {
                "total_software": len(self.results),
                "vulnerable_count": sum(1 for r in self.results if r.status == 'VULNERABLE'),
                "secure_count": sum(1 for r in self.results if r.status == 'SECURE'),
                "unknown_count": sum(1 for r in self.results if r.status == 'UNKNOWN')
            },
            "results": [asdict(r) for r in self.results]
        }
        
        return report
    
    def save_report(self, report: Dict[str, Any], output_path: str = None) -> str:
        """
        Save the scan report to a JSON file
        
        Args:
            report: The scan report dictionary
            output_path: Optional custom output path
            
        Returns:
            Path to the saved file
        """
        output_file = Path(output_path) if output_path else SCAN_RESULTS_FILE
        
        # Ensure output directory exists
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Report saved to: {output_file}")
        return str(output_file)


# =============================================================================
# CONVENIENCE FUNCTION
# =============================================================================

def run_scan(fingerprint_path: str = None, output_path: str = None) -> Dict[str, Any]:
    """
    Convenience function to run a complete scan
    
    Args:
        fingerprint_path: Optional custom fingerprint file path
        output_path: Optional custom output file path
    
    Returns:
        The scan report dictionary
    """
    scanner = VulnerabilityScanner(fingerprint_path)
    report = scanner.scan()
    scanner.save_report(report, output_path)
    return report


if __name__ == "__main__":
    # Test run
    report = run_scan()
    print(json.dumps(report, indent=2))
