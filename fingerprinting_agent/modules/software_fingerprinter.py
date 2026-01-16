"""
Software Fingerprinter Module
Detects installed software products and extracts metadata
WHY: Core component - this is what we're really interested in for vulnerability scanning

FEATURES:
- Fingerprint predefined software (TARGET_SOFTWARE in config)
- Auto-discover ALL installed software (optional --discover mode)
"""

import re
from typing import List, Dict, Optional, Tuple, Any
from modules.evidence_collector import EvidenceCollector
from config import TARGET_SOFTWARE, AUTO_DISCOVERY_CONFIG
from models import SoftwareInventoryItem, Evidence
import platform


class SoftwareFingerprinter:
    """
    Detects specific installed software products
    Platform-aware (handles macOS, Linux, Windows differences)
    Extracts version and path information
    
    Two modes:
    1. Targeted: Scans for predefined software in TARGET_SOFTWARE
    2. Discovery: Scans for ALL installed software on the system
    """
    
    def __init__(self, evidence_collector: EvidenceCollector, discover_all: bool = False):
        """
        Initialize with evidence collector
        
        Args:
            evidence_collector: EvidenceCollector instance
            discover_all: If True, also discover non-predefined software
        """
        self.evidence = evidence_collector
        self.os_type = self._detect_os_type()
        self.target_software = TARGET_SOFTWARE
        self.discover_all = discover_all
    
    def _detect_os_type(self) -> str:
        """Detect operating system"""
        system = platform.system()
        if system == "Darwin":
            return "macOS"
        elif system == "Linux":
            return "Linux"
        elif system == "Windows":
            return "Windows"
        return "Unknown"
    
    def _parse_version_string(self, version_output: str) -> str:
        """
        Extract version number from various output formats
        Handles different command outputs intelligently
        
        Examples:
            "Docker version 24.0.6" → "24.0.6"
            "24.0.6" → "24.0.6"
            "git version 2.43.0" → "2.43.0"
        """
        if not version_output:
            return "unknown"
        
        # Try common version patterns
        patterns = [
            r'v?(\d+\.\d+(?:\.\d+)?)',  # x.y or x.y.z
            r'version[:\s]+v?(\d+\.\d+(?:\.\d+)?)',  # "version: x.y.z"
        ]
        
        for pattern in patterns:
            match = re.search(pattern, version_output, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # If no pattern matches, return first word (might be version)
        parts = version_output.split()
        return parts[0] if parts else "unknown"
    
    def _extract_install_path(self, detection_output: str) -> Optional[str]:
        """Extract installation path from detection command output"""
        if detection_output and detection_output.strip():
            lines = detection_output.strip().split('\n')
            return lines[0]  # Return first match
        return None
    
    def fingerprint_software(self, software_name: str) -> Optional[SoftwareInventoryItem]:
        """
        Detect a specific software product and extract metadata
        
        Args:
            software_name: Name of software from TARGET_SOFTWARE config
            
        Returns:
            SoftwareInventoryItem or None if not found
        """
        
        if software_name not in self.target_software:
            print(f"Warning: {software_name} not in target software list")
            return None
        
        software_config = self.target_software[software_name]
        
        # Get OS-specific commands
        if self.os_type not in software_config:
            print(f"  {software_name}: Not configured for {self.os_type}")
            return None
        
        os_config = software_config[self.os_type]
        detection_cmd = os_config.get("detection_command")
        version_cmd = os_config.get("version_command")
        
        if not detection_cmd or not version_cmd:
            print(f"  {software_name}: Missing commands for {self.os_type}")
            return None
        
        # Try to detect the software
        print(f"  Checking {software_name}...", end=" ")
        
        success, detection_output, _ = self.evidence.execute_command_locally(
            detection_cmd,
            description=f"detect_{software_name.lower()}_installed",
            timeout=5
        )
        
        # If detection failed, software likely not installed
        if not success or not detection_output:
            print("Not found")
            return None
        
        print("Found! Getting version...")
        
        # Software found, now get version
        success, version_output, _ = self.evidence.execute_command_locally(
            version_cmd,
            description=f"detect_{software_name.lower()}_version",
            timeout=5
        )
        
        version = self._parse_version_string(version_output) if success else "unknown"
        install_path = self._extract_install_path(detection_output)
        
        # Create evidence record
        evidence = Evidence(
            command_run=detection_cmd,
            raw_output=detection_output,
            execution_timestamp=self.evidence.get_evidence(
                f"detect_{software_name.lower()}_installed"
            ).get("timestamp") if self.evidence.get_evidence(
                f"detect_{software_name.lower()}_installed"
            ) else None
        )
        
        # Determine architecture (macOS specific for now)
        architecture = "unknown"
        if self.os_type == "macOS":
            # Try to detect if it's arm64 or x86_64
            if install_path:
                arch_cmd = f"file {install_path}/Contents/MacOS/* 2>/dev/null | grep -o 'arm64\\|x86_64' | head -1"
                success, arch_output, _ = self.evidence.execute_command_locally(
                    arch_cmd,
                    description=f"detect_{software_name.lower()}_arch",
                    timeout=3
                )
                if success and arch_output:
                    architecture = arch_output
        
        # Create inventory item
        return SoftwareInventoryItem(
            productName=software_name,
            versionNumber=version,
            architecture=architecture,
            productFamily=software_config.get("productFamily", "Unknown"),
            vendor=software_config.get("vendor", "Unknown"),
            installPath=install_path,
            evidence=evidence
        )
    
    def fingerprint_all_software(self) -> List[SoftwareInventoryItem]:
        """
        Scan for all target software products
        
        Returns:
            List of detected software items
        """
        print(f"\n[*] Fingerprinting software for {self.os_type}...")
        
        detected_software = []
        
        # First, scan predefined target software
        for software_name in self.target_software.keys():
            result = self.fingerprint_software(software_name)
            if result:
                detected_software.append(result)
        
        # If discover_all is enabled, also discover non-predefined software
        if self.discover_all:
            print(f"\n[*] Discovering additional software...")
            discovered = self._discover_all_software()
            
            # Add only software not already in the list
            existing_names = {s.productName.lower() for s in detected_software}
            for item in discovered:
                if item.productName.lower() not in existing_names:
                    detected_software.append(item)
                    existing_names.add(item.productName.lower())
        
        print(f"\n[*] Found {len(detected_software)} installed software products\n")
        return detected_software
    
    def _discover_all_software(self) -> List[SoftwareInventoryItem]:
        """
        Discover ALL installed software on the system
        Uses platform-specific commands to list installed applications
        
        Returns:
            List of discovered software items
        """
        discovered = []
        
        if self.os_type not in AUTO_DISCOVERY_CONFIG:
            print(f"  Auto-discovery not configured for {self.os_type}")
            return discovered
        
        os_config = AUTO_DISCOVERY_CONFIG[self.os_type]
        
        # macOS: List GUI applications
        if self.os_type == "macOS":
            discovered.extend(self._discover_macos_apps(os_config))
            discovered.extend(self._discover_brew_packages(os_config))
            discovered.extend(self._discover_cli_tools(os_config))
        
        # Linux: List installed packages
        elif self.os_type == "Linux":
            discovered.extend(self._discover_linux_packages(os_config))
            discovered.extend(self._discover_cli_tools(os_config))
        
        return discovered
    
    def _discover_macos_apps(self, config: Dict) -> List[SoftwareInventoryItem]:
        """Discover macOS applications in /Applications"""
        discovered = []
        
        if "list_apps" not in config:
            return discovered
        
        success, output, _ = self.evidence.execute_command_locally(
            config["list_apps"],
            description="discover_macos_apps",
            timeout=10
        )
        
        if success and output:
            for app_name in output.strip().split('\n'):
                if app_name.strip():
                    # Try to get version from Info.plist
                    version_cmd = f"defaults read '/Applications/{app_name}.app/Contents/Info' CFBundleShortVersionString 2>/dev/null || echo 'unknown'"
                    _, version, _ = self.evidence.execute_command_locally(
                        version_cmd, description=f"version_{app_name}", timeout=3
                    )
                    
                    discovered.append(SoftwareInventoryItem(
                        productName=app_name.strip(),
                        versionNumber=version.strip() if version else "unknown",
                        architecture="unknown",
                        productFamily="Application",
                        vendor="Unknown",
                        installPath=f"/Applications/{app_name}.app",
                        evidence=Evidence(
                            command_run=config["list_apps"],
                            raw_output=app_name
                        )
                    ))
        
        return discovered
    
    def _discover_brew_packages(self, config: Dict) -> List[SoftwareInventoryItem]:
        """Discover Homebrew packages"""
        discovered = []
        
        if "list_brew" not in config:
            return discovered
        
        success, output, _ = self.evidence.execute_command_locally(
            config["list_brew"],
            description="discover_brew_packages",
            timeout=30
        )
        
        if success and output:
            for line in output.strip().split('\n'):
                parts = line.strip().split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1] if len(parts) > 1 else "unknown"
                    
                    discovered.append(SoftwareInventoryItem(
                        productName=name,
                        versionNumber=version,
                        architecture="unknown",
                        productFamily="Homebrew Package",
                        vendor="Unknown",
                        installPath=f"/opt/homebrew/Cellar/{name}",
                        evidence=Evidence(
                            command_run=config["list_brew"],
                            raw_output=line
                        )
                    ))
        
        return discovered
    
    def _discover_cli_tools(self, config: Dict) -> List[SoftwareInventoryItem]:
        """Discover common CLI tools"""
        discovered = []
        
        if "list_cli" not in config:
            return discovered
        
        success, output, _ = self.evidence.execute_command_locally(
            config["list_cli"],
            description="discover_cli_tools",
            timeout=30
        )
        
        if success and output:
            for line in output.strip().split('\n'):
                if '|' in line:
                    parts = line.split('|', 1)
                    name = parts[0].strip()
                    version_str = parts[1].strip() if len(parts) > 1 else "unknown"
                    
                    # Extract version number from output
                    version = self._parse_version_string(version_str)
                    
                    discovered.append(SoftwareInventoryItem(
                        productName=name,
                        versionNumber=version,
                        architecture="unknown",
                        productFamily="CLI Tool",
                        vendor="Unknown",
                        installPath=None,
                        evidence=Evidence(
                            command_run="which " + name,
                            raw_output=version_str
                        )
                    ))
        
        return discovered
    
    def _discover_linux_packages(self, config: Dict) -> List[SoftwareInventoryItem]:
        """Discover Linux packages (apt/rpm/snap/flatpak)"""
        discovered = []
        
        # Try apt (Debian/Ubuntu)
        if "list_apt" in config:
            success, output, _ = self.evidence.execute_command_locally(
                config["list_apt"],
                description="discover_apt_packages",
                timeout=30
            )
            
            if success and output:
                for line in output.strip().split('\n')[:100]:  # Limit to first 100
                    if '|' in line:
                        parts = line.split('|')
                        name = parts[0].strip()
                        version = parts[1].strip() if len(parts) > 1 else "unknown"
                        
                        discovered.append(SoftwareInventoryItem(
                            productName=name,
                            versionNumber=version,
                            architecture="unknown",
                            productFamily="System Package",
                            vendor="Unknown",
                            installPath=None,
                            evidence=Evidence(
                                command_run=config["list_apt"],
                                raw_output=line
                            )
                        ))
        
        # Try rpm (RHEL/CentOS/Fedora)
        if "list_rpm" in config and not discovered:
            success, output, _ = self.evidence.execute_command_locally(
                config["list_rpm"],
                description="discover_rpm_packages",
                timeout=30
            )
            
            if success and output:
                for line in output.strip().split('\n')[:100]:  # Limit to first 100
                    if '|' in line:
                        parts = line.split('|')
                        name = parts[0].strip()
                        version = parts[1].strip() if len(parts) > 1 else "unknown"
                        
                        discovered.append(SoftwareInventoryItem(
                            productName=name,
                            versionNumber=version,
                            architecture="unknown",
                            productFamily="System Package",
                            vendor="Unknown",
                            installPath=None,
                            evidence=Evidence(
                                command_run=config["list_rpm"],
                                raw_output=line
                            )
                        ))
        
        return discovered
