from typing import Optional, Dict, List
from datetime import datetime
from modules.evidence_collector import EvidenceCollector
from modules.system_info import SystemInfoDetector
from modules.software_fingerprinter import SoftwareFingerprinter
from modules.ssh_connector import SSHConnector
from models import FingerprintReport, AgentMetadata, SystemInfo, SoftwareInventoryItem
import json
import os


class FingerprintingAgent:
    
    def __init__(self, scan_type: str = "local", target_host: str = "localhost"):
        """
        Initialize the fingerprinting agent
        
        Args:
            scan_type: "local" or "remote"
            target_host: localhost (for local) or IP/hostname (for remote)
        """
        self.scan_type = scan_type
        self.target_host = target_host
        self.evidence_collector = EvidenceCollector()
        self.report: Optional[FingerprintReport] = None
        self.ssh_connector: Optional[SSHConnector] = None
    
    def scan_local(self) -> FingerprintReport:
        print("\n" + "="*60)
        print("FINGERPRINTING AGENT - LOCAL SCAN")
        print("="*60)
        
        # 1. Collect system information
        print("\n[1/3] Detecting system information...")
        system_detector = SystemInfoDetector(self.evidence_collector)
        system_info_dict = system_detector.detect_all()
        
        system_info = SystemInfo(
            os=system_info_dict["os"],
            version=system_info_dict["version"],
            kernel=system_info_dict["kernel"],
            cpu=system_info_dict["cpu"],
            hostname=system_info_dict["hostname"]
        )
        
        print(f"    ✓ OS: {system_info.os} {system_info.version}")
        print(f"    ✓ Kernel: {system_info.kernel}")
        print(f"    ✓ CPU: {system_info.cpu}")
        
        # 2. Fingerprint installed software
        print("\n[2/3] Fingerprinting installed software...")
        software_fingerprinter = SoftwareFingerprinter(self.evidence_collector)
        software_inventory = software_fingerprinter.fingerprint_all_software()
        
        # 3. Create agent metadata
        print("\n[3/3] Compiling report...")
        agent_metadata = AgentMetadata(
            scan_type=self.scan_type,
            target_host=self.target_host
        )
        
        # 4. Assemble final report
        errors = self.evidence_collector.get_errors() if self.evidence_collector.has_errors() else []
        
        self.report = FingerprintReport(
            agent_metadata=agent_metadata,
            system_info=system_info,
            software_inventory=software_inventory,
            errors=errors,
            summary={
                "total_software_detected": len(software_inventory),
                "scan_type": self.scan_type,
                "execution_status": "success" if not errors else "partial_success"
            }
        )
        
        print(f"    ✓ Report compiled")
        print(f"\n[*] Scan complete!")
        print(f"    Total software detected: {len(software_inventory)}")
        print(f"    Errors: {len(errors)}")
        
        return self.report
    
    def scan_remote(
        self,
        hostname: str,
        username: str,
        port: int = 22,
        password: Optional[str] = None,
        key_file: Optional[str] = None
    ) -> FingerprintReport:
        """
        Perform remote system fingerprinting via SSH
        
        Args:
            hostname: Remote host IP or domain
            username: SSH username
            port: SSH port
            password: Password for authentication
            key_file: SSH key file path
            
        Returns:
            FingerprintReport with all collected data
        """
        print("\n" + "="*60)
        print("FINGERPRINTING AGENT - REMOTE SCAN")
        print(f"Target: {username}@{hostname}:{port}")
        print("="*60)
        
        # Initialize SSH connector
        self.ssh_connector = SSHConnector(
            hostname=hostname,
            username=username,
            port=port,
            password=password,
            key_file=key_file
        )
        
        # Test SSH connection
        print("\n[*] Testing SSH connection...", end=" ")
        if not self.ssh_connector.connect_with_subprocess():
            print("FAILED")
            raise Exception("Cannot establish SSH connection. Check credentials.")
        print("OK")
        
        # 1. Detect remote system information
        print("\n[1/3] Detecting remote system information...")
        system_info_dict = self._detect_remote_system_info()
        
        system_info = SystemInfo(
            os=system_info_dict.get("os", "Unknown"),
            version=system_info_dict.get("version", "unknown"),
            kernel=system_info_dict.get("kernel", "unknown"),
            cpu=system_info_dict.get("cpu", "unknown"),
            hostname=system_info_dict.get("hostname", "unknown")
        )
        
        print(f"    ✓ OS: {system_info.os} {system_info.version}")
        print(f"    ✓ Kernel: {system_info.kernel}")
        print(f"    ✓ CPU: {system_info.cpu}")
        
        # 2. Fingerprint remote software
        print("\n[2/3] Fingerprinting remote software...")
        software_inventory = self._fingerprint_remote_software()
        
        # 3. Create agent metadata
        print("\n[3/3] Compiling report...")
        agent_metadata = AgentMetadata(
            scan_type=self.scan_type,
            target_host=self.target_host
        )
        
        # 4. Assemble final report
        errors = self.evidence_collector.get_errors() if self.evidence_collector.has_errors() else []
        
        self.report = FingerprintReport(
            agent_metadata=agent_metadata,
            system_info=system_info,
            software_inventory=software_inventory,
            errors=errors,
            summary={
                "total_software_detected": len(software_inventory),
                "scan_type": self.scan_type,
                "execution_status": "success" if not errors else "partial_success"
            }
        )
        
        print(f"    ✓ Report compiled")
        print(f"\n[*] Scan complete!")
        print(f"    Total software detected: {len(software_inventory)}")
        print(f"    Errors: {len(errors)}")
        
        return self.report
    
    def _detect_remote_system_info(self) -> Dict[str, str]:
        """Detect system information on remote host via SSH"""
        system_info = {}
        
        # Detect OS type first
        success, output, _ = self.ssh_connector.execute_command("uname -s")
        os_type = output.strip() if success else "Unknown"
        
        if os_type == "Linux":
            # Linux detection
            success, output, _ = self.ssh_connector.execute_command(
                "cat /etc/os-release | grep '^NAME=' | cut -d'=' -f2 | tr -d '\"'"
            )
            system_info["os"] = output.strip() if success else "Linux"
            
            success, output, _ = self.ssh_connector.execute_command(
                "cat /etc/os-release | grep '^VERSION_ID=' | cut -d'=' -f2 | tr -d '\"'"
            )
            system_info["version"] = output.strip() if success else "unknown"
            
        elif os_type == "Darwin":
            # macOS detection
            system_info["os"] = "macOS"
            success, output, _ = self.ssh_connector.execute_command("sw_vers -productVersion")
            system_info["version"] = output.strip() if success else "unknown"
        else:
            system_info["os"] = os_type
            system_info["version"] = "unknown"
        
        # Get kernel
        success, output, _ = self.ssh_connector.execute_command("uname -r")
        system_info["kernel"] = output.strip() if success else "unknown"
        
        # Get CPU
        if os_type == "Linux":
            success, output, _ = self.ssh_connector.execute_command(
                "cat /proc/cpuinfo | grep 'model name' | head -1 | awk -F: '{print $2}' | xargs"
            )
            system_info["cpu"] = output.strip() if success else "unknown"
        elif os_type == "Darwin":
            success, output, _ = self.ssh_connector.execute_command("sysctl -n machdep.cpu.brand_string")
            system_info["cpu"] = output.strip() if success else "unknown"
        else:
            system_info["cpu"] = "unknown"
        
        # Get hostname
        success, output, _ = self.ssh_connector.execute_command("hostname")
        system_info["hostname"] = output.strip() if success else "unknown"
        
        return system_info
    
    def _fingerprint_remote_software(self) -> List[SoftwareInventoryItem]:
        """Fingerprint software on remote host via SSH"""
        from config import TARGET_SOFTWARE
        from models import Evidence
        
        detected_software = []
        
        # Detect OS type to use appropriate commands
        success, os_type, _ = self.ssh_connector.execute_command("uname -s")
        os_type = os_type.strip()
        
        if os_type == "Darwin":
            os_key = "macOS"
        elif os_type == "Linux":
            os_key = "Linux"
        else:
            os_key = "Linux"  # Default to Linux commands
        
        print(f"\n[*] Scanning for software on remote {os_key} system...")
        
        for software_name, software_config in TARGET_SOFTWARE.items():
            if os_key not in software_config:
                continue
            
            os_config = software_config[os_key]
            detection_cmd = os_config.get("detection_command")
            version_cmd = os_config.get("version_command")
            
            if not detection_cmd or not version_cmd:
                continue
            
            print(f"  Checking {software_name}...", end=" ")
            
            # Try to detect software
            success, detection_output, _ = self.ssh_connector.execute_command(detection_cmd)
            
            if not success or not detection_output.strip():
                print("Not found")
                continue
            
            print("Found! Getting version...")
            
            # Get version
            success, version_output, _ = self.ssh_connector.execute_command(version_cmd)
            
            # Parse version
            version = self._parse_version_string(version_output) if success else "unknown"
            install_path = detection_output.strip().split('\n')[0] if detection_output else None
            
            # Create evidence
            evidence = Evidence(
                command_run=detection_cmd,
                raw_output=detection_output.strip()
            )
            
            # Create inventory item
            detected_software.append(SoftwareInventoryItem(
                productName=software_name,
                versionNumber=version,
                architecture="unknown",
                productFamily=software_config.get("productFamily", "Unknown"),
                vendor=software_config.get("vendor", "Unknown"),
                installPath=install_path,
                evidence=evidence
            ))
        
        print(f"\n[*] Found {len(detected_software)} installed software products\n")
        return detected_software
    
    def _parse_version_string(self, version_output: str) -> str:
        """Parse version from command output"""
        import re
        
        if not version_output:
            return "unknown"
        
        patterns = [
            r'v?(\d+\.\d+(?:\.\d+)?)',
            r'version[:\s]+v?(\d+\.\d+(?:\.\d+)?)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, version_output, re.IGNORECASE)
            if match:
                return match.group(1)
        
        parts = version_output.split()
        return parts[0] if parts else "unknown"
    
    def export_report(self, output_path: str = "output/fingerprint_report.json") -> str:
        """
        Export fingerprint report to JSON file
        
        Args:
            output_path: Path where to save the report
            
        Returns:
            Path to saved file
        """
        if not self.report:
            raise Exception("No report to export. Run scan first.")
        
        # Create output directory if it doesn't exist
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        
        # Convert report to JSON
        report_dict = self.report.dict()
        
        # Write to file
        with open(output_path, 'w') as f:
            json.dump(report_dict, f, indent=2)
        
        print(f"\n[✓] Report exported to: {output_path}")
        return output_path
    
    def print_report_summary(self):
        """Print a human-readable summary of the report"""
        if not self.report:
            print("No report to display")
            return
        
        print("\n" + "="*60)
        print("FINGERPRINT REPORT SUMMARY")
        print("="*60)
        
        print(f"\nAgent Metadata:")
        print(f"  Timestamp: {self.report.agent_metadata.timestamp}")
        print(f"  Scan Type: {self.report.agent_metadata.scan_type}")
        print(f"  Target Host: {self.report.agent_metadata.target_host}")
        
        print(f"\nSystem Information:")
        sys = self.report.system_info
        print(f"  OS: {sys.os} {sys.version}")
        print(f"  Kernel: {sys.kernel}")
        print(f"  CPU: {sys.cpu}")
        print(f"  Hostname: {sys.hostname}")
        
        print(f"\nSoftware Inventory ({len(self.report.software_inventory)} items):")
        for idx, software in enumerate(self.report.software_inventory, 1):
            print(f"  {idx}. {software.productName}")
            print(f"     Version: {software.versionNumber}")
            print(f"     Vendor: {software.vendor}")
            print(f"     Family: {software.productFamily}")
            if software.installPath:
                print(f"     Path: {software.installPath}")
            print(f"     Evidence: {software.evidence.command_run}")
        
        if self.report.errors:
            print(f"\nErrors ({len(self.report.errors)}):")
            for error in self.report.errors:
                print(f"  - {error}")
        
        print("\n" + "="*60 + "\n")
