"""
System Information Detection Module
Detects OS, version, kernel, CPU architecture with evidence tracking
WHY: Foundational data - we need to know WHAT system we're scanning
"""

import platform
from typing import Optional, Dict, Any
from modules.evidence_collector import EvidenceCollector
from config import SYSTEM_INFO_COMMANDS


class SystemInfoDetector:
    """
    Detects core system specifications
    Automatically handles platform differences (macOS vs Linux vs Windows)
    """
    
    def __init__(self, evidence_collector: EvidenceCollector):
        """
        Initialize with evidence collector
        
        Args:
            evidence_collector: EvidenceCollector instance for tracking commands
        """
        self.evidence = evidence_collector
        self.os_type = self._detect_os_type()
        self.commands = SYSTEM_INFO_COMMANDS.get(self.os_type, {})
    
    def _detect_os_type(self) -> str:
        """
        Detect which operating system we're running on
        Uses Python's platform module as first pass
        
        Returns:
            "macOS", "Linux", or "Windows"
        """
        system = platform.system()
        
        if system == "Darwin":
            return "macOS"
        elif system == "Linux":
            return "Linux"
        elif system == "Windows":
            return "Windows"
        else:
            return "Unknown"
    
    def get_os_name(self) -> str:
        """Get operating system name"""
        if self.os_type == "macOS":
            return "macOS"
        elif self.os_type == "Windows":
            return "Windows"
        
        # For Linux, use command
        cmd, expected_value = self.commands.get("os_name", ("echo Unknown", None))
        success, output, _ = self.evidence.execute_command_locally(
            cmd,
            description="detect_os_name"
        )
        return output if success and output else self.os_type
    
    def get_os_version(self) -> str:
        """Get OS version number"""
        cmd, _ = self.commands.get("os_version", ("uname -v", None))
        success, output, _ = self.evidence.execute_command_locally(
            cmd,
            description="detect_os_version"
        )
        return output if success and output else "unknown"
    
    def get_kernel_version(self) -> str:
        """Get kernel version"""
        cmd, _ = self.commands.get("kernel", ("uname -r", None))
        success, output, _ = self.evidence.execute_command_locally(
            cmd,
            description="detect_kernel_version"
        )
        return output if success and output else "unknown"
    
    def get_cpu_info(self) -> Dict[str, str]:
        """
        Get CPU information (name and architecture)
        
        Returns:
            {"cpu": "Apple M2", "arch": "arm64"}
        """
        cpu_name = "unknown"
        cpu_arch = "unknown"
        
        # Get CPU name
        if "cpu" in self.commands:
            cmd, _ = self.commands["cpu"]
            success, output, _ = self.evidence.execute_command_locally(
                cmd,
                description="detect_cpu_name"
            )
            if success and output:
                cpu_name = output
        
        # Get CPU architecture
        if "cpu_arch" in self.commands:
            cmd, _ = self.commands["cpu_arch"]
            success, output, _ = self.evidence.execute_command_locally(
                cmd,
                description="detect_cpu_arch"
            )
            if success and output:
                cpu_arch = output
        
        return {
            "cpu": cpu_name,
            "arch": cpu_arch
        }
    
    def get_hostname(self) -> str:
        """Get system hostname"""
        cmd, _ = self.commands.get("hostname", ("hostname", None))
        success, output, _ = self.evidence.execute_command_locally(
            cmd,
            description="detect_hostname"
        )
        return output if success and output else "unknown"
    
    def detect_all(self) -> Dict[str, Any]:
        """
        Collect all system information
        
        Returns:
            Dictionary with all system details
        """
        cpu_info = self.get_cpu_info()
        
        return {
            "os": self.get_os_name(),
            "version": self.get_os_version(),
            "kernel": self.get_kernel_version(),
            "cpu": cpu_info["cpu"],
            "architecture": cpu_info["arch"],
            "hostname": self.get_hostname(),
            "os_type": self.os_type  # Internal tracking
        }
