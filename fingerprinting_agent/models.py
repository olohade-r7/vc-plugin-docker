"""
Data models for Fingerprinting Agent output
Defines JSON schema structures using Pydantic for type safety and validation
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class Evidence(BaseModel):
    """Track command executed and raw output for audit trail"""
    command_run: str = Field(..., description="Exact shell command executed")
    raw_output: str = Field(..., description="Literal output from system before parsing")
    execution_timestamp: Optional[str] = Field(None, description="When command was executed")


class SoftwareInventoryItem(BaseModel):
    """Individual software product metadata"""
    productName: str = Field(..., description="Formal name of software")
    versionNumber: str = Field(..., description="Specific version installed")
    architecture: Optional[str] = Field(None, description="arm64, x86_64, etc.")
    productFamily: str = Field(..., description="Category: IDE, Browser, Virtualization, etc.")
    vendor: str = Field(..., description="Company that developed the software")
    installPath: Optional[str] = Field(None, description="Installation directory")
    evidence: Evidence = Field(..., description="Command and raw output proof")


class SystemInfo(BaseModel):
    """Core system attributes"""
    os: str = Field(..., description="Operating System: macOS, Ubuntu, Windows")
    version: str = Field(..., description="OS version: 14.2.1")
    kernel: str = Field(..., description="Kernel version: Darwin 23.2.0")
    cpu: str = Field(..., description="CPU Architecture and model: Apple M2")
    hostname: Optional[str] = Field(None, description="Machine hostname")


class AgentMetadata(BaseModel):
    """Metadata about the fingerprinting scan"""
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    scan_type: str = Field(..., description="local or remote")
    target_host: str = Field(..., description="localhost or remote IP/hostname")
    agent_version: str = Field(default="1.0.0", description="Fingerprinting agent version")


class FingerprintReport(BaseModel):
    """Complete fingerprint report structure"""
    agent_metadata: AgentMetadata = Field(..., description="Scan metadata")
    system_info: SystemInfo = Field(..., description="System specifications")
    software_inventory: List[SoftwareInventoryItem] = Field(
        default_factory=list,
        description="List of detected software products"
    )
    errors: Optional[List[str]] = Field(default_factory=list, description="Any errors encountered")
    summary: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Summary statistics"
    )
