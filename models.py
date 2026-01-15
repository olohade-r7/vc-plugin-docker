"""
Pydantic Models for Docker Security Vulnerabilities

These models validate and structure vulnerability data according to Rapid7 standards.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, validator, HttpUrl
from enum import Enum


class SeverityLevel(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class ProductType(str, Enum):
    """Docker product types"""
    DOCKER_DESKTOP = "Docker Desktop"
    DOCKER_ENGINE = "Docker Engine"
    DOCKER_HUB = "Docker Hub"
    BUILDKIT = "BuildKit"
    RUNC = "runc"
    MOBY = "Moby"


class CVSSScore(BaseModel):
    """CVSS scoring information"""
    version: str = Field(default="3.1", description="CVSS version")
    base_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    vector_string: Optional[str] = None
    severity: Optional[SeverityLevel] = None
    
    class Config:
        use_enum_values = True


class CVEReference(BaseModel):
    """CVE reference information"""
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,7}$")
    url: str
    description: Optional[str] = None
    cvss: Optional[CVSSScore] = None
    published_date: Optional[datetime] = None
    last_modified_date: Optional[datetime] = None
    
    @validator('cve_id')
    def validate_cve_format(cls, v):
        """Ensure CVE ID is properly formatted"""
        if not v.startswith('CVE-'):
            raise ValueError('CVE ID must start with "CVE-"')
        return v.upper()


class AffectedVersion(BaseModel):
    """Information about affected product versions"""
    product: str
    version_affected: str = Field(..., description="Version or version range affected")
    fixed_in: Optional[str] = Field(None, description="Version where vulnerability is fixed")
    
    class Config:
        json_schema_extra = {
            "examples": [
                {
                    "product": "Docker Desktop",
                    "version_affected": "<= 4.27.0",
                    "fixed_in": "4.27.1"
                }
            ]
        }


class VulnerabilityDetail(BaseModel):
    """Detailed vulnerability information"""
    title: str = Field(..., min_length=10, max_length=500)
    description: str = Field(..., min_length=20)
    summary: Optional[str] = Field(None, description="Short summary for reports")
    
    # CVE Information
    cve_references: List[CVEReference] = Field(default_factory=list)
    
    # Severity and Impact
    severity: SeverityLevel = Field(default=SeverityLevel.MEDIUM)
    impact: Optional[str] = Field(None, description="Impact description")
    
    # Affected Products
    affected_versions: List[AffectedVersion] = Field(default_factory=list)
    
    # Technical Details
    technical_details: Optional[str] = None
    exploit_available: bool = Field(default=False)
    proof_of_concept: Optional[str] = None
    
    # Remediation
    solution: str = Field(..., description="How to fix the vulnerability")
    workaround: Optional[str] = Field(None, description="Temporary workaround if available")
    
    # Metadata
    disclosed_date: Optional[datetime] = None
    published_date: datetime = Field(default_factory=datetime.now)
    last_updated: Optional[datetime] = None
    
    # References
    external_references: List[str] = Field(default_factory=list)
    
    # Raw data for reference
    raw_data: Optional[Dict[str, Any]] = Field(default=None, exclude=True)
    
    @validator('summary', always=True)
    def generate_summary(cls, v, values):
        """Generate summary from description if not provided"""
        if v is None and 'description' in values:
            desc = values['description']
            v = desc[:200] + '...' if len(desc) > 200 else desc
        return v
    
    class Config:
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class VulnerabilityCheck(BaseModel):
    """
    Vulnerability check information for .vck files
    Defines how to detect if a system is vulnerable
    """
    check_id: str = Field(..., description="Unique identifier for this check")
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,7}$")
    
    # Check logic
    check_type: str = Field(default="version", description="Type of check: version, config, etc.")
    check_description: str
    
    # Detection criteria
    detection_patterns: List[str] = Field(default_factory=list)
    vulnerable_versions: List[str] = Field(default_factory=list)
    safe_versions: List[str] = Field(default_factory=list)
    
    # Check metadata
    confidence: str = Field(default="HIGH", description="Confidence level: HIGH, MEDIUM, LOW")
    false_positive_risk: str = Field(default="LOW")
    
    class Config:
        json_schema_extra = {
            "examples": [
                {
                    "check_id": "docker-desktop-cve-2025-13743",
                    "cve_id": "CVE-2025-13743",
                    "check_type": "version",
                    "check_description": "Check if Docker Desktop version is vulnerable to CVE-2025-13743",
                    "vulnerable_versions": ["< 4.54.0"],
                    "safe_versions": [">= 4.54.0"]
                }
            ]
        }


class Solution(BaseModel):
    """
    Solution information for .sol files
    Provides remediation steps and guidance
    """
    solution_id: str = Field(..., description="Unique identifier for this solution")
    cve_ids: List[str] = Field(..., description="CVE IDs this solution addresses")
    
    # Solution content
    title: str
    summary: str
    detailed_steps: List[str] = Field(..., description="Step-by-step remediation instructions")
    
    # Additional guidance
    prerequisites: List[str] = Field(default_factory=list)
    verification_steps: List[str] = Field(default_factory=list)
    rollback_steps: Optional[List[str]] = None
    
    # Impact of applying solution
    downtime_required: bool = Field(default=False)
    estimated_time: Optional[str] = Field(None, description="Estimated time to apply solution")
    
    # References
    vendor_advisory_url: Optional[str] = None
    additional_references: List[str] = Field(default_factory=list)
    
    class Config:
        json_schema_extra = {
            "examples": [
                {
                    "solution_id": "sol-docker-desktop-cve-2025-13743",
                    "cve_ids": ["CVE-2025-13743"],
                    "title": "Update Docker Desktop to version 4.54.0 or later",
                    "summary": "Install the latest Docker Desktop version to fix CVE-2025-13743",
                    "detailed_steps": [
                        "1. Download Docker Desktop 4.54.0 or later from official website",
                        "2. Close all running Docker containers",
                        "3. Install the update",
                        "4. Restart Docker Desktop",
                        "5. Verify version using 'docker version' command"
                    ]
                }
            ]
        }


class VulnerabilityContent(BaseModel):
    """
    Complete vulnerability content package
    Combines all information needed for .xml, .vck, and .sol files
    """
    vulnerability: VulnerabilityDetail
    check: VulnerabilityCheck
    solution: Solution
    
    # Content metadata
    content_version: str = Field(default="1.0")
    generated_at: datetime = Field(default_factory=datetime.now)
    generated_by: str = Field(default="Docker Security Advisory VC Plugin")
    
    def get_primary_cve(self) -> str:
        """Get the primary CVE ID"""
        if self.vulnerability.cve_references:
            return self.vulnerability.cve_references[0].cve_id
        return "UNKNOWN"
    
    def get_filename_base(self) -> str:
        """Generate base filename for content files"""
        primary_cve = self.get_primary_cve()
        product = "docker"
        return f"{product}_{primary_cve.lower()}"
    
    class Config:
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


# Data transformation helpers
class VulnerabilityParser:
    """Helper class to parse raw scraped data into Pydantic models"""
    
    @staticmethod
    def parse_severity(text: str) -> SeverityLevel:
        """Parse severity from text"""
        text_lower = text.lower()
        if 'critical' in text_lower:
            return SeverityLevel.CRITICAL
        elif 'high' in text_lower:
            return SeverityLevel.HIGH
        elif 'medium' in text_lower or 'moderate' in text_lower:
            return SeverityLevel.MEDIUM
        elif 'low' in text_lower:
            return SeverityLevel.LOW
        return SeverityLevel.INFO
    
    @staticmethod
    def parse_date(date_str: Optional[str]) -> Optional[datetime]:
        """Parse date from various formats"""
        if not date_str:
            return None
        
        from dateutil import parser
        try:
            return parser.parse(date_str)
        except:
            return None
    
    @staticmethod
    def extract_version_info(text: str) -> tuple[Optional[str], Optional[str]]:
        """
        Extract affected version and fixed version from text
        
        Returns:
            Tuple of (affected_version, fixed_version)
        """
        import re
        
        # Look for version patterns
        affected = None
        fixed = None
        
        # Pattern: "version X.Y.Z" or "versions X.Y.Z"
        version_pattern = r'(?:version|versions?)\s+([\d.]+)'
        
        # Pattern: "fixed in X.Y.Z"
        fixed_pattern = r'fixed in.*?([\d.]+)'
        
        version_match = re.search(version_pattern, text, re.IGNORECASE)
        if version_match:
            affected = version_match.group(1)
        
        fixed_match = re.search(fixed_pattern, text, re.IGNORECASE)
        if fixed_match:
            fixed = fixed_match.group(1)
        
        return affected, fixed
