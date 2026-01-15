"""
Content File Transformers

This module transforms Pydantic models into Rapid7 standard content files:
- .xml: Vulnerability metadata and details
- .vck: Vulnerability check definitions
- .sol: Solution/remediation information
"""

import os
from typing import Dict, List
from datetime import datetime
from xml.etree.ElementTree import Element, SubElement, tostring
from xml.dom import minidom
from models import VulnerabilityContent, VulnerabilityDetail, VulnerabilityCheck, Solution


class XMLTransformer:
    """Transform vulnerability data into XML format following Rapid7 standards"""
    
    @staticmethod
    def create_vulnerability_xml(vuln_content: VulnerabilityContent) -> str:
        """
        Create XML representation of vulnerability
        
        Args:
            vuln_content: VulnerabilityContent object
            
        Returns:
            Formatted XML string
        """
        vuln = vuln_content.vulnerability
        
        # Root element
        root = Element('vulnerability')
        root.set('version', vuln_content.content_version)
        root.set('generated_at', vuln_content.generated_at.isoformat())
        
        # Metadata section
        metadata = SubElement(root, 'metadata')
        XMLTransformer._add_element(metadata, 'id', vuln_content.get_primary_cve())
        XMLTransformer._add_element(metadata, 'title', vuln.title)
        XMLTransformer._add_element(metadata, 'severity', vuln.severity)
        XMLTransformer._add_element(metadata, 'published', vuln.published_date.isoformat())
        
        if vuln.last_updated:
            XMLTransformer._add_element(metadata, 'last_updated', vuln.last_updated.isoformat())
        
        # Description section
        description_elem = SubElement(root, 'description')
        description_elem.text = vuln.description
        
        # Summary
        if vuln.summary:
            summary_elem = SubElement(root, 'summary')
            summary_elem.text = vuln.summary
        
        # CVE References
        if vuln.cve_references:
            cve_section = SubElement(root, 'cve_references')
            for cve_ref in vuln.cve_references:
                cve_elem = SubElement(cve_section, 'cve')
                XMLTransformer._add_element(cve_elem, 'id', cve_ref.cve_id)
                XMLTransformer._add_element(cve_elem, 'url', cve_ref.url)
                
                if cve_ref.cvss:
                    cvss_elem = SubElement(cve_elem, 'cvss')
                    XMLTransformer._add_element(cvss_elem, 'version', cve_ref.cvss.version)
                    if cve_ref.cvss.base_score:
                        XMLTransformer._add_element(cvss_elem, 'base_score', str(cve_ref.cvss.base_score))
                    if cve_ref.cvss.vector_string:
                        XMLTransformer._add_element(cvss_elem, 'vector', cve_ref.cvss.vector_string)
                    if cve_ref.cvss.severity:
                        XMLTransformer._add_element(cvss_elem, 'severity', cve_ref.cvss.severity)
        
        # Affected Versions
        if vuln.affected_versions:
            affected_section = SubElement(root, 'affected_versions')
            for affected in vuln.affected_versions:
                affected_elem = SubElement(affected_section, 'product')
                XMLTransformer._add_element(affected_elem, 'name', affected.product)
                XMLTransformer._add_element(affected_elem, 'version_affected', affected.version_affected)
                if affected.fixed_in:
                    XMLTransformer._add_element(affected_elem, 'fixed_in', affected.fixed_in)
        
        # Impact
        if vuln.impact:
            impact_elem = SubElement(root, 'impact')
            impact_elem.text = vuln.impact
        
        # Technical Details
        if vuln.technical_details:
            tech_elem = SubElement(root, 'technical_details')
            tech_elem.text = vuln.technical_details
        
        # Exploit Information
        exploit_elem = SubElement(root, 'exploit_information')
        XMLTransformer._add_element(exploit_elem, 'exploit_available', str(vuln.exploit_available).lower())
        if vuln.proof_of_concept:
            XMLTransformer._add_element(exploit_elem, 'proof_of_concept', vuln.proof_of_concept)
        
        # Solution
        solution_elem = SubElement(root, 'solution')
        solution_elem.text = vuln.solution
        
        # Workaround
        if vuln.workaround:
            workaround_elem = SubElement(root, 'workaround')
            workaround_elem.text = vuln.workaround
        
        # External References
        if vuln.external_references:
            refs_section = SubElement(root, 'references')
            for ref in vuln.external_references:
                XMLTransformer._add_element(refs_section, 'reference', ref)
        
        # Format and return
        return XMLTransformer._prettify_xml(root)
    
    @staticmethod
    def _add_element(parent: Element, tag: str, text: str) -> Element:
        """Helper to add a child element with text"""
        elem = SubElement(parent, tag)
        elem.text = str(text) if text is not None else ""
        return elem
    
    @staticmethod
    def _prettify_xml(elem: Element) -> str:
        """Return a pretty-printed XML string"""
        rough_string = tostring(elem, encoding='utf-8')
        reparsed = minidom.parseString(rough_string)
        return reparsed.toprettyxml(indent="  ", encoding='utf-8').decode('utf-8')


class VCKTransformer:
    """Transform vulnerability check data into .vck format"""
    
    @staticmethod
    def create_vck_content(vuln_content: VulnerabilityContent) -> str:
        """
        Create .vck file content
        
        VCK files define how to check if a system is vulnerable.
        Format is custom but typically includes:
        - Check ID
        - Description
        - Detection logic
        - Version checks
        
        Args:
            vuln_content: VulnerabilityContent object
            
        Returns:
            VCK file content as string
        """
        check = vuln_content.check
        vuln = vuln_content.vulnerability
        
        lines = []
        
        # Header
        lines.append("# Rapid7 Vulnerability Check File")
        lines.append(f"# Generated: {vuln_content.generated_at.isoformat()}")
        lines.append(f"# Generator: {vuln_content.generated_by}")
        lines.append("")
        
        # Check Information
        lines.append("[CHECK_INFO]")
        lines.append(f"check_id = {check.check_id}")
        lines.append(f"cve_id = {check.cve_id}")
        lines.append(f"title = {vuln.title}")
        lines.append(f"severity = {vuln.severity}")
        lines.append(f"check_type = {check.check_type}")
        lines.append(f"confidence = {check.confidence}")
        lines.append(f"false_positive_risk = {check.false_positive_risk}")
        lines.append("")
        
        # Description
        lines.append("[DESCRIPTION]")
        lines.append(check.check_description)
        lines.append("")
        
        # Detection Logic
        lines.append("[DETECTION]")
        
        if check.vulnerable_versions:
            lines.append("# Vulnerable versions")
            lines.append("vulnerable_versions = [")
            for ver in check.vulnerable_versions:
                lines.append(f"  \"{ver}\",")
            lines.append("]")
            lines.append("")
        
        if check.safe_versions:
            lines.append("# Safe versions")
            lines.append("safe_versions = [")
            for ver in check.safe_versions:
                lines.append(f"  \"{ver}\",")
            lines.append("]")
            lines.append("")
        
        if check.detection_patterns:
            lines.append("# Detection patterns")
            lines.append("detection_patterns = [")
            for pattern in check.detection_patterns:
                lines.append(f"  \"{pattern}\",")
            lines.append("]")
            lines.append("")
        
        # Check Logic (pseudo-code example)
        lines.append("[CHECK_LOGIC]")
        lines.append("# Pseudo-code for vulnerability detection")
        lines.append("def check_vulnerability():")
        lines.append("    # Get installed product version")
        lines.append("    installed_version = get_product_version()")
        lines.append("    ")
        lines.append("    # Check if version is vulnerable")
        lines.append("    if version_matches(installed_version, vulnerable_versions):")
        lines.append("        return VULNERABLE")
        lines.append("    ")
        lines.append("    # Check if version is safe")
        lines.append("    if version_matches(installed_version, safe_versions):")
        lines.append("        return SAFE")
        lines.append("    ")
        lines.append("    return UNKNOWN")
        lines.append("")
        
        # References
        if vuln.external_references:
            lines.append("[REFERENCES]")
            for ref in vuln.external_references:
                lines.append(f"# {ref}")
            lines.append("")
        
        return "\n".join(lines)


class SOLTransformer:
    """Transform solution data into .sol format"""
    
    @staticmethod
    def create_sol_content(vuln_content: VulnerabilityContent) -> str:
        """
        Create .sol file content
        
        SOL files contain remediation guidance and solution steps.
        
        Args:
            vuln_content: VulnerabilityContent object
            
        Returns:
            SOL file content as string
        """
        solution = vuln_content.solution
        vuln = vuln_content.vulnerability
        
        lines = []
        
        # Header
        lines.append("# Rapid7 Solution File")
        lines.append(f"# Generated: {vuln_content.generated_at.isoformat()}")
        lines.append(f"# Generator: {vuln_content.generated_by}")
        lines.append("")
        
        # Solution Information
        lines.append("[SOLUTION_INFO]")
        lines.append(f"solution_id = {solution.solution_id}")
        lines.append(f"cve_ids = {', '.join(solution.cve_ids)}")
        lines.append(f"title = {solution.title}")
        lines.append(f"downtime_required = {solution.downtime_required}")
        if solution.estimated_time:
            lines.append(f"estimated_time = {solution.estimated_time}")
        lines.append("")
        
        # Summary
        lines.append("[SUMMARY]")
        lines.append(solution.summary)
        lines.append("")
        
        # Prerequisites
        if solution.prerequisites:
            lines.append("[PREREQUISITES]")
            for i, prereq in enumerate(solution.prerequisites, 1):
                lines.append(f"{i}. {prereq}")
            lines.append("")
        
        # Remediation Steps
        lines.append("[REMEDIATION_STEPS]")
        lines.append("# Follow these steps to remediate the vulnerability")
        lines.append("")
        for step in solution.detailed_steps:
            lines.append(step)
        lines.append("")
        
        # Verification Steps
        if solution.verification_steps:
            lines.append("[VERIFICATION]")
            lines.append("# Steps to verify the solution was applied successfully")
            lines.append("")
            for i, step in enumerate(solution.verification_steps, 1):
                lines.append(f"{i}. {step}")
            lines.append("")
        
        # Rollback Steps
        if solution.rollback_steps:
            lines.append("[ROLLBACK]")
            lines.append("# Steps to rollback the solution if needed")
            lines.append("")
            for i, step in enumerate(solution.rollback_steps, 1):
                lines.append(f"{i}. {step}")
            lines.append("")
        
        # Vendor Advisory
        if solution.vendor_advisory_url:
            lines.append("[VENDOR_ADVISORY]")
            lines.append(solution.vendor_advisory_url)
            lines.append("")
        
        # Additional References
        if solution.additional_references:
            lines.append("[ADDITIONAL_REFERENCES]")
            for ref in solution.additional_references:
                lines.append(f"- {ref}")
            lines.append("")
        
        # Related Vulnerabilities
        lines.append("[RELATED_VULNERABILITIES]")
        for cve_ref in vuln.cve_references:
            lines.append(f"- {cve_ref.cve_id}: {cve_ref.url}")
        lines.append("")
        
        return "\n".join(lines)


class ContentFileManager:
    """Manages writing content files to disk"""
    
    def __init__(self, output_dir: str = "Content/Docker"):
        """
        Initialize the content file manager
        
        Args:
            output_dir: Directory where content files will be stored
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def write_content_files(self, vuln_content: VulnerabilityContent) -> Dict[str, str]:
        """
        Write all three content files for a vulnerability
        
        Args:
            vuln_content: VulnerabilityContent object
            
        Returns:
            Dictionary mapping file type to file path
        """
        base_filename = vuln_content.get_filename_base()
        
        files_written = {}
        
        # Write XML file
        xml_content = XMLTransformer.create_vulnerability_xml(vuln_content)
        xml_path = os.path.join(self.output_dir, f"{base_filename}.xml")
        with open(xml_path, 'w', encoding='utf-8') as f:
            f.write(xml_content)
        files_written['xml'] = xml_path
        
        # Write VCK file
        vck_content = VCKTransformer.create_vck_content(vuln_content)
        vck_path = os.path.join(self.output_dir, f"{base_filename}.vck")
        with open(vck_path, 'w', encoding='utf-8') as f:
            f.write(vck_content)
        files_written['vck'] = vck_path
        
        # Write SOL file
        sol_content = SOLTransformer.create_sol_content(vuln_content)
        sol_path = os.path.join(self.output_dir, f"{base_filename}.sol")
        with open(sol_path, 'w', encoding='utf-8') as f:
            f.write(sol_content)
        files_written['sol'] = sol_path
        
        return files_written
    
    def write_batch(self, vuln_contents: List[VulnerabilityContent]) -> List[Dict[str, str]]:
        """
        Write multiple vulnerability content files
        
        Args:
            vuln_contents: List of VulnerabilityContent objects
            
        Returns:
            List of dictionaries mapping file types to file paths
        """
        all_files = []
        
        for vuln_content in vuln_contents:
            try:
                files = self.write_content_files(vuln_content)
                all_files.append(files)
                print(f"  ✓ Generated files for {vuln_content.get_primary_cve()}")
            except Exception as e:
                print(f"  ✗ Error generating files for {vuln_content.get_primary_cve()}: {e}")
        
        return all_files


if __name__ == "__main__":
    # Test the transformers with sample data
    from models import (
        VulnerabilityContent, VulnerabilityDetail, VulnerabilityCheck, 
        Solution, CVEReference, AffectedVersion, SeverityLevel
    )
    
    # Create sample vulnerability content
    cve_ref = CVEReference(
        cve_id="CVE-2025-13743",
        url="https://cve.org/CVERecord?id=CVE-2025-13743",
        description="Expired Hub PATs in Docker Desktop diagnostics"
    )
    
    affected = AffectedVersion(
        product="Docker Desktop",
        version_affected="< 4.54.0",
        fixed_in="4.54.0"
    )
    
    vuln_detail = VulnerabilityDetail(
        title="Docker Desktop 4.54.0 security update: CVE-2025-13743",
        description="Docker Desktop diagnostics bundles were found to include expired Hub PATs in log output due to error object serialization.",
        severity=SeverityLevel.MEDIUM,
        cve_references=[cve_ref],
        affected_versions=[affected],
        solution="Update Docker Desktop to version 4.54.0 or later",
        external_references=["https://docs.docker.com/desktop/release-notes/#4540"]
    )
    
    check = VulnerabilityCheck(
        check_id="docker-desktop-cve-2025-13743",
        cve_id="CVE-2025-13743",
        check_description="Check if Docker Desktop version is vulnerable to CVE-2025-13743",
        vulnerable_versions=["< 4.54.0"],
        safe_versions=[">= 4.54.0"]
    )
    
    solution = Solution(
        solution_id="sol-docker-desktop-cve-2025-13743",
        cve_ids=["CVE-2025-13743"],
        title="Update Docker Desktop to version 4.54.0 or later",
        summary="Install the latest Docker Desktop version to fix CVE-2025-13743",
        detailed_steps=[
            "1. Download Docker Desktop 4.54.0 or later from https://www.docker.com/products/docker-desktop",
            "2. Close all running Docker containers",
            "3. Run the installer",
            "4. Restart Docker Desktop",
            "5. Verify the version using: docker version"
        ],
        verification_steps=[
            "Run 'docker version' and confirm version is 4.54.0 or higher"
        ],
        vendor_advisory_url="https://docs.docker.com/security/security-announcements/"
    )
    
    vuln_content = VulnerabilityContent(
        vulnerability=vuln_detail,
        check=check,
        solution=solution
    )
    
    # Write files
    manager = ContentFileManager()
    files = manager.write_content_files(vuln_content)
    
    print("\nTest files generated:")
    for file_type, path in files.items():
        print(f"  {file_type.upper()}: {path}")
