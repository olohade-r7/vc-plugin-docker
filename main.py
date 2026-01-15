"""
Main Pipeline Orchestrator

This script coordinates the complete vulnerability content generation pipeline:
1. Scrape Docker security advisories
2. Parse and validate data with Pydantic models
3. Transform into Rapid7 content files (.xml, .vck, .sol)
4. Store files in Content/Docker directory
"""

import os
import json
import sys
from typing import List, Dict
from datetime import datetime

from scraper import DockerSecurityScraper
from models import (
    VulnerabilityContent, VulnerabilityDetail, VulnerabilityCheck, Solution,
    CVEReference, AffectedVersion, SeverityLevel, VulnerabilityParser
)
from transformers import ContentFileManager


class VulnerabilityContentGenerator:
    """Main pipeline for generating vulnerability content"""
    
    def __init__(self, raw_data_dir: str = "raw_data", content_dir: str = "Content/Docker"):
        """
        Initialize the generator
        
        Args:
            raw_data_dir: Directory containing scraped data
            content_dir: Directory to store generated content files
        """
        self.raw_data_dir = raw_data_dir
        self.content_dir = content_dir
        self.parser = VulnerabilityParser()
        self.file_manager = ContentFileManager(content_dir)
    
    def load_scraped_data(self) -> Dict:
        """Load scraped vulnerability data from JSON"""
        json_path = os.path.join(self.raw_data_dir, "json", "all_vulnerabilities.json")
        
        if not os.path.exists(json_path):
            raise FileNotFoundError(f"Scraped data not found at {json_path}. Run scraper first.")
        
        with open(json_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def parse_vulnerability(self, raw_vuln: Dict) -> VulnerabilityContent:
        """
        Parse raw vulnerability data into Pydantic models
        
        Args:
            raw_vuln: Raw vulnerability dictionary from scraper
            
        Returns:
            VulnerabilityContent object
        """
        # Extract basic information
        title = raw_vuln.get('title', 'Unknown Vulnerability')
        description = raw_vuln.get('description', '')
        cve_ids = raw_vuln.get('cve_ids', [])
        
        if not cve_ids:
            # Extract from title if not found
            import re
            cve_ids = re.findall(r'CVE-\d{4}-\d{4,7}', title)
        
        # Determine severity from title or content
        severity = SeverityLevel.MEDIUM  # Default
        severity_keywords = {
            'critical': SeverityLevel.CRITICAL,
            'high': SeverityLevel.HIGH,
            'medium': SeverityLevel.MEDIUM,
            'moderate': SeverityLevel.MEDIUM,
            'low': SeverityLevel.LOW
        }
        
        title_lower = title.lower()
        desc_lower = description.lower()
        for keyword, sev_level in severity_keywords.items():
            if keyword in title_lower or keyword in desc_lower:
                severity = sev_level
                break
        
        # Create CVE references
        cve_references = []
        for cve_id in cve_ids[:1]:  # Primary CVE
            cve_url = f"https://cve.org/CVERecord?id={cve_id}"
            cve_ref = CVEReference(
                cve_id=cve_id,
                url=cve_url,
                description=description[:200] if description else None
            )
            cve_references.append(cve_ref)
        
        # Extract version information
        fixed_version = raw_vuln.get('fixed_version', '')
        
        # Create affected versions
        affected_versions = []
        if fixed_version:
            # Try to extract version number
            import re
            version_match = re.search(r'([\d.]+)', fixed_version)
            if version_match:
                version_num = version_match.group(1)
                affected = AffectedVersion(
                    product="Docker Desktop",
                    version_affected=f"< {version_num}",
                    fixed_in=version_num
                )
                affected_versions.append(affected)
        
        # Create solution text
        solution_text = f"Update to the latest version"
        if fixed_version:
            solution_text = f"Update to Docker Desktop {fixed_version} or later"
        
        # Extract details for solution steps
        detailed_steps = [
            "1. Visit the Docker Desktop download page: https://www.docker.com/products/docker-desktop",
            "2. Download the latest version for your operating system",
            "3. Close all running Docker containers and applications",
            "4. Run the installer to update Docker Desktop",
            "5. Restart Docker Desktop after installation",
            "6. Verify the installation by running: docker version"
        ]
        
        # Check for specific details in raw data
        details = raw_vuln.get('details', [])
        if details:
            # Use actual details if available
            detailed_steps = [f"{i+1}. {detail}" for i, detail in enumerate(details[:6])]
        
        # External references
        external_refs = []
        for link_data in raw_vuln.get('cve_links', []):
            external_refs.append(link_data.get('url', ''))
        
        # Add release notes link if available
        external_refs.append("https://docs.docker.com/desktop/release-notes/")
        external_refs.append("https://docs.docker.com/security/security-announcements/")
        
        # Create vulnerability detail
        vuln_detail = VulnerabilityDetail(
            title=title,
            description=description or "Security vulnerability in Docker Desktop",
            severity=severity,
            cve_references=cve_references,
            affected_versions=affected_versions,
            solution=solution_text,
            external_references=[ref for ref in external_refs if ref],
            published_date=datetime.now(),
            raw_data=raw_vuln
        )
        
        # Create vulnerability check
        primary_cve = cve_ids[0] if cve_ids else "UNKNOWN"
        check_id = f"docker-{primary_cve.lower().replace('cve-', 'cve-')}"
        
        vulnerable_versions = []
        safe_versions = []
        
        if fixed_version:
            import re
            version_match = re.search(r'([\d.]+)', fixed_version)
            if version_match:
                version_num = version_match.group(1)
                vulnerable_versions.append(f"< {version_num}")
                safe_versions.append(f">= {version_num}")
        
        check = VulnerabilityCheck(
            check_id=check_id,
            cve_id=primary_cve,
            check_description=f"Check if Docker Desktop is vulnerable to {primary_cve}",
            check_type="version",
            vulnerable_versions=vulnerable_versions,
            safe_versions=safe_versions,
            detection_patterns=[
                "Docker Desktop",
                primary_cve
            ]
        )
        
        # Create solution
        solution = Solution(
            solution_id=f"sol-{check_id}",
            cve_ids=cve_ids,
            title=f"Update Docker Desktop to remediate {primary_cve}",
            summary=solution_text,
            detailed_steps=detailed_steps,
            verification_steps=[
                "Run 'docker version' command",
                f"Verify Docker Desktop version is {fixed_version} or higher" if fixed_version else "Verify Docker Desktop is updated",
                "Check that all containers start normally after update"
            ],
            vendor_advisory_url="https://docs.docker.com/security/security-announcements/",
            additional_references=external_refs[:3],
            downtime_required=True,
            estimated_time="15-30 minutes"
        )
        
        # Create complete vulnerability content
        vuln_content = VulnerabilityContent(
            vulnerability=vuln_detail,
            check=check,
            solution=solution
        )
        
        return vuln_content
    
    def generate_all_content(self) -> Dict:
        """
        Generate content files for all vulnerabilities
        
        Returns:
            Dictionary with generation results
        """
        print("="*70)
        print("DOCKER SECURITY ADVISORY VC PLUGIN - CONTENT GENERATION")
        print("="*70)
        print()
        
        # Load scraped data
        print("Step 1: Loading scraped data...")
        try:
            scraped_data = self.load_scraped_data()
            vulnerabilities = scraped_data.get('vulnerabilities', [])
            print(f"  ✓ Loaded {len(vulnerabilities)} vulnerabilities from scraped data")
        except Exception as e:
            print(f"  ✗ Error loading data: {e}")
            return {'error': str(e)}
        
        print()
        
        # Parse and validate with Pydantic
        print("Step 2: Parsing and validating data with Pydantic models...")
        vuln_contents = []
        for i, raw_vuln in enumerate(vulnerabilities, 1):
            try:
                vuln_content = self.parse_vulnerability(raw_vuln)
                vuln_contents.append(vuln_content)
                cve_id = vuln_content.get_primary_cve()
                print(f"  [{i}/{len(vulnerabilities)}] ✓ Validated {cve_id}")
            except Exception as e:
                title = raw_vuln.get('title', 'Unknown')
                print(f"  [{i}/{len(vulnerabilities)}] ✗ Error parsing {title}: {e}")
        
        print(f"\n  Successfully validated {len(vuln_contents)} vulnerabilities")
        print()
        
        # Transform to content files
        print("Step 3: Generating content files (.xml, .vck, .sol)...")
        all_files = self.file_manager.write_batch(vuln_contents)
        print(f"\n  Generated {len(all_files)} complete content sets")
        print()
        
        # Summary
        print("="*70)
        print("GENERATION COMPLETE")
        print("="*70)
        print(f"Total vulnerabilities processed: {len(vulnerabilities)}")
        print(f"Successfully generated: {len(all_files)}")
        print(f"Content files location: {self.content_dir}/")
        print()
        
        # List generated files
        if all_files:
            print("Generated files:")
            for file_set in all_files:
                basename = os.path.basename(file_set['xml']).replace('.xml', '')
                print(f"  • {basename}")
                print(f"    - {basename}.xml")
                print(f"    - {basename}.vck")
                print(f"    - {basename}.sol")
        
        return {
            'total_processed': len(vulnerabilities),
            'successfully_generated': len(all_files),
            'content_directory': self.content_dir,
            'files': all_files
        }


def main():
    """Main entry point"""
    print("\n🚀 Starting Docker Security Advisory VC Plugin Pipeline\n")
    
    # Step 1: Scrape data
    print("Phase 1: SCRAPING")
    print("-" * 70)
    
    scraper = DockerSecurityScraper()
    
    # Check if data already exists
    json_path = os.path.join(scraper.output_dir, "json", "all_vulnerabilities.json")
    if os.path.exists(json_path):
        print("✓ Scraped data already exists. Skipping scraping.")
        print(f"  (Delete {json_path} to re-scrape)")
    else:
        print("Scraping Docker security advisories...")
        scrape_results = scraper.scrape_all()
        if 'error' in scrape_results:
            print(f"✗ Scraping failed: {scrape_results['error']}")
            return 1
    
    print()
    
    # Step 2: Generate content
    print("Phase 2: CONTENT GENERATION")
    print("-" * 70)
    
    generator = VulnerabilityContentGenerator()
    results = generator.generate_all_content()
    
    if 'error' in results:
        print(f"\n✗ Content generation failed: {results['error']}")
        return 1
    
    print("\n✅ Pipeline completed successfully!")
    print(f"\n📁 All content files are in: {results['content_directory']}/")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
