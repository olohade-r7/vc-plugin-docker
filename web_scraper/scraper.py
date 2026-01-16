import os
import json
import time
import requests
from bs4 import BeautifulSoup
from typing import List, Dict, Optional
from datetime import datetime
from urllib.parse import urljoin


class DockerSecurityScraper:
    
    BASE_URL = "https://docs.docker.com"
    SECURITY_URL = "https://docs.docker.com/security/security-announcements/"
    
    def __init__(self, output_dir: str = "raw_data"):
        """
        Initialize the scraper
    
    BASE_URL = "https://docs.docker.com"
    SECURITY_URL = "https://docs.docker.com/security/security-announcements/"
    
    def __init__(self, output_dir: str = "raw_data"):makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, "html"), exist_ok=True)
        os.makedirs(os.path.join(output_dir, "json"), exist_ok=True)
    
    def fetch_page(self, url: str, delay: float = 1.0) -> Optional[str]:
        """
        Fetch a web page with error handling
        
        Args:
            url: URL to fetch
            delay: Delay between requests in seconds
            
            return None
    
    def parse_main_page(self, html: str) -> List[Dict]:
        """
        Parse the main security announcements page
        
        Args:
            html: HTML content of the page
            
        Returns:
            List of vulnerability dictionaries
        """
        soup = BeautifulSoup(html, 'html.parser')
        vulnerabilities = []
        
        # Find all security update sections
        headings = soup.find_all(['h2', 'h3'])
        
        for heading in headings:
            heading_text = heading.get_text(strip=True)
                # Extract CVE IDs from heading
                cve_ids = self._extract_cve_ids(heading_text)
                vuln_data['cve_ids'] = cve_ids
                
                # Get the content following this heading
                content = []
                for sibling in heading.find_next_siblings():
                    if sibling.name in ['h2', 'h3']:
                        break
                    content.append(str(sibling))
                
                vuln_data['content_html'] = '\n'.join(content)
                
                # Parse structured data from content
                content_soup = BeautifulSoup('\n'.join(content), 'html.parser')
                
                # Extract description
                first_p = content_soup.find('p')
                if first_p:
                    vuln_data['description'] = first_p.get_text(strip=True)
                
                # Extract bullet points/lists
                lists = content_soup.find_all(['ul', 'ol'])
                if lists:
                    vuln_data['details'] = []
                    for lst in lists:
                        items = [li.get_text(strip=True) for li in lst.find_all('li')]
                        vuln_data['details'].extend(items)
                
                # Extract CVE links
                vuln_data['cve_links'] = []
                for link in content_soup.find_all('a', href=True):
                    href = link['href']
                    if 'cve.org' in href or 'CVE' in link.get_text():
                        vuln_data['cve_links'].append({
                            'text': link.get_text(strip=True),
                            'url': href
                        })
                
                # Extract release version
                version_link = content_soup.find('a', href=lambda x: x and 'release-notes' in x)
                if version_link:
                    vuln_data['fixed_version'] = version_link.get_text(strip=True)
                
                # Extract last updated date
                for elem in content_soup.find_all(string=lambda text: 'Last updated' in text if text else False):
                    vuln_data['last_updated'] = elem.strip()
                    break
                
                vulnerabilities.append(vuln_data)
        
        return vulnerabilities
    
    def _extract_cve_ids(self, text: str) -> List[str]:
        """
        Extract CVE IDs from text
        
        Args:
            text: Text to search
            
        Returns:
            List of CVE IDs
        """
        import re
        pattern = r'CVE-\d{4}-\d{4,7}'
        return re.findall(pattern, text)
    
    def fetch_cve_details(self, cve_id: str) -> Optional[Dict]:
        """
        Fetch detailed information from cve.org
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2025-13743)
            
        Returns:
            Dictionary with CVE details or None
        """
        url = f"https://cve.org/CVERecord?id={cve_id}"
        html = self.fetch_page(url)
        
        if not html:
            return None
        
        soup = BeautifulSoup(html, 'html.parser')
        
        cve_data = {
            'cve_id': cve_id,
            'url': url,
            'scraped_at': datetime.now().isoformat(),
        }
        
        # Try to extract various fields
        # Note: CVE.org structure may vary, this is a best-effort extraction
        
        # Look for description
        desc_elem = soup.find('div', {'class': lambda x: x and 'description' in x.lower()})
        if desc_elem:
            cve_data['cve_description'] = desc_elem.get_text(strip=True)
        
        # Look for CVSS score
        cvss_elem = soup.find(string=lambda text: 'CVSS' in text if text else False)
        if cvss_elem:
            parent = cvss_elem.find_parent()
            if parent:
                cve_data['cvss_info'] = parent.get_text(strip=True)
        
        # Store full HTML for reference
        cve_data['full_html'] = html
        
        return cve_data
    
    def scrape_all(self) -> Dict:
        """
        Scrape all Docker security advisories
        
        Returns:
            Dictionary with scraping results
        """
        print("Fetching main security announcements page...")
        main_html = self.fetch_page(self.SECURITY_URL)
        
        if not main_html:
            return {'error': 'Failed to fetch main page'}
        
        # Save main page HTML
        main_html_path = os.path.join(self.output_dir, "html", "security_announcements.html")
        with open(main_html_path, 'w', encoding='utf-8') as f:
            f.write(main_html)
        print(f"Saved main page HTML to {main_html_path}")
        
        # Parse vulnerabilities
        print("Parsing vulnerabilities...")
        vulnerabilities = self.parse_main_page(main_html)
        print(f"Found {len(vulnerabilities)} vulnerabilities")
        
        # Fetch CVE details for each unique CVE
        all_cves = set()
        for vuln in vulnerabilities:
            all_cves.update(vuln.get('cve_ids', []))
        
        print(f"\nFetching details for {len(all_cves)} unique CVEs...")
        cve_details = {}
        for i, cve_id in enumerate(all_cves, 1):
            print(f"  [{i}/{len(all_cves)}] Fetching {cve_id}...")
            details = self.fetch_cve_details(cve_id)
            if details:
                cve_details[cve_id] = details
                
                # Save individual CVE HTML
                cve_html_path = os.path.join(self.output_dir, "html", f"{cve_id}.html")
                with open(cve_html_path, 'w', encoding='utf-8') as f:
                    f.write(details.get('full_html', ''))
        
        # Combine data
        results = {
            'scraped_at': datetime.now().isoformat(),
            'source_url': self.SECURITY_URL,
            'total_vulnerabilities': len(vulnerabilities),
            'total_cves': len(all_cves),
            'vulnerabilities': vulnerabilities,
            'cve_details': cve_details
        }
        
        # Save JSON
        json_path = os.path.join(self.output_dir, "json", "all_vulnerabilities.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\nSaved all data to {json_path}")
        
        return results


if __name__ == "__main__":
    scraper = DockerSecurityScraper()
    results = scraper.scrape_all()
    
    print("\n" + "="*60)
    print("SCRAPING COMPLETE")
    print("="*60)
    print(f"Total vulnerabilities: {results.get('total_vulnerabilities', 0)}")
    print(f"Total CVEs: {results.get('total_cves', 0)}")
    print(f"Data saved in: {scraper.output_dir}/")
