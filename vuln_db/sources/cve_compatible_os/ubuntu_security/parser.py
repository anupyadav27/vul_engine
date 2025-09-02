#!/usr/bin/env python3
"""
Ubuntu Security Notices Parser
Extracts vulnerability data from Ubuntu Security Notices (USN)
Priority: HIGH - CVE Compatible OS Source
"""

import requests
import json
import re
from datetime import datetime
from typing import Dict, List, Optional
import logging
from xml.etree import ElementTree as ET

logger = logging.getLogger(__name__)

class UbuntuSecurityParser:
    """Parser for Ubuntu Security Notices"""
    
    def __init__(self):
        self.base_url = "https://ubuntu.com/security/notices"
        self.rss_url = "https://ubuntu.com/security/notices/rss.xml"
        self.api_url = "https://ubuntu.com/security/notices.json"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnDB-Ubuntu-Parser/1.0'
        })
    
    def fetch_security_notices(self, limit: int = 100) -> List[Dict]:
        """Fetch Ubuntu security notices"""
        try:
            # Try JSON API first
            notices = self._fetch_from_json_api(limit)
            
            if not notices:
                # Fallback to RSS feed
                notices = self._fetch_from_rss(limit)
            
            return notices
            
        except Exception as e:
            logger.error(f"Error fetching Ubuntu security notices: {e}")
            return []
    
    def _fetch_from_json_api(self, limit: int) -> List[Dict]:
        """Fetch notices from JSON API"""
        try:
            response = self.session.get(self.api_url)
            if response.status_code != 200:
                return []
            
            data = response.json()
            notices = []
            
            for notice in data.get('notices', [])[:limit]:
                parsed_notice = self._parse_json_notice(notice)
                if parsed_notice:
                    notices.append(parsed_notice)
            
            return notices
            
        except Exception as e:
            logger.error(f"Error parsing JSON API: {e}")
            return []
    
    def _parse_json_notice(self, notice: Dict) -> Optional[Dict]:
        """Parse individual notice from JSON"""
        try:
            usn_id = notice.get('id', '')
            title = notice.get('title', '')
            summary = notice.get('summary', '')
            published = notice.get('published', '')
            
            # Extract CVE references
            cves = []
            cve_refs = notice.get('cves', [])
            if isinstance(cve_refs, list):
                cves = [cve.get('id') if isinstance(cve, dict) else str(cve) for cve in cve_refs]
            
            # Extract affected packages
            packages = []
            releases = notice.get('releases', {})
            for release_name, release_data in releases.items():
                if isinstance(release_data, dict):
                    sources = release_data.get('sources', {})
                    for pkg_name, pkg_data in sources.items():
                        packages.append({
                            'name': pkg_name,
                            'release': release_name,
                            'version': pkg_data.get('version', ''),
                            'description': pkg_data.get('description', '')
                        })
            
            # Determine severity from title/summary
            severity = self._extract_severity(title + ' ' + summary)
            
            return {
                'usn_id': usn_id,
                'title': title,
                'summary': summary,
                'published_date': published,
                'cves': cves,
                'packages': packages,
                'severity': severity,
                'source': 'ubuntu_security',
                'url': f"{self.base_url}/{usn_id}"
            }
            
        except Exception as e:
            logger.error(f"Error parsing JSON notice: {e}")
            return None
    
    def _fetch_from_rss(self, limit: int) -> List[Dict]:
        """Fetch notices from RSS feed"""
        try:
            response = self.session.get(self.rss_url)
            if response.status_code != 200:
                return []
            
            root = ET.fromstring(response.text)
            notices = []
            
            for item in root.findall('.//item')[:limit]:
                notice = self._parse_rss_item(item)
                if notice:
                    notices.append(notice)
            
            return notices
            
        except Exception as e:
            logger.error(f"Error parsing RSS feed: {e}")
            return []
    
    def _parse_rss_item(self, item: ET.Element) -> Optional[Dict]:
        """Parse individual RSS item"""
        try:
            title_elem = item.find('title')
            link_elem = item.find('link')
            description_elem = item.find('description')
            pub_date_elem = item.find('pubDate')
            
            title = title_elem.text if title_elem is not None else ''
            link = link_elem.text if link_elem is not None else ''
            description = description_elem.text if description_elem is not None else ''
            pub_date = pub_date_elem.text if pub_date_elem is not None else ''
            
            # Extract USN ID from title
            usn_match = re.search(r'USN-(\d+-\d+)', title)
            usn_id = usn_match.group(0) if usn_match else ''
            
            # Extract CVE references
            cve_pattern = re.compile(r'CVE-\d{4}-\d+')
            cves = list(set(cve_pattern.findall(description)))
            
            # Extract severity
            severity = self._extract_severity(title + ' ' + description)
            
            return {
                'usn_id': usn_id,
                'title': title,
                'summary': description,
                'published_date': pub_date,
                'cves': cves,
                'packages': [],  # Need to fetch details for packages
                'severity': severity,
                'source': 'ubuntu_security',
                'url': link
            }
            
        except Exception as e:
            logger.error(f"Error parsing RSS item: {e}")
            return None
    
    def _extract_severity(self, text: str) -> str:
        """Extract severity from text"""
        text_lower = text.lower()
        if any(word in text_lower for word in ['critical', 'urgent']):
            return 'Critical'
        elif any(word in text_lower for word in ['high', 'important']):
            return 'High'
        elif any(word in text_lower for word in ['medium', 'moderate']):
            return 'Medium'
        elif any(word in text_lower for word in ['low', 'minor']):
            return 'Low'
        return 'Unknown'
    
    def get_notice_details(self, usn_id: str) -> Optional[Dict]:
        """Get detailed information for a specific USN"""
        try:
            notice_url = f"{self.base_url}/{usn_id}"
            response = self.session.get(notice_url)
            
            if response.status_code == 200:
                content = response.text
                
                # Extract CVE references
                cve_pattern = re.compile(r'CVE-\d{4}-\d+')
                cves = list(set(cve_pattern.findall(content)))
                
                # Extract affected packages
                packages = []
                pkg_pattern = re.compile(r'<li><strong>([^<]+)</strong>')
                pkg_matches = pkg_pattern.findall(content)
                packages = [pkg.strip() for pkg in pkg_matches]
                
                # Extract affected releases
                release_pattern = re.compile(r'Ubuntu (\d+\.\d+)')
                releases = list(set(release_pattern.findall(content)))
                
                return {
                    'usn_id': usn_id,
                    'cves': cves,
                    'packages': packages,
                    'releases': releases,
                    'url': notice_url,
                    'source': 'ubuntu_security'
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting USN details for {usn_id}: {e}")
            return None
    
    def get_package_vulnerabilities(self, package_name: str) -> List[Dict]:
        """Get vulnerabilities for a specific package"""
        try:
            # Search for package in all notices
            all_notices = self.fetch_security_notices()
            package_vulns = []
            
            for notice in all_notices:
                packages = notice.get('packages', [])
                for pkg in packages:
                    if isinstance(pkg, dict) and pkg.get('name') == package_name:
                        package_vulns.append(notice)
                        break
                    elif isinstance(pkg, str) and pkg == package_name:
                        package_vulns.append(notice)
                        break
            
            return package_vulns
            
        except Exception as e:
            logger.error(f"Error getting package vulnerabilities for {package_name}: {e}")
            return []
    
    def get_cve_notices(self, cve_id: str) -> List[Dict]:
        """Get USN notices that address a specific CVE"""
        try:
            all_notices = self.fetch_security_notices()
            cve_notices = []
            
            for notice in all_notices:
                if cve_id in notice.get('cves', []):
                    cve_notices.append(notice)
            
            return cve_notices
            
        except Exception as e:
            logger.error(f"Error getting CVE notices for {cve_id}: {e}")
            return []

    def parse_to_vuln_format(self, ubuntu_notice: Dict) -> Dict:
        """Convert Ubuntu notice to standard vulnerability format"""
        return {
            'vulnerability_id': ubuntu_notice.get('usn_id', ''),
            'source': 'ubuntu_security',
            'source_id': ubuntu_notice.get('usn_id', ''),
            'title': ubuntu_notice.get('title', ''),
            'description': ubuntu_notice.get('summary', ''),
            'severity': ubuntu_notice.get('severity', 'Unknown'),
            'published_date': ubuntu_notice.get('published_date'),
            'modified_date': ubuntu_notice.get('published_date'),
            'cve_references': ubuntu_notice.get('cves', []),
            'affected_packages': [
                pkg.get('name') if isinstance(pkg, dict) else str(pkg) 
                for pkg in ubuntu_notice.get('packages', [])
            ],
            'affected_releases': list(set([
                pkg.get('release') for pkg in ubuntu_notice.get('packages', [])
                if isinstance(pkg, dict) and pkg.get('release')
            ])),
            'references': [ubuntu_notice.get('url', '')],
            'source_url': ubuntu_notice.get('url', ''),
            'metadata': {
                'source_type': 'ubuntu_security_notice',
                'os_family': 'ubuntu',
                'vendor': 'canonical',
                'usn_id': ubuntu_notice.get('usn_id', '')
            }
        }