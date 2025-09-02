#!/usr/bin/env python3
"""
Debian Security Tracker Parser
Extracts vulnerability data from Debian Security Tracker
Priority: HIGH - CVE Compatible OS Source
"""

import requests
import json
import re
from datetime import datetime
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class DebianSecurityParser:
    """Parser for Debian Security Tracker"""
    
    def __init__(self):
        self.base_url = "https://security-tracker.debian.org"
        self.json_url = "https://security-tracker.debian.org/tracker/data/json"
        self.cve_url = "https://security-tracker.debian.org/tracker/"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnDB-Debian-Parser/1.0'
        })
    
    def fetch_security_data(self, limit: int = 1000) -> List[Dict]:
        """Fetch Debian security tracker data"""
        try:
            response = self.session.get(self.json_url)
            if response.status_code != 200:
                logger.error(f"Failed to fetch Debian data: {response.status_code}")
                return []
            
            data = response.json()
            vulnerabilities = []
            
            # Process CVE entries
            for cve_id, cve_data in list(data.items())[:limit]:
                if cve_id.startswith('CVE-'):
                    vuln = self._parse_cve_entry(cve_id, cve_data)
                    if vuln:
                        vulnerabilities.append(vuln)
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error fetching Debian security data: {e}")
            return []
    
    def _parse_cve_entry(self, cve_id: str, cve_data: Dict) -> Optional[Dict]:
        """Parse individual CVE entry"""
        try:
            # Extract basic information
            description = cve_data.get('description', '')
            scope = cve_data.get('scope', 'unknown')
            
            # Extract affected releases
            releases = cve_data.get('releases', {})
            affected_releases = []
            
            for release_name, release_data in releases.items():
                if isinstance(release_data, dict):
                    status = release_data.get('status', 'unknown')
                    urgency = release_data.get('urgency', 'unknown')
                    
                    affected_releases.append({
                        'release': release_name,
                        'status': status,
                        'urgency': urgency
                    })
            
            # Extract package information
            packages = []
            if 'releases' in cve_data:
                for release_data in cve_data['releases'].values():
                    if isinstance(release_data, dict):
                        for pkg_name, pkg_data in release_data.items():
                            if isinstance(pkg_data, dict) and 'status' in pkg_data:
                                packages.append({
                                    'name': pkg_name,
                                    'status': pkg_data.get('status'),
                                    'urgency': pkg_data.get('urgency', 'unknown')
                                })
            
            # Determine severity from urgency
            severity = self._map_urgency_to_severity(
                max([r.get('urgency', 'low') for r in affected_releases] or ['low'])
            )
            
            return {
                'cve_id': cve_id,
                'description': description,
                'scope': scope,
                'severity': severity,
                'affected_releases': affected_releases,
                'packages': packages,
                'source': 'debian_security',
                'url': f"{self.cve_url}{cve_id}"
            }
            
        except Exception as e:
            logger.error(f"Error parsing CVE {cve_id}: {e}")
            return None
    
    def _map_urgency_to_severity(self, urgency: str) -> str:
        """Map Debian urgency to standard severity"""
        urgency_map = {
            'critical': 'Critical',
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low',
            'unimportant': 'Low',
            'not yet assigned': 'Unknown',
            'end-of-life': 'Low'
        }
        return urgency_map.get(urgency.lower(), 'Unknown')
    
    def get_package_vulnerabilities(self, package_name: str) -> List[Dict]:
        """Get vulnerabilities for a specific package"""
        try:
            package_url = f"{self.base_url}/tracker/source-package/{package_name}"
            response = self.session.get(package_url)
            
            if response.status_code == 200:
                # Parse HTML to extract CVE references
                cve_pattern = re.compile(r'CVE-\d{4}-\d+')
                cves = list(set(cve_pattern.findall(response.text)))
                
                vulnerabilities = []
                for cve in cves:
                    vuln_data = self.get_cve_details(cve)
                    if vuln_data:
                        vulnerabilities.append(vuln_data)
                
                return vulnerabilities
            
            return []
            
        except Exception as e:
            logger.error(f"Error getting package vulnerabilities for {package_name}: {e}")
            return []
    
    def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        """Get detailed information for a specific CVE"""
        try:
            cve_url = f"{self.cve_url}{cve_id}"
            response = self.session.get(cve_url)
            
            if response.status_code == 200:
                # Extract information from HTML
                content = response.text
                
                # Extract description
                desc_match = re.search(r'<p class="cve-description">(.*?)</p>', content, re.DOTALL)
                description = desc_match.group(1).strip() if desc_match else ""
                
                # Extract severity/urgency
                urgency_match = re.search(r'Urgency: <strong>(\w+)</strong>', content)
                urgency = urgency_match.group(1) if urgency_match else "unknown"
                
                return {
                    'cve_id': cve_id,
                    'description': description,
                    'urgency': urgency,
                    'severity': self._map_urgency_to_severity(urgency),
                    'url': cve_url,
                    'source': 'debian_security'
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting CVE details for {cve_id}: {e}")
            return None
    
    def get_release_vulnerabilities(self, release_name: str) -> List[Dict]:
        """Get vulnerabilities for a specific Debian release"""
        try:
            # Fetch all data and filter by release
            all_data = self.fetch_security_data()
            release_vulns = []
            
            for vuln in all_data:
                for release in vuln.get('affected_releases', []):
                    if release.get('release') == release_name:
                        release_vulns.append(vuln)
                        break
            
            return release_vulns
            
        except Exception as e:
            logger.error(f"Error getting release vulnerabilities for {release_name}: {e}")
            return []

    def parse_to_vuln_format(self, debian_vuln: Dict) -> Dict:
        """Convert Debian vulnerability to standard format"""
        return {
            'vulnerability_id': debian_vuln.get('cve_id', ''),
            'source': 'debian_security',
            'source_id': debian_vuln.get('cve_id', ''),
            'title': f"Debian Security Advisory - {debian_vuln.get('cve_id', '')}",
            'description': debian_vuln.get('description', ''),
            'severity': debian_vuln.get('severity', 'Unknown'),
            'published_date': None,  # Debian tracker doesn't provide published dates in JSON
            'modified_date': None,
            'cve_references': [debian_vuln.get('cve_id', '')],
            'affected_packages': [pkg.get('name') for pkg in debian_vuln.get('packages', [])],
            'affected_releases': [rel.get('release') for rel in debian_vuln.get('affected_releases', [])],
            'references': [debian_vuln.get('url', '')],
            'source_url': debian_vuln.get('url', ''),
            'metadata': {
                'source_type': 'debian_security_tracker',
                'os_family': 'debian',
                'vendor': 'debian',
                'scope': debian_vuln.get('scope', 'unknown'),
                'urgency': debian_vuln.get('urgency', 'unknown')
            }
        }