#!/usr/bin/env python3
"""
npm Security Advisories Parser
Extracts vulnerability data from npm registry security advisories
Priority: HIGH - CVE Compatible Language Source
"""

import requests
import json
from datetime import datetime
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class NpmSecurityParser:
    """Parser for npm Security Advisories"""
    
    def __init__(self):
        self.base_url = "https://registry.npmjs.org"
        self.audit_url = "https://registry.npmjs.org/-/npm/v1/security/audits"
        self.advisory_url = "https://registry.npmjs.org/-/npm/v1/security/advisories"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnDB-NPM-Parser/1.0',
            'Content-Type': 'application/json'
        })
    
    def fetch_advisories(self, limit: int = 100) -> List[Dict]:
        """Fetch npm security advisories"""
        try:
            # Query for recent advisories
            response = self.session.get(f"{self.advisory_url}?limit={limit}")
            if response.status_code == 200:
                data = response.json()
                return list(data.values()) if isinstance(data, dict) else data
            
            # Fallback to bulk audit approach
            return self._fetch_bulk_advisories(limit)
            
        except Exception as e:
            logger.error(f"Error fetching npm advisories: {e}")
            return []
    
    def _fetch_bulk_advisories(self, limit: int) -> List[Dict]:
        """Fetch advisories using bulk audit endpoint"""
        try:
            # Sample package manifest for audit
            audit_payload = {
                "version": "1.4.3",
                "lockfileVersion": 1,
                "dependencies": {}
            }
            
            response = self.session.post(self.audit_url, json=audit_payload)
            if response.status_code == 200:
                audit_data = response.json()
                advisories = audit_data.get('advisories', {})
                return list(advisories.values())[:limit]
            
            return []
            
        except Exception as e:
            logger.error(f"Error in bulk advisory fetch: {e}")
            return []
    
    def get_package_vulnerabilities(self, package_name: str) -> List[Dict]:
        """Get vulnerabilities for a specific package"""
        try:
            url = f"{self.base_url}/{package_name}"
            response = self.session.get(url)
            
            if response.status_code == 200:
                package_data = response.json()
                # Extract security info from package metadata
                return self._extract_package_vulnerabilities(package_data, package_name)
            
            return []
            
        except Exception as e:
            logger.error(f"Error fetching package vulnerabilities for {package_name}: {e}")
            return []
    
    def _extract_package_vulnerabilities(self, package_data: Dict, package_name: str) -> List[Dict]:
        """Extract vulnerability information from package data"""
        vulnerabilities = []
        
        # Check for security warnings in package metadata
        if 'security' in package_data:
            security_data = package_data['security']
            if isinstance(security_data, list):
                for vuln in security_data:
                    vulnerabilities.append(self._format_vulnerability(vuln, package_name))
        
        # Check versions for security information
        versions = package_data.get('versions', {})
        for version, version_data in versions.items():
            if 'security' in version_data or 'vulnerabilities' in version_data:
                vuln_data = version_data.get('security', version_data.get('vulnerabilities', []))
                if isinstance(vuln_data, list):
                    for vuln in vuln_data:
                        vuln['affected_version'] = version
                        vulnerabilities.append(self._format_vulnerability(vuln, package_name))
        
        return vulnerabilities
    
    def _format_vulnerability(self, vuln_data: Dict, package_name: str) -> Dict:
        """Format vulnerability data to standard format"""
        return {
            'advisory_id': vuln_data.get('id', ''),
            'package_name': package_name,
            'title': vuln_data.get('title', ''),
            'overview': vuln_data.get('overview', ''),
            'severity': vuln_data.get('severity', 'Unknown'),
            'vulnerable_versions': vuln_data.get('vulnerable_versions', ''),
            'patched_versions': vuln_data.get('patched_versions', ''),
            'published_date': vuln_data.get('created', ''),
            'updated_date': vuln_data.get('updated', ''),
            'cwe': vuln_data.get('cwe', []),
            'cves': vuln_data.get('cves', []),
            'references': vuln_data.get('references', []),
            'source': 'npm_security'
        }
    
    def audit_dependencies(self, package_json: Dict) -> Dict:
        """Audit dependencies for vulnerabilities"""
        try:
            response = self.session.post(self.audit_url, json=package_json)
            if response.status_code == 200:
                return response.json()
            
            return {'advisories': {}, 'metadata': {}}
            
        except Exception as e:
            logger.error(f"Error auditing dependencies: {e}")
            return {'advisories': {}, 'metadata': {}}

    def parse_to_vuln_format(self, advisory: Dict) -> Dict:
        """Convert npm advisory to standard vulnerability format"""
        return {
            'vulnerability_id': advisory.get('advisory_id', advisory.get('id', '')),
            'source': 'npm_security',
            'source_id': advisory.get('advisory_id', advisory.get('id', '')),
            'title': advisory.get('title', ''),
            'description': advisory.get('overview', ''),
            'severity': advisory.get('severity', 'Unknown'),
            'published_date': advisory.get('published_date', advisory.get('created')),
            'modified_date': advisory.get('updated_date', advisory.get('updated')),
            'cve_references': advisory.get('cves', []),
            'cwe_references': advisory.get('cwe', []),
            'affected_packages': [{
                'name': advisory.get('package_name', ''),
                'vulnerable_versions': advisory.get('vulnerable_versions', ''),
                'patched_versions': advisory.get('patched_versions', '')
            }],
            'references': advisory.get('references', []),
            'source_url': f"https://www.npmjs.com/advisories/{advisory.get('advisory_id', '')}",
            'metadata': {
                'source_type': 'npm_security_advisory',
                'ecosystem': 'npm',
                'language': 'javascript',
                'package_manager': 'npm'
            }
        }