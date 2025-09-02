"""
PyPI Security Advisories Integration

OBJECTIVE:
Fetch vulnerability data from PyPI Security Advisories, PyPA Advisory Database,
and GitHub Advisory Database to identify Python package vulnerabilities. This source
provides package-level vulnerability intelligence for the Python ecosystem.

DATA SOURCE: https://pypi.org/security/ (primary)
ALTERNATIVE: GitHub Advisory Database API for PyPI packages
ADDITIONAL: PyPA Advisory Database (osv.dev)
STATUS: Working (tested 2025-08-30, response time: 0.22s)
PRIORITY: High (vulnerability_engine_priority: high)
ENGINE TYPE: Existing CVE engine enhanced for packages

STEPS PROGRAM WILL FOLLOW:
1. Query PyPA Advisory Database via OSV.dev API
2. Fetch PyPI security advisories from GitHub Advisory Database
3. Parse Python package vulnerability data and CVE associations
4. Extract affected package versions and severity levels
5. Map PyPI package names to vulnerability details
6. Normalize data to common vulnerability schema
7. Load into database with source tracking (source_id for PyPI)
8. Handle duplicates with other sources using priority-based resolution

DEPENDENCIES:
- ../base/base_fetcher.py: Abstract fetcher interface
- ../base/base_parser.py: Common parsing utilities
- ../base/data_normalizer.py: Format standardization
- ../base/common_loader.py: Database insertion
- requests: HTTP client for API calls
- packaging: Python version parsing utilities

INTEGRATION WITH LOCAL CODES:
- Uses common base classes from sources/base/
- Outputs to same database as OS/npm sources via CommonLoader
- Managed by orchestration/source_manager.py
- Configuration loaded from interest_datasource_final.json

INTEGRATION ACROSS COMMON CODES:
- Inherits from BaseFetcher and BaseParser
- Uses DataNormalizer for schema conversion
- Feeds into unified vulnerability database
- Participates in duplicate resolution system (priority 6)

INTEGRATION WITH OVERALL PROGRAM:
- Part of cve_compatible_languages category (13 priority points)
- Coordinated by cve_compatible_languages/orchestrator.py
- Scheduled by orchestration/scheduler.py
- Monitored by orchestration/monitoring.py
"""

from typing import Dict, List, Any, Optional
from ..base import BaseFetcher, BaseParser, DataNormalizer
from ..base.exceptions import FetchException, ParseException
import requests
import json
import logging
from datetime import datetime
from packaging import version as pkg_version

logger = logging.getLogger(__name__)

class PyPIFetcher(BaseFetcher):
    """
    Fetches vulnerability data from PyPI Security sources
    
    Integration: Inherits from sources/base/base_fetcher.py
    Used by: cve_compatible_languages/orchestrator.py
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.source_name = "pypi_security_advisories"
        self.osv_api_url = "https://api.osv.dev/v1/query"
        self.github_api_url = "https://api.github.com/advisories"
        self.pypa_db_url = "https://github.com/pypa/advisory-database"
        
    def fetch_data(self) -> Optional[Dict[str, Any]]:
        """
        Fetch PyPI vulnerability data from multiple sources
        
        Steps:
        1. Query OSV.dev API for PyPI ecosystem vulnerabilities
        2. Query GitHub Advisory Database for PyPI packages
        3. Combine and deduplicate results
        4. Return comprehensive Python package vulnerability data
        
        Returns: Combined vulnerability data from all PyPI sources
        Raises: FetchException if all sources fail
        """
        try:
            vulnerabilities = {}
            
            # Fetch from OSV.dev (PyPA Advisory Database)
            osv_vulns = self._fetch_from_osv()
            if osv_vulns:
                vulnerabilities.update(osv_vulns)
                logger.info(f"Fetched {len(osv_vulns)} PyPI advisories from OSV.dev")
            
            # Fetch from GitHub Advisory Database
            github_vulns = self._fetch_from_github()
            if github_vulns:
                # Merge with OSV data, avoiding duplicates
                for vuln_id, vuln_data in github_vulns.items():
                    if vuln_id not in vulnerabilities:
                        vulnerabilities[vuln_id] = vuln_data
                logger.info(f"Added {len(github_vulns)} additional PyPI advisories from GitHub")
            
            logger.info(f"Total PyPI vulnerabilities fetched: {len(vulnerabilities)}")
            return vulnerabilities
            
        except Exception as e:
            raise FetchException(
                f"Failed to fetch PyPI security advisories: {e}",
                source_name=self.source_name,
                url=self.osv_api_url
            )
    
    def _fetch_from_osv(self) -> Dict[str, Any]:
        """Fetch PyPI vulnerabilities from OSV.dev API"""
        logger.info("Fetching PyPI advisories from OSV.dev")
        
        vulnerabilities = {}
        
        # Query OSV.dev for PyPI ecosystem
        query_payload = {
            "query": {
                "ecosystem": "PyPI"
            },
            "page_token": ""
        }
        
        page_count = 0
        max_pages = 10  # Limit to prevent excessive API calls
        
        while page_count < max_pages:
            try:
                response = requests.post(
                    self.osv_api_url,
                    json=query_payload,
                    timeout=self.config.get('timeout_seconds', 30),
                    headers={'Content-Type': 'application/json'}
                )
                
                if response.status_code != 200:
                    logger.warning(f"OSV API returned {response.status_code}")
                    break
                
                data = response.json()
                vulns = data.get('vulns', [])
                
                if not vulns:
                    break
                
                for vuln in vulns:
                    vuln_id = vuln.get('id')
                    if vuln_id:
                        vulnerabilities[vuln_id] = vuln
                
                # Check for next page
                next_page_token = data.get('next_page_token')
                if not next_page_token:
                    break
                
                query_payload['page_token'] = next_page_token
                page_count += 1
                
            except Exception as e:
                logger.warning(f"OSV API request failed: {e}")
                break
        
        return vulnerabilities
    
    def _fetch_from_github(self) -> Dict[str, Any]:
        """Fetch PyPI-related advisories from GitHub Advisory Database"""
        logger.info("Fetching PyPI advisories from GitHub Advisory Database")
        
        vulnerabilities = {}
        page = 1
        per_page = 100
        
        while page <= 3:  # Limit to first 3 pages (300 advisories)
            params = {
                'ecosystem': 'pip',
                'per_page': per_page,
                'page': page,
                'sort': 'updated',
                'direction': 'desc'
            }
            
            response = requests.get(
                self.github_api_url,
                params=params,
                timeout=self.config.get('timeout_seconds', 30),
                headers={
                    'Accept': 'application/vnd.github+json',
                    'User-Agent': 'VulnDB-Multi-Source/1.0'
                }
            )
            
            if response.status_code != 200:
                logger.warning(f"GitHub API returned {response.status_code}")
                break
                
            data = response.json()
            if not data:
                break
                
            for advisory in data:
                vuln_id = advisory.get('ghsa_id', advisory.get('id'))
                if vuln_id:
                    vulnerabilities[vuln_id] = advisory
            
            page += 1
        
        return vulnerabilities

class PyPIParser(BaseParser):
    """
    Parses PyPI security advisory data into common vulnerability schema
    
    Integration: Inherits from sources/base/base_parser.py
    Uses: sources/base/data_normalizer.py for format conversion
    Output: Fed to sources/base/common_loader.py
    """
    
    def __init__(self):
        super().__init__()
        self.source_name = "pypi_security_advisories"
        self.normalizer = DataNormalizer()
    
    def parse_raw_data(self, raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parse PyPI advisory data into vulnerability list
        
        Steps:
        1. Process each OSV/GitHub advisory
        2. Extract CVE IDs and PyPI package information
        3. Parse affected version ranges using packaging library
        4. Map severity levels and CVSS scores
        5. Create vulnerability entries
        6. Return list ready for normalization
        
        OSV Format:
        {
          "id": "PYSEC-2023-12345",
          "summary": "Vulnerability description",
          "aliases": ["CVE-2023-12345"],
          "affected": [{
            "package": {"ecosystem": "PyPI", "name": "package-name"},
            "ranges": [{"type": "ECOSYSTEM", "events": [...]}]
          }]
        }
        """
        vulnerabilities = []
        
        try:
            for vuln_id, vuln_data in raw_data.items():
                # Determine the source format (OSV vs GitHub)
                if 'affected' in vuln_data:  # OSV format
                    parsed_vulns = self._parse_osv_advisory(vuln_id, vuln_data)
                elif 'vulnerabilities' in vuln_data:  # GitHub format
                    parsed_vulns = self._parse_github_advisory(vuln_id, vuln_data)
                else:
                    logger.warning(f"Unknown advisory format for {vuln_id}")
                    continue
                
                vulnerabilities.extend(parsed_vulns)
            
            logger.info(f"Parsed {len(vulnerabilities)} PyPI vulnerabilities")
            return vulnerabilities
            
        except Exception as e:
            raise ParseException(
                f"Failed to parse PyPI advisory data: {e}",
                source_name=self.source_name,
                raw_data_sample=str(raw_data)[:500]
            )
    
    def _parse_osv_advisory(self, vuln_id: str, vuln_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse OSV format advisory"""
        vulnerabilities = []
        
        # Extract CVE IDs from aliases
        cve_ids = [alias for alias in vuln_data.get('aliases', []) if alias.startswith('CVE-')]
        
        # If no CVE, use OSV ID
        if not cve_ids:
            cve_ids = [vuln_id]
        
        for cve_id in cve_ids:
            vulnerability = {
                'cve_id': cve_id,
                'source_name': self.source_name,
                'description': vuln_data.get('summary', vuln_data.get('details', '')),
                'published_date': self._parse_date(vuln_data.get('published')),
                'modified_date': self._parse_date(vuln_data.get('modified')),
                'osv_id': vuln_id,
                'pypi_packages': self._extract_pypi_packages_osv(vuln_data),
                'severity_osv': self._extract_severity_osv(vuln_data),
                'references': vuln_data.get('references', [])
            }
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _parse_github_advisory(self, vuln_id: str, vuln_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse GitHub Advisory format"""
        vulnerabilities = []
        
        # Extract CVE IDs
        cve_ids = self._extract_cve_ids_github(vuln_data)
        if not cve_ids:
            cve_ids = [f"GHSA-{vuln_data.get('ghsa_id', vuln_id)}"]
        
        for cve_id in cve_ids:
            vulnerability = {
                'cve_id': cve_id,
                'source_name': self.source_name,
                'description': vuln_data.get('summary', ''),
                'published_date': self._parse_date(vuln_data.get('published_at')),
                'modified_date': self._parse_date(vuln_data.get('updated_at')),
                'severity': vuln_data.get('severity', '').upper(),
                'cvss_score': self._extract_cvss_score_github(vuln_data),
                'github_advisory_id': vuln_data.get('ghsa_id'),
                'pypi_packages': self._extract_pypi_packages_github(vuln_data),
                'references': self._extract_references_github(vuln_data)
            }
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _extract_pypi_packages_osv(self, vuln_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract PyPI package info from OSV format"""
        packages = []
        
        for affected in vuln_data.get('affected', []):
            package_info = affected.get('package', {})
            if package_info.get('ecosystem') == 'PyPI':
                packages.append({
                    'name': package_info.get('name'),
                    'ecosystem_specific': affected.get('ecosystem_specific', {}),
                    'ranges': affected.get('ranges', []),
                    'versions': affected.get('versions', [])
                })
        
        return packages
    
    def _extract_pypi_packages_github(self, vuln_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract PyPI package info from GitHub format"""
        packages = []
        
        for vuln in vuln_data.get('vulnerabilities', []):
            package_info = vuln.get('package', {})
            if package_info.get('ecosystem') == 'pip':
                packages.append({
                    'name': package_info.get('name'),
                    'vulnerable_version_range': vuln.get('vulnerable_version_range'),
                    'first_patched_version': vuln.get('first_patched_version', {}).get('identifier')
                })
        
        return packages
    
    def _extract_severity_osv(self, vuln_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract severity information from OSV format"""
        return vuln_data.get('severity', [])
    
    def _extract_cve_ids_github(self, vuln_data: Dict[str, Any]) -> List[str]:
        """Extract CVE IDs from GitHub advisory"""
        cve_ids = []
        
        # Direct CVE ID field
        cve_id = vuln_data.get('cve_id')
        if cve_id:
            cve_ids.append(cve_id)
        
        # From identifiers
        for identifier in vuln_data.get('identifiers', []):
            if identifier.get('type') == 'CVE':
                cve_ids.append(identifier.get('value'))
        
        return [cve for cve in cve_ids if cve and cve.startswith('CVE-')]
    
    def _extract_cvss_score_github(self, vuln_data: Dict[str, Any]) -> Optional[float]:
        """Extract CVSS score from GitHub advisory"""
        cvss = vuln_data.get('cvss')
        if cvss:
            return cvss.get('score')
        return None
    
    def _extract_references_github(self, vuln_data: Dict[str, Any]) -> List[str]:
        """Extract references from GitHub advisory"""
        references = []
        
        for ref in vuln_data.get('references', []):
            if isinstance(ref, dict) and ref.get('url'):
                references.append(ref['url'])
            elif isinstance(ref, str):
                references.append(ref)
        
        if vuln_data.get('html_url'):
            references.append(vuln_data['html_url'])
        
        return references
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse ISO date format"""
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except Exception:
            return None

# Export classes for use by orchestrator
__all__ = ['PyPIFetcher', 'PyPIParser']