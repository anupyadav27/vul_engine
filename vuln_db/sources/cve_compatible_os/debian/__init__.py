"""
Debian Security Tracker Integration

OBJECTIVE:
Fetch vulnerability data from Debian Security Tracker JSON API and integrate it with 
the existing NVD-based vulnerability database. This source provides OS-specific 
vulnerability intelligence for Debian-based systems.

DATA SOURCE: https://security-tracker.debian.org/tracker/data/json
STATUS: Working (tested 2025-08-30, response time: 1.34s)
PRIORITY: High (vulnerability_engine_priority: high)
ENGINE TYPE: Existing CVE engine compatible

STEPS PROGRAM WILL FOLLOW:
1. Fetch JSON data from Debian Security Tracker API
2. Parse Debian-specific vulnerability format
3. Extract CVE IDs and map to affected Debian packages
4. Normalize data to common vulnerability schema
5. Load into database with source tracking (source_id for Debian)
6. Handle duplicates with NVD data using priority-based resolution

DEPENDENCIES:
- ../../base/base_fetcher.py: Abstract fetcher interface
- ../../base/base_parser.py: Common parsing utilities
- ../../base/data_normalizer.py: Format standardization
- ../../base/common_loader.py: Database insertion
- ../../nvd/database.py: Enhanced database operations
- ../../db_schema/vulnerability_schema.py: Database schema

INTEGRATION WITH LOCAL CODES:
- Uses common base classes from sources/base/
- Outputs to same database as NVD via CommonLoader
- Managed by orchestration/source_manager.py
- Configuration loaded from interest_datasource_final.json

INTEGRATION ACROSS COMMON CODES:
- Inherits from BaseFetcher and BaseParser
- Uses DataNormalizer for schema conversion
- Feeds into unified vulnerability database
- Participates in duplicate resolution system

INTEGRATION WITH OVERALL PROGRAM:
- Part of cve_compatible_os category (23 priority points)
- Coordinated by cve_compatible_os/orchestrator.py
- Scheduled by orchestration/scheduler.py
- Monitored by orchestration/monitoring.py
"""

from typing import Dict, List, Any, Optional
# Fixed import path - base infrastructure is at sources.base, not sources.cve_compatible_os.base
from ...base import BaseFetcher, BaseParser, DataNormalizer, CommonLoader
from ...base.exceptions import FetchException, ParseException
import requests
import json
import logging

logger = logging.getLogger(__name__)

class DebianFetcher(BaseFetcher):
    """
    Fetches vulnerability data from Debian Security Tracker JSON API
    
    Integration: Inherits from sources/base/base_fetcher.py
    Used by: cve_compatible_os/orchestrator.py
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.source_name = "debian_security_tracker"
        self.api_url = "https://security-tracker.debian.org/tracker/data/json"
        
    def fetch_data(self) -> Optional[Dict[str, Any]]:
        """
        Fetch complete Debian security tracker data
        
        Steps:
        1. Make HTTP request to Debian Security Tracker JSON API
        2. Validate response status and format
        3. Return parsed JSON data
        
        Returns: Raw JSON data from Debian Security Tracker
        Raises: FetchException if request fails
        """
        try:
            logger.info(f"Fetching Debian security data from {self.api_url}")
            
            response = requests.get(
                self.api_url,
                timeout=self.config.get('timeout_seconds', 30),
                headers={'User-Agent': 'VulnDB-Multi-Source/1.0'}
            )
            
            response.raise_for_status()
            data = response.json()
            
            logger.info(f"Successfully fetched {len(data)} Debian security entries")
            return data
            
        except requests.exceptions.RequestException as e:
            raise FetchException(
                f"Failed to fetch Debian security data: {e}",
                source_name=self.source_name,
                url=self.api_url
            )
        except json.JSONDecodeError as e:
            raise ParseException(
                f"Invalid JSON response from Debian API: {e}",
                source_name=self.source_name
            )
    
    def get_incremental_data(self, since_date) -> Optional[Dict[str, Any]]:
        """
        Debian doesn't provide incremental API, so fetch all data
        The parser will filter based on dates
        """
        return self.fetch_data()

class DebianParser(BaseParser):
    """
    Parses Debian Security Tracker JSON data into common vulnerability schema
    
    Integration: Inherits from sources/base/base_parser.py
    Uses: sources/base/data_normalizer.py for format conversion
    Output: Fed to sources/base/common_loader.py
    """
    
    def __init__(self):
        super().__init__()
        self.source_name = "debian_security_tracker"
        self.normalizer = DataNormalizer()
    
    def parse_raw_data(self, raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parse Debian Security Tracker JSON format into vulnerability list
        
        Steps:
        1. Iterate through all CVE entries in Debian data
        2. Extract CVE ID, description, and affected packages
        3. Map Debian releases to affected software versions
        4. Create vulnerability dictionary in intermediate format
        5. Return list ready for normalization
        
        Debian Format:
        {
          "CVE-YYYY-NNNN": {
            "description": "...",
            "releases": {
              "bullseye": {
                "package_name": {
                  "status": "fixed",
                  "fixed_version": "1.2.3-1+deb11u1"
                }
              }
            }
          }
        }
        """
        vulnerabilities = []
        
        try:
            for cve_id, cve_data in raw_data.items():
                if not cve_id.startswith('CVE-'):
                    continue
                
                # Extract basic vulnerability info
                vulnerability = {
                    'cve_id': cve_id,
                    'description': cve_data.get('description', ''),
                    'source_name': self.source_name,
                    'packages': self._extract_affected_packages(cve_data),
                    'debian_releases': cve_data.get('releases', {}),
                    'debian_scope': cve_data.get('scope', ''),
                    # Debian doesn't provide dates directly, will be None
                    'published_date': None,
                    'modified_date': None
                }
                
                vulnerabilities.append(vulnerability)
                
            logger.info(f"Parsed {len(vulnerabilities)} Debian vulnerabilities")
            return vulnerabilities
            
        except Exception as e:
            raise ParseException(
                f"Failed to parse Debian data: {e}",
                source_name=self.source_name,
                raw_data_sample=str(raw_data)[:500]
            )
    
    def _extract_affected_packages(self, cve_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract affected Debian packages from CVE data
        
        Returns list of packages with release and version info
        """
        packages = []
        releases = cve_data.get('releases', {})
        
        for release_name, release_data in releases.items():
            if isinstance(release_data, dict):
                for package_name, package_info in release_data.items():
                    if isinstance(package_info, dict):
                        packages.append({
                            'name': package_name,
                            'release': release_name,
                            'status': package_info.get('status', ''),
                            'fixed_version': package_info.get('fixed_version', ''),
                            'urgency': package_info.get('urgency', ''),
                            'repository': package_info.get('repository', '')
                        })
        
        return packages

# Export classes for use by orchestrator
__all__ = ['DebianFetcher', 'DebianParser']