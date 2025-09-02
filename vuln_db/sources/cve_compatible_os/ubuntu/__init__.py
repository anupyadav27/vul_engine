"""
Ubuntu Security Notices Integration

OBJECTIVE:
Fetch vulnerability data from Ubuntu Security Notices (USN) and integrate with 
the existing vulnerability database. This source provides Ubuntu-specific 
vulnerability intelligence and package security updates.

DATA SOURCE: https://ubuntu.com/security/notices
STATUS: Working (tested 2025-08-30, response time: 0.92s)
PRIORITY: High (vulnerability_engine_priority: high)
ENGINE TYPE: Existing CVE engine compatible

STEPS PROGRAM WILL FOLLOW:
1. Scrape Ubuntu Security Notices HTML page or use RSS feed
2. Parse security notice format and extract CVE IDs
3. Map USN notices to affected Ubuntu packages and versions
4. Normalize data to common vulnerability schema
5. Load into database with source tracking (source_id for Ubuntu)
6. Handle duplicates with NVD/Debian data using priority-based resolution

DEPENDENCIES:
- ../base/base_fetcher.py: Abstract fetcher interface
- ../base/base_parser.py: Common parsing utilities
- ../base/data_normalizer.py: Format standardization
- ../base/common_loader.py: Database insertion
- beautifulsoup4: HTML parsing for security notices
- feedparser: RSS feed parsing (optional)

INTEGRATION WITH LOCAL CODES:
- Uses common base classes from sources/base/
- Outputs to same database as NVD/Debian via CommonLoader
- Managed by orchestration/source_manager.py
- Configuration loaded from interest_datasource_final.json

INTEGRATION ACROSS COMMON CODES:
- Inherits from BaseFetcher and BaseParser
- Uses DataNormalizer for schema conversion
- Feeds into unified vulnerability database
- Participates in duplicate resolution system (priority 8)

INTEGRATION WITH OVERALL PROGRAM:
- Part of cve_compatible_os category (23 priority points)
- Coordinated by cve_compatible_os/orchestrator.py
- Scheduled by orchestration/scheduler.py
- Monitored by orchestration/monitoring.py
"""

from typing import Dict, List, Any, Optional
from ..base import BaseFetcher, BaseParser, DataNormalizer
from ..base.exceptions import FetchException, ParseException
import requests
import re
from bs4 import BeautifulSoup
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class UbuntuFetcher(BaseFetcher):
    """
    Fetches vulnerability data from Ubuntu Security Notices
    
    Integration: Inherits from sources/base/base_fetcher.py
    Used by: cve_compatible_os/orchestrator.py
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.source_name = "ubuntu_security_notices"
        self.base_url = "https://ubuntu.com/security/notices"
        self.rss_url = "https://ubuntu.com/security/notices/rss.xml"
        
    def fetch_data(self) -> Optional[List[Dict[str, Any]]]:
        """
        Fetch Ubuntu Security Notices data
        
        Steps:
        1. Try RSS feed first for structured data
        2. Fallback to HTML scraping if RSS fails
        3. Extract individual notice URLs
        4. Fetch detailed notice content
        
        Returns: List of security notice data
        Raises: FetchException if all methods fail
        """
        try:
            # Try RSS feed first
            notices = self._fetch_from_rss()
            if notices:
                return notices
                
            # Fallback to HTML scraping
            return self._fetch_from_html()
            
        except Exception as e:
            raise FetchException(
                f"Failed to fetch Ubuntu security notices: {e}",
                source_name=self.source_name,
                url=self.base_url
            )
    
    def _fetch_from_rss(self) -> Optional[List[Dict[str, Any]]]:
        """Fetch from RSS feed for structured data"""
        try:
            import feedparser
            
            logger.info(f"Fetching Ubuntu notices from RSS: {self.rss_url}")
            feed = feedparser.parse(self.rss_url)
            
            notices = []
            for entry in feed.entries[:50]:  # Limit to recent 50 notices
                notice = {
                    'title': entry.title,
                    'link': entry.link,
                    'published': entry.published,
                    'summary': getattr(entry, 'summary', ''),
                    'usn_id': self._extract_usn_id(entry.title)
                }
                notices.append(notice)
            
            logger.info(f"Fetched {len(notices)} Ubuntu notices from RSS")
            return notices
            
        except ImportError:
            logger.warning("feedparser not available, falling back to HTML")
            return None
        except Exception as e:
            logger.warning(f"RSS fetch failed: {e}, falling back to HTML")
            return None
    
    def _fetch_from_html(self) -> List[Dict[str, Any]]:
        """Fetch from HTML page scraping"""
        logger.info(f"Fetching Ubuntu notices from HTML: {self.base_url}")
        
        response = requests.get(
            self.base_url,
            timeout=self.config.get('timeout_seconds', 30),
            headers={'User-Agent': 'VulnDB-Multi-Source/1.0'}
        )
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        notices = []
        
        # Parse security notices from HTML structure
        notice_links = soup.find_all('a', href=re.compile(r'/security/notices/USN-'))
        
        for link in notice_links[:50]:  # Limit to recent 50
            usn_url = f"https://ubuntu.com{link['href']}"
            notice_detail = self._fetch_notice_detail(usn_url)
            if notice_detail:
                notices.append(notice_detail)
        
        logger.info(f"Fetched {len(notices)} Ubuntu notices from HTML")
        return notices
    
    def _fetch_notice_detail(self, notice_url: str) -> Optional[Dict[str, Any]]:
        """Fetch detailed notice content"""
        try:
            response = requests.get(notice_url, timeout=15)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            return {
                'url': notice_url,
                'usn_id': self._extract_usn_id(notice_url),
                'title': soup.find('h1').get_text() if soup.find('h1') else '',
                'content': soup.get_text(),
                'cve_ids': self._extract_cve_ids(soup.get_text())
            }
        except Exception as e:
            logger.warning(f"Failed to fetch notice detail {notice_url}: {e}")
            return None
    
    def _extract_usn_id(self, text: str) -> Optional[str]:
        """Extract USN ID from text"""
        match = re.search(r'USN-(\d+-\d+)', text)
        return match.group(0) if match else None
    
    def _extract_cve_ids(self, text: str) -> List[str]:
        """Extract CVE IDs from notice text"""
        return re.findall(r'CVE-\d{4}-\d{4,}', text)

class UbuntuParser(BaseParser):
    """
    Parses Ubuntu Security Notice data into common vulnerability schema
    
    Integration: Inherits from sources/base/base_parser.py
    Uses: sources/base/data_normalizer.py for format conversion
    Output: Fed to sources/base/common_loader.py
    """
    
    def __init__(self):
        super().__init__()
        self.source_name = "ubuntu_security_notices"
        self.normalizer = DataNormalizer()
    
    def parse_raw_data(self, raw_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse Ubuntu Security Notice data into vulnerability list
        
        Steps:
        1. Process each security notice
        2. Extract CVE IDs and affected packages
        3. Map Ubuntu-specific package information
        4. Create vulnerability entries for each CVE
        5. Return list ready for normalization
        """
        vulnerabilities = []
        
        try:
            for notice in raw_data:
                cve_ids = notice.get('cve_ids', [])
                
                for cve_id in cve_ids:
                    vulnerability = {
                        'cve_id': cve_id,
                        'source_name': self.source_name,
                        'description': notice.get('summary', notice.get('title', '')),
                        'ubuntu_usn_id': notice.get('usn_id'),
                        'ubuntu_notice_url': notice.get('url', notice.get('link')),
                        'published_date': self._parse_date(notice.get('published')),
                        'affected_packages': self._extract_packages(notice),
                        'ubuntu_releases': self._extract_releases(notice)
                    }
                    
                    vulnerabilities.append(vulnerability)
            
            logger.info(f"Parsed {len(vulnerabilities)} Ubuntu vulnerabilities")
            return vulnerabilities
            
        except Exception as e:
            raise ParseException(
                f"Failed to parse Ubuntu data: {e}",
                source_name=self.source_name,
                raw_data_sample=str(raw_data)[:500]
            )
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse Ubuntu date format"""
        if not date_str:
            return None
        try:
            # Handle various Ubuntu date formats
            for fmt in ['%a, %d %b %Y %H:%M:%S %Z', '%Y-%m-%d']:
                try:
                    return datetime.strptime(date_str, fmt)
                except ValueError:
                    continue
        except Exception:
            pass
        return None
    
    def _extract_packages(self, notice: Dict[str, Any]) -> List[str]:
        """Extract affected package names from notice"""
        content = notice.get('content', notice.get('summary', ''))
        # Simple package extraction - can be enhanced
        packages = re.findall(r'\b([a-z][a-z0-9\-\.]*)\s+package', content.lower())
        return list(set(packages))
    
    def _extract_releases(self, notice: Dict[str, Any]) -> List[str]:
        """Extract affected Ubuntu releases"""
        content = notice.get('content', notice.get('title', ''))
        releases = re.findall(r'Ubuntu (\d+\.\d+)', content)
        return list(set(releases))

# Export classes for use by orchestrator
__all__ = ['UbuntuFetcher', 'UbuntuParser']