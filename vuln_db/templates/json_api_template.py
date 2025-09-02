#!/usr/bin/env python3
"""
JSON API Data Downloader Template

APPLIES TO SOURCES:
- npm Security Advisories
- Other REST/JSON API endpoints

OBJECTIVE:
Downloads vulnerability data from JSON REST APIs with pagination support.
This template provides a foundation for any JSON-based vulnerability API.

DATA FORMAT: JSON API responses
COMPLEXITY: Low
IMPLEMENTATION APPROACH: Direct HTTP requests with aiohttp + JSON parsing

TEMPLATE USAGE:
1. Update API_ENDPOINT and authentication if required
2. Customize pagination handling for API structure
3. Implement API-specific data extraction
4. Update field mappings for API response format
"""

import asyncio
import aiohttp
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin, urlparse
import time

# Add vuln_db root to Python path
current_dir = Path(__file__).resolve().parent
vuln_db_root = current_dir.parent.parent.parent
sys.path.insert(0, str(vuln_db_root))
sys.path.append(str(vuln_db_root / "config"))

from source_config import get_source_config

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class JSONAPIVulnerabilityDownloader:
    """
    JSON API vulnerability downloader with pagination support
    
    TEMPLATE INSTRUCTIONS:
    1. Update api_endpoint for your target API
    2. Customize authentication if required
    3. Adapt pagination handling for API structure
    4. Update data extraction for API response format
    """
    
    def __init__(self, source_name: str = "json_api_source", api_endpoint: str = "https://api.example.com/vulnerabilities"):
        """Initialize JSON API downloader"""
        # UPDATE: Set your source configuration
        self.source_name = source_name.lower().replace(" ", "_")
        self.api_endpoint = api_endpoint
        
        # API CONFIGURATION - UPDATE as needed
        self.headers = {
            'User-Agent': 'VulnDB/1.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            # 'Authorization': 'Bearer YOUR_API_TOKEN',  # UPDATE: Add if needed
            # 'X-API-Key': 'YOUR_API_KEY',              # UPDATE: Add if needed
        }
        
        # API-specific configuration - CUSTOMIZE for your API
        self.api_config = {
            # Pagination settings
            'pagination_type': 'page_based',  # 'page_based', 'offset_based', 'cursor_based', 'none'
            'page_size': 100,                 # Items per page
            'max_pages': 100,                 # Maximum pages to fetch
            'page_param': 'page',             # URL parameter for page number
            'size_param': 'per_page',         # URL parameter for page size
            'offset_param': 'offset',         # URL parameter for offset (if offset_based)
            'cursor_param': 'cursor',         # URL parameter for cursor (if cursor_based)
            
            # Rate limiting
            'delay_between_requests': 1.0,    # Delay in seconds between requests
            'timeout_seconds': 30,            # Request timeout
            'retry_attempts': 3,              # Number of retry attempts
            
            # Response structure - UPDATE for your API
            'data_field': 'data',             # Field containing the vulnerability data
            'pagination_info_field': 'meta',  # Field containing pagination info
            'total_count_field': 'total',     # Field containing total count
            'next_page_field': 'next_page',   # Field indicating next page
            'has_more_field': 'has_more',     # Field indicating if more data exists
        }
        
        # Session for connection pooling
        self.session = None
        
        # Statistics tracking
        self.stats = {
            'api_requests': 0,
            'total_vulnerabilities': 0,
            'failed_requests': 0,
            'data_size_mb': 0,
            'processing_time_seconds': 0
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            headers=self.headers,
            timeout=aiohttp.ClientTimeout(total=self.api_config['timeout_seconds'])
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def download_and_save_data(self, output_dir: str = None) -> str:
        """Download complete vulnerability data from JSON API"""
        if output_dir is None:
            output_dir = current_dir / "output" / "data_downloads"
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"🚀 Starting JSON API download for {self.source_name}")
        logger.info(f"🌐 API Endpoint: {self.api_endpoint}")
        
        start_time = datetime.utcnow()
        
        try:
            # Download all vulnerability data
            all_vulnerabilities = await self._download_all_vulnerabilities()
            
            # Process and analyze data
            processed_data = self._process_vulnerability_data(all_vulnerabilities)
            structure_analysis = self._analyze_data_structure(processed_data)
            
            # Update statistics
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            self.stats['processing_time_seconds'] = processing_time
            self.stats['total_vulnerabilities'] = len(processed_data)
            
            # Generate timestamped filename
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"{self.source_name}_data_{timestamp}.json"
            output_file = output_path / filename
            
            # Calculate file size
            file_size_mb = len(json.dumps(processed_data).encode('utf-8')) / (1024 * 1024)
            self.stats['data_size_mb'] = file_size_mb
            
            # Prepare final data with metadata
            final_data = {
                'metadata': {
                    'download_timestamp': datetime.utcnow().isoformat(),
                    'source_name': self.source_name,
                    'source_url': self.api_endpoint,
                    'api_method': 'json_rest_api',
                    'total_vulnerabilities': self.stats['total_vulnerabilities'],
                    'api_requests_made': self.stats['api_requests'],
                    'failed_requests': self.stats['failed_requests'],
                    'processing_time_seconds': processing_time,
                    'data_size_mb': file_size_mb,
                    'content_type': 'application/json',
                    'structure_analysis': structure_analysis,
                    'field_mappings': self._generate_field_mappings(),
                    'api_config': self.api_config
                },
                'data': processed_data
            }
            
            # Save to file
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(final_data, f, indent=2, ensure_ascii=False, default=str)
            
            logger.info(f"✅ JSON API download completed successfully")
            logger.info(f"📁 File: {output_file}")
            logger.info(f"🛡️ Vulnerabilities: {self.stats['total_vulnerabilities']:,}")
            logger.info(f"📡 API Requests: {self.stats['api_requests']:,}")
            logger.info(f"⏱️ Processing Time: {processing_time:.1f}s")
            logger.info(f"💾 Size: {file_size_mb:.2f} MB")
            
            return str(output_file)
            
        except Exception as e:
            logger.error(f"❌ Failed to download from JSON API: {e}")
            raise
    
    async def _download_all_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        Download all vulnerabilities using API pagination
        
        TEMPLATE: Customize pagination logic for your API
        """
        all_vulnerabilities = []
        
        if self.api_config['pagination_type'] == 'page_based':
            all_vulnerabilities = await self._download_page_based_pagination()
        elif self.api_config['pagination_type'] == 'offset_based':
            all_vulnerabilities = await self._download_offset_based_pagination()
        elif self.api_config['pagination_type'] == 'cursor_based':
            all_vulnerabilities = await self._download_cursor_based_pagination()
        else:
            # No pagination - single request
            all_vulnerabilities = await self._download_single_request()
        
        logger.info(f"✓ Downloaded {len(all_vulnerabilities)} total vulnerabilities")
        return all_vulnerabilities
    
    async def _download_page_based_pagination(self) -> List[Dict[str, Any]]:
        """Download using page-based pagination (page=1, page=2, etc.)"""
        all_vulnerabilities = []
        page = 1
        
        while page <= self.api_config['max_pages']:
            logger.info(f"📄 Downloading page {page}...")
            
            # Build URL with pagination parameters
            params = {
                self.api_config['page_param']: page,
                self.api_config['size_param']: self.api_config['page_size']
            }
            
            # Make API request
            page_data = await self._make_api_request(self.api_endpoint, params)
            if not page_data:
                break
            
            # Extract vulnerabilities from response
            vulnerabilities = self._extract_vulnerabilities_from_response(page_data)
            if not vulnerabilities:
                logger.info("🏁 No more vulnerabilities found")
                break
            
            all_vulnerabilities.extend(vulnerabilities)
            logger.info(f"✓ Downloaded {len(vulnerabilities)} vulnerabilities from page {page}")
            
            # Check if there are more pages
            if not self._has_more_pages(page_data):
                logger.info("🏁 No more pages available")
                break
            
            page += 1
            
            # Rate limiting
            await asyncio.sleep(self.api_config['delay_between_requests'])
        
        return all_vulnerabilities
    
    async def _download_offset_based_pagination(self) -> List[Dict[str, Any]]:
        """Download using offset-based pagination (offset=0, offset=100, etc.)"""
        all_vulnerabilities = []
        offset = 0
        page_size = self.api_config['page_size']
        
        while True:
            logger.info(f"📄 Downloading from offset {offset}...")
            
            # Build URL with pagination parameters
            params = {
                self.api_config['offset_param']: offset,
                self.api_config['size_param']: page_size
            }
            
            # Make API request
            page_data = await self._make_api_request(self.api_endpoint, params)
            if not page_data:
                break
            
            # Extract vulnerabilities from response
            vulnerabilities = self._extract_vulnerabilities_from_response(page_data)
            if not vulnerabilities:
                logger.info("🏁 No more vulnerabilities found")
                break
            
            all_vulnerabilities.extend(vulnerabilities)
            logger.info(f"✓ Downloaded {len(vulnerabilities)} vulnerabilities from offset {offset}")
            
            # Check if we got fewer items than requested (indicates end)
            if len(vulnerabilities) < page_size:
                logger.info("🏁 Reached end of data")
                break
            
            offset += page_size
            
            # Rate limiting
            await asyncio.sleep(self.api_config['delay_between_requests'])
        
        return all_vulnerabilities
    
    async def _download_cursor_based_pagination(self) -> List[Dict[str, Any]]:
        """Download using cursor-based pagination"""
        all_vulnerabilities = []
        cursor = None
        page = 1
        
        while page <= self.api_config['max_pages']:
            logger.info(f"📄 Downloading page {page} (cursor: {cursor})...")
            
            # Build URL with pagination parameters
            params = {
                self.api_config['size_param']: self.api_config['page_size']
            }
            if cursor:
                params[self.api_config['cursor_param']] = cursor
            
            # Make API request
            page_data = await self._make_api_request(self.api_endpoint, params)
            if not page_data:
                break
            
            # Extract vulnerabilities from response
            vulnerabilities = self._extract_vulnerabilities_from_response(page_data)
            if not vulnerabilities:
                logger.info("🏁 No more vulnerabilities found")
                break
            
            all_vulnerabilities.extend(vulnerabilities)
            logger.info(f"✓ Downloaded {len(vulnerabilities)} vulnerabilities from page {page}")
            
            # Get next cursor
            cursor = self._extract_next_cursor(page_data)
            if not cursor:
                logger.info("🏁 No more pages (no cursor)")
                break
            
            page += 1
            
            # Rate limiting
            await asyncio.sleep(self.api_config['delay_between_requests'])
        
        return all_vulnerabilities
    
    async def _download_single_request(self) -> List[Dict[str, Any]]:
        """Download from API with no pagination"""
        logger.info("📄 Downloading all data in single request...")
        
        # Make API request
        data = await self._make_api_request(self.api_endpoint)
        if not data:
            return []
        
        # Extract vulnerabilities from response
        vulnerabilities = self._extract_vulnerabilities_from_response(data)
        logger.info(f"✓ Downloaded {len(vulnerabilities)} vulnerabilities")
        
        return vulnerabilities
    
    async def _make_api_request(self, url: str, params: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """Make HTTP request to API with retry logic"""
        for attempt in range(self.api_config['retry_attempts']):
            try:
                self.stats['api_requests'] += 1
                
                async with self.session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data
                    elif response.status == 429:  # Rate limited
                        wait_time = 2 ** attempt  # Exponential backoff
                        logger.warning(f"⚠️ Rate limited, waiting {wait_time}s before retry...")
                        await asyncio.sleep(wait_time)
                        continue
                    else:
                        logger.warning(f"⚠️ API returned status {response.status}")
                        self.stats['failed_requests'] += 1
                        return None
                        
            except Exception as e:
                logger.warning(f"❌ API request failed (attempt {attempt + 1}): {e}")
                if attempt < self.api_config['retry_attempts'] - 1:
                    await asyncio.sleep(1)
                continue
        
        self.stats['failed_requests'] += 1
        return None
    
    def _extract_vulnerabilities_from_response(self, response_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract vulnerability data from API response
        
        TEMPLATE: Customize for your API's response structure
        """
        if not response_data:
            return []
        
        # Try different common response structures
        data_field = self.api_config['data_field']
        
        # Method 1: Data in specified field
        if data_field in response_data and isinstance(response_data[data_field], list):
            return response_data[data_field]
        
        # Method 2: Response is directly a list
        if isinstance(response_data, list):
            return response_data
        
        # Method 3: Common field names
        common_fields = ['vulnerabilities', 'advisories', 'items', 'results', 'entries']
        for field in common_fields:
            if field in response_data and isinstance(response_data[field], list):
                return response_data[field]
        
        # Method 4: Return response as single item if it contains vulnerability data
        if any(key in response_data for key in ['cve', 'id', 'title', 'description']):
            return [response_data]
        
        return []
    
    def _has_more_pages(self, response_data: Dict[str, Any]) -> bool:
        """Check if there are more pages available"""
        if not response_data:
            return False
        
        # Check pagination info field
        pagination_field = self.api_config['pagination_info_field']
        if pagination_field in response_data:
            pagination_info = response_data[pagination_field]
            
            # Check has_more field
            has_more_field = self.api_config['has_more_field']
            if has_more_field in pagination_info:
                return bool(pagination_info[has_more_field])
            
            # Check next_page field
            next_page_field = self.api_config['next_page_field']
            if next_page_field in pagination_info:
                return pagination_info[next_page_field] is not None
        
        # If no explicit pagination info, assume no more pages
        return False
    
    def _extract_next_cursor(self, response_data: Dict[str, Any]) -> Optional[str]:
        """Extract next cursor from response"""
        if not response_data:
            return None
        
        pagination_field = self.api_config['pagination_info_field']
        if pagination_field in response_data:
            pagination_info = response_data[pagination_field]
            cursor_field = self.api_config['cursor_param']
            return pagination_info.get(cursor_field)
        
        return None
    
    def _process_vulnerability_data(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process and standardize vulnerability data
        
        TEMPLATE: Customize field mapping for your API data format
        """
        processed_vulnerabilities = []
        
        for vuln in vulnerabilities:
            try:
                # Extract and standardize fields - UPDATE for your API format
                processed_vuln = {
                    'source_api_id': vuln.get('id', vuln.get('advisory_id', '')),
                    'cve_identifiers': self._extract_cve_ids(vuln),
                    'title': vuln.get('title', vuln.get('summary', '')),
                    'description': vuln.get('description', vuln.get('details', '')),
                    'severity': self._normalize_severity(vuln.get('severity', vuln.get('priority', 'UNKNOWN'))),
                    'published_date': vuln.get('published_at', vuln.get('created_at', vuln.get('published'))),
                    'updated_date': vuln.get('updated_at', vuln.get('modified_at', vuln.get('modified'))),
                    'affected_packages': self._extract_affected_packages(vuln),
                    'references': self._extract_references(vuln),
                    'cvss_score': self._extract_cvss_score(vuln),
                    'cwe_ids': self._extract_cwe_ids(vuln),
                    'source_name': self.source_name,
                    'raw_data': vuln  # Keep original data for debugging
                }
                
                # Only include vulnerabilities with meaningful data
                if (processed_vuln['cve_identifiers'] or 
                    processed_vuln['title'] or 
                    len(processed_vuln['description']) > 10):
                    processed_vulnerabilities.append(processed_vuln)
                
            except Exception as e:
                logger.warning(f"Failed to process vulnerability: {e}")
                continue
        
        return processed_vulnerabilities
    
    def _extract_cve_ids(self, vuln: Dict[str, Any]) -> List[str]:
        """Extract CVE identifiers from vulnerability data"""
        import re
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        cve_ids = set()
        
        # Common CVE fields
        cve_fields = ['cve', 'cve_id', 'cve_ids', 'identifiers', 'aliases']
        
        for field in cve_fields:
            if field in vuln:
                value = vuln[field]
                if isinstance(value, str):
                    matches = re.findall(cve_pattern, value)
                    cve_ids.update(matches)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str):
                            matches = re.findall(cve_pattern, item)
                            cve_ids.update(matches)
                        elif isinstance(item, dict) and 'value' in item:
                            matches = re.findall(cve_pattern, item['value'])
                            cve_ids.update(matches)
        
        return list(cve_ids)
    
    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity to standard levels"""
        if not severity:
            return 'UNKNOWN'
        
        severity_upper = str(severity).upper()
        
        # Map various severity formats to standard levels
        severity_mapping = {
            'CRITICAL': 'CRITICAL',
            'HIGH': 'HIGH',
            'MEDIUM': 'MEDIUM',
            'MODERATE': 'MEDIUM',
            'LOW': 'LOW',
            'IMPORTANT': 'HIGH',
            'URGENT': 'CRITICAL',
            'SEVERE': 'HIGH'
        }
        
        for term, level in severity_mapping.items():
            if term in severity_upper:
                return level
        
        return 'UNKNOWN'
    
    def _extract_affected_packages(self, vuln: Dict[str, Any]) -> List[str]:
        """Extract affected packages from vulnerability data"""
        packages = []
        
        # Common package fields
        package_fields = ['affected_packages', 'packages', 'affected', 'vulnerable_packages']
        
        for field in package_fields:
            if field in vuln:
                value = vuln[field]
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, str):
                            packages.append(item)
                        elif isinstance(item, dict):
                            name = item.get('name', item.get('package_name', ''))
                            if name:
                                packages.append(name)
                elif isinstance(value, str):
                    packages.append(value)
        
        return packages[:10]  # Limit to 10 packages
    
    def _extract_references(self, vuln: Dict[str, Any]) -> List[str]:
        """Extract reference URLs from vulnerability data"""
        references = []
        
        # Common reference fields
        ref_fields = ['references', 'urls', 'links', 'external_references']
        
        for field in ref_fields:
            if field in vuln:
                value = vuln[field]
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, str) and item.startswith('http'):
                            references.append(item)
                        elif isinstance(item, dict):
                            url = item.get('url', item.get('link', ''))
                            if url and url.startswith('http'):
                                references.append(url)
                elif isinstance(value, str) and value.startswith('http'):
                    references.append(value)
        
        return references[:5]  # Limit to 5 references
    
    def _extract_cvss_score(self, vuln: Dict[str, Any]) -> Optional[float]:
        """Extract CVSS score from vulnerability data"""
        cvss_fields = ['cvss_score', 'cvss', 'score', 'base_score']
        
        for field in cvss_fields:
            if field in vuln:
                value = vuln[field]
                if isinstance(value, (int, float)):
                    return float(value)
                elif isinstance(value, dict):
                    score = value.get('score', value.get('base_score'))
                    if isinstance(score, (int, float)):
                        return float(score)
                elif isinstance(value, str):
                    try:
                        return float(value)
                    except ValueError:
                        continue
        
        return None
    
    def _extract_cwe_ids(self, vuln: Dict[str, Any]) -> List[str]:
        """Extract CWE identifiers from vulnerability data"""
        import re
        cwe_pattern = r'CWE-\d+'
        cwe_ids = set()
        
        # Common CWE fields
        cwe_fields = ['cwe', 'cwe_id', 'cwe_ids', 'weaknesses']
        
        for field in cwe_fields:
            if field in vuln:
                value = vuln[field]
                if isinstance(value, str):
                    matches = re.findall(cwe_pattern, value)
                    cwe_ids.update(matches)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str):
                            matches = re.findall(cwe_pattern, item)
                            cwe_ids.update(matches)
                        elif isinstance(item, dict):
                            cwe_id = item.get('id', item.get('cwe_id', ''))
                            if cwe_id:
                                matches = re.findall(cwe_pattern, str(cwe_id))
                                cwe_ids.update(matches)
        
        return list(cwe_ids)
    
    def _analyze_data_structure(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze the structure of vulnerability data"""
        if not data:
            return {'data_type': 'empty_list', 'total_size': 0}
        
        sample_vuln = data[0]
        
        # Count vulnerabilities with different types of data
        vulns_with_cves = sum(1 for vuln in data if vuln.get('cve_identifiers'))
        vulns_with_cvss = sum(1 for vuln in data if vuln.get('cvss_score'))
        vulns_with_packages = sum(1 for vuln in data if vuln.get('affected_packages'))
        
        analysis = {
            'data_type': 'list_of_api_vulnerabilities',
            'total_vulnerabilities': len(data),
            'vulnerability_structure': list(sample_vuln.keys()),
            'vulnerabilities_with_cves': vulns_with_cves,
            'vulnerabilities_with_cvss': vulns_with_cvss,
            'vulnerabilities_with_packages': vulns_with_packages,
            'data_completeness_score': (vulns_with_cves + vulns_with_cvss) / (len(data) * 2) if data else 0,
            'api_success_rate': (self.stats['api_requests'] - self.stats['failed_requests']) / max(self.stats['api_requests'], 1)
        }
        
        return analysis
    
    def _generate_field_mappings(self) -> Dict[str, str]:
        """Generate field mappings for parser"""
        return {
            'source_api_id': 'identifier',
            'cve_identifiers': 'cve_ids',
            'title': 'title',
            'description': 'description',
            'severity': 'severity',
            'published_date': 'published_date',
            'updated_date': 'last_modified_date',
            'affected_packages': 'affected_packages',
            'references': 'references',
            'cvss_score': 'cvss_score',
            'cwe_ids': 'cwe_ids'
        }
    
    async def test_connectivity(self) -> Dict[str, Any]:
        """Test API connectivity and basic functionality"""
        logger.info(f"🔍 Testing JSON API connectivity for {self.api_endpoint}")
        
        try:
            start_time = datetime.utcnow()
            
            # Test basic API connectivity
            test_data = await self._make_api_request(self.api_endpoint, {'limit': 1})
            response_time = (datetime.utcnow() - start_time).total_seconds()
            
            if test_data:
                vulnerabilities = self._extract_vulnerabilities_from_response(test_data)
                
                logger.info(f"✅ API connectivity test passed ({response_time:.2f}s)")
                logger.info(f"📊 Sample response contains {len(vulnerabilities)} vulnerabilities")
                
                return {
                    'status': 'success',
                    'response_time_seconds': response_time,
                    'sample_vulnerabilities_count': len(vulnerabilities),
                    'has_pagination_info': self._has_more_pages(test_data),
                    'response_structure': list(test_data.keys()) if isinstance(test_data, dict) else 'list',
                    'timestamp': datetime.utcnow().isoformat()
                }
            else:
                return {
                    'status': 'failed',
                    'error': 'No data received from API',
                    'timestamp': datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            logger.error(f"❌ API connectivity test failed: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def display_statistics(self):
        """Display download statistics"""
        logger.info("=" * 70)
        logger.info(f"📊 JSON API Download Statistics ({self.source_name})")
        logger.info("=" * 70)
        logger.info(f"🛡️ Vulnerabilities: {self.stats['total_vulnerabilities']:,}")
        logger.info(f"📡 API Requests: {self.stats['api_requests']:,}")
        logger.info(f"❌ Failed Requests: {self.stats['failed_requests']:,}")
        logger.info(f"⏱️ Processing Time: {self.stats['processing_time_seconds']:.1f}s")
        logger.info(f"💾 Data Size: {self.stats['data_size_mb']:.2f} MB")
        
        success_rate = ((self.stats['api_requests'] - self.stats['failed_requests']) / 
                       max(self.stats['api_requests'], 1) * 100)
        logger.info(f"✅ Success Rate: {success_rate:.1f}%")
        
        logger.info(f"🌐 API Endpoint: {self.api_endpoint}")
        logger.info("=" * 70)

async def main():
    """Main execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Download from JSON vulnerability API')
    parser.add_argument('--source-name', required=True,
                       help='Name of the vulnerability source')
    parser.add_argument('--api-endpoint', required=True,
                       help='JSON API endpoint URL')
    parser.add_argument('--test-connectivity', action='store_true',
                       help='Test API connectivity only')
    parser.add_argument('--output-dir', 
                       help='Output directory for downloaded data')
    
    args = parser.parse_args()
    
    async with JSONAPIVulnerabilityDownloader(args.source_name, args.api_endpoint) as downloader:
        try:
            if args.test_connectivity:
                results = await downloader.test_connectivity()
                print(f"Connectivity test: {results['status']}")
                if results['status'] == 'success':
                    print(f"Sample vulnerabilities: {results['sample_vulnerabilities_count']}")
                return
            
            # Download and save data
            output_file = await downloader.download_and_save_data(args.output_dir)
            
            # Display statistics
            downloader.display_statistics()
            
            print(f"✅ JSON API download completed!")
            print(f"📁 Output file: {output_file}")
            
        except Exception as e:
            print(f"❌ Download failed: {e}")
            sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())