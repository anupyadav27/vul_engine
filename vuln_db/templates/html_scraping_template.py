#!/usr/bin/env python3
"""
HTML Web Scraping Data Downloader Template

APPLIES TO SOURCES (29 sources):
- Debian Security Tracker
- Ubuntu Security Notices  
- Red Hat Security Advisories
- Amazon Linux Security
- SUSE Security
- CentOS Security
- Oracle Linux Security
- OpenShift Security
- JBoss Security
- PyPI Security
- Maven Central (OSS Index)
- Go Vulnerability Database
- AWS Security Bulletins
- GCP Security Bulletins
- Oracle Cloud Security
- Oracle Database Security
- WebLogic Security
- PostgreSQL Security
- MySQL Security
- Redis Security
- MariaDB Security
- MongoDB Security
- Cassandra Security
- Apache Security
- Nginx Security
- Tomcat Security
- Istio Security
- Azure Security Updates
- SQL Server Security

OBJECTIVE:
Downloads vulnerability data from HTML pages using web scraping with BeautifulSoup.
This template provides a flexible foundation for scraping various security advisory websites.

DATA FORMAT: HTML pages with structured content
COMPLEXITY: High
IMPLEMENTATION APPROACH: BeautifulSoup + requests with CSS selectors

TEMPLATE USAGE:
1. Update BASE_URL and source configuration
2. Customize CSS selectors for target site structure
3. Implement source-specific parsing logic
4. Update field extraction methods for site's data format
"""

import asyncio
import aiohttp
import json
import logging
import sys
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin, urlparse
import time

# HTML parsing libraries
from bs4 import BeautifulSoup
import requests

# Add vuln_db root to Python path
current_dir = Path(__file__).resolve().parent
vuln_db_root = current_dir.parent.parent.parent
sys.path.insert(0, str(vuln_db_root))
sys.path.append(str(vuln_db_root / "config"))

from source_config import get_source_config

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class HTMLSecurityAdvisoryScraper:
    """
    HTML web scraping downloader for security advisories
    
    TEMPLATE INSTRUCTIONS:
    1. Update base_url for your target site
    2. Customize CSS selectors for site structure
    3. Implement source-specific parsing methods
    4. Update field extraction logic for site's format
    5. Configure pagination handling if needed
    """
    
    def __init__(self, source_name: str = "security_source", base_url: str = "https://example.com/security/"):
        """Initialize HTML scraper"""
        # UPDATE: Set your source configuration
        self.source_name = source_name.lower().replace(" ", "_")
        self.base_url = base_url
        
        # REQUEST CONFIGURATION - UPDATE as needed
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Session for connection pooling and cookies
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
        # SITE-SPECIFIC CONFIGURATION - UPDATE for your target site
        self.site_config = {
            # CSS selectors for common elements - CUSTOMIZE these
            'advisory_links': 'a[href*="advisory"], a[href*="security"], a[href*="CVE"]',  # Links to individual advisories
            'advisory_list': '.security-list, .advisory-list, .vulnerability-list',         # Container for advisory list
            'pagination_links': 'a[href*="page"], .pagination a, .next',                   # Pagination controls
            'date_selector': '.date, .published, .updated, time',                         # Date elements
            'title_selector': 'h1, h2, .title, .advisory-title',                         # Advisory titles
            'description_selector': '.description, .summary, .content, p',                # Description content
            'cve_selector': 'a[href*="CVE"], .cve, .cve-id',                             # CVE links/IDs
            'severity_selector': '.severity, .priority, .risk',                          # Severity indicators
            
            # Site-specific patterns - CUSTOMIZE these
            'advisory_url_pattern': r'/advisory/|/security/|/CVE-',                       # URL pattern for advisories
            'cve_pattern': r'CVE-\d{4}-\d{4,}',                                          # CVE ID pattern
            'date_patterns': [                                                            # Date format patterns
                r'\d{4}-\d{2}-\d{2}',           # YYYY-MM-DD
                r'\d{2}/\d{2}/\d{4}',           # MM/DD/YYYY
                r'\w+ \d{1,2}, \d{4}',          # Month DD, YYYY
            ],
            
            # Processing configuration
            'max_pages': 50,                    # Maximum pages to scrape
            'delay_between_requests': 1.0,      # Delay in seconds between requests
            'timeout_seconds': 30,              # Request timeout
            'follow_redirects': True            # Follow HTTP redirects
        }
        
        # Statistics tracking
        self.stats = {
            'pages_scraped': 0,
            'advisories_found': 0,
            'cves_extracted': 0,
            'failed_requests': 0,
            'data_size_mb': 0
        }
        
        # Scraped data storage
        self.scraped_advisories = []
    
    async def download_and_save_data(self, output_dir: str = None) -> str:
        """Download and scrape security advisories from HTML pages"""
        if output_dir is None:
            output_dir = current_dir / "output" / "data_downloads"
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"🚀 Starting HTML scraping for {self.source_name}")
        logger.info(f"🌐 Base URL: {self.base_url}")
        
        try:
            # Step 1: Discover advisory pages
            advisory_urls = await self._discover_advisory_pages()
            logger.info(f"🔍 Discovered {len(advisory_urls)} advisory URLs")
            
            # Step 2: Scrape individual advisories
            scraped_data = await self._scrape_advisories(advisory_urls)
            
            # Step 3: Process and clean data
            processed_data = self._process_scraped_data(scraped_data)
            structure_analysis = self._analyze_data_structure(processed_data)
            
            # Update statistics
            self.stats['advisories_found'] = len(processed_data)
            self.stats['cves_extracted'] = sum(1 for adv in processed_data if adv.get('cve_identifiers'))
            
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
                    'source_url': self.base_url,
                    'scraping_method': 'html_beautifulsoup',
                    'total_advisories': self.stats['advisories_found'],
                    'total_cves': self.stats['cves_extracted'],
                    'pages_scraped': self.stats['pages_scraped'],
                    'failed_requests': self.stats['failed_requests'],
                    'data_size_mb': file_size_mb,
                    'content_type': 'text/html',
                    'structure_analysis': structure_analysis,
                    'field_mappings': self._generate_field_mappings(),
                    'site_config': self.site_config
                },
                'data': processed_data
            }
            
            # Save to file
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(final_data, f, indent=2, ensure_ascii=False, default=str)
            
            logger.info(f"✅ HTML scraping completed successfully")
            logger.info(f"📁 File: {output_file}")
            logger.info(f"📊 Advisories: {self.stats['advisories_found']:,}")
            logger.info(f"🛡️ CVEs: {self.stats['cves_extracted']:,}")
            logger.info(f"📄 Pages: {self.stats['pages_scraped']:,}")
            logger.info(f"💾 Size: {file_size_mb:.2f} MB")
            
            return str(output_file)
            
        except Exception as e:
            logger.error(f"❌ Failed to scrape HTML data: {e}")
            raise
        finally:
            # Clean up session
            self.session.close()
    
    async def _discover_advisory_pages(self) -> List[str]:
        """
        Discover advisory pages by scraping index/listing pages
        
        TEMPLATE: Customize this method for your site's structure
        """
        advisory_urls = set()
        
        try:
            # Start with the base URL
            current_url = self.base_url
            page_num = 1
            
            while page_num <= self.site_config['max_pages']:
                logger.info(f"📄 Discovering advisories from page {page_num}: {current_url}")
                
                # Fetch the page
                response = self.session.get(
                    current_url, 
                    timeout=self.site_config['timeout_seconds']
                )
                
                if response.status_code != 200:
                    logger.warning(f"⚠️ Page {page_num} returned status {response.status_code}")
                    break
                
                # Parse HTML
                soup = BeautifulSoup(response.content, 'html.parser')
                self.stats['pages_scraped'] += 1
                
                # Extract advisory links using CSS selectors
                advisory_links = soup.select(self.site_config['advisory_links'])
                page_advisory_count = 0
                
                for link in advisory_links:
                    href = link.get('href')
                    if href:
                        # Convert relative URLs to absolute
                        full_url = urljoin(current_url, href)
                        
                        # Filter by advisory URL pattern
                        if re.search(self.site_config['advisory_url_pattern'], full_url, re.IGNORECASE):
                            advisory_urls.add(full_url)
                            page_advisory_count += 1
                
                logger.info(f"✓ Found {page_advisory_count} advisory links on page {page_num}")
                
                # Look for next page
                next_url = self._find_next_page_url(soup, current_url)
                if not next_url or next_url == current_url:
                    logger.info("🏁 No more pages found")
                    break
                
                current_url = next_url
                page_num += 1
                
                # Rate limiting
                time.sleep(self.site_config['delay_between_requests'])
            
            logger.info(f"🔍 Discovery complete: {len(advisory_urls)} unique advisory URLs found")
            return list(advisory_urls)
            
        except Exception as e:
            logger.error(f"❌ Failed to discover advisory pages: {e}")
            return list(advisory_urls)
    
    def _find_next_page_url(self, soup: BeautifulSoup, current_url: str) -> Optional[str]:
        """
        Find the URL for the next page of results
        
        TEMPLATE: Customize for your site's pagination structure
        """
        # Try different pagination selectors
        pagination_selectors = [
            'a.next',
            'a[rel="next"]',
            '.pagination a:contains("Next")',
            '.pagination a:contains(">")',
            'a[href*="page="]:contains("Next")'
        ]
        
        for selector in pagination_selectors:
            try:
                next_link = soup.select_one(selector)
                if next_link and next_link.get('href'):
                    return urljoin(current_url, next_link['href'])
            except:
                continue
        
        # Try to find pagination with page numbers
        pagination_links = soup.select(self.site_config['pagination_links'])
        if pagination_links:
            # Look for the highest page number
            current_page_num = self._extract_page_number(current_url)
            next_page_num = current_page_num + 1 if current_page_num else 2
            
            for link in pagination_links:
                page_num = self._extract_page_number(link.get('href', ''))
                if page_num == next_page_num:
                    return urljoin(current_url, link['href'])
        
        return None
    
    def _extract_page_number(self, url: str) -> Optional[int]:
        """Extract page number from URL"""
        if not url:
            return None
        
        # Common page parameter patterns
        patterns = [
            r'page=(\d+)',
            r'p=(\d+)',
            r'/page/(\d+)',
            r'/(\d+)/?$'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                try:
                    return int(match.group(1))
                except:
                    continue
        
        return None
    
    async def _scrape_advisories(self, advisory_urls: List[str]) -> List[Dict[str, Any]]:
        """
        Scrape individual advisory pages
        
        TEMPLATE: Customize parsing logic for your site's advisory format
        """
        scraped_advisories = []
        
        for i, url in enumerate(advisory_urls[:100], 1):  # Limit for testing
            try:
                logger.info(f"📋 Scraping advisory {i}/{len(advisory_urls[:100])}: {url}")
                
                # Fetch advisory page
                response = self.session.get(
                    url, 
                    timeout=self.site_config['timeout_seconds']
                )
                
                if response.status_code != 200:
                    logger.warning(f"⚠️ Advisory page returned status {response.status_code}: {url}")
                    self.stats['failed_requests'] += 1
                    continue
                
                # Parse advisory content
                soup = BeautifulSoup(response.content, 'html.parser')
                advisory_data = self._extract_advisory_data(soup, url)
                
                if advisory_data:
                    scraped_advisories.append(advisory_data)
                
                # Rate limiting
                time.sleep(self.site_config['delay_between_requests'])
                
            except Exception as e:
                logger.warning(f"❌ Failed to scrape advisory {url}: {e}")
                self.stats['failed_requests'] += 1
                continue
        
        logger.info(f"✓ Successfully scraped {len(scraped_advisories)} advisories")
        return scraped_advisories
    
    def _extract_advisory_data(self, soup: BeautifulSoup, url: str) -> Dict[str, Any]:
        """
        Extract data from individual advisory page
        
        TEMPLATE: Customize field extraction for your site's format
        """
        try:
            advisory_data = {
                'source_url': url,
                'scraped_timestamp': datetime.utcnow().isoformat()
            }
            
            # Extract title
            title_element = soup.select_one(self.site_config['title_selector'])
            advisory_data['title'] = title_element.get_text(strip=True) if title_element else ''
            
            # Extract description/content
            description_elements = soup.select(self.site_config['description_selector'])
            if description_elements:
                # Combine multiple paragraphs
                description_parts = [elem.get_text(strip=True) for elem in description_elements if elem.get_text(strip=True)]
                advisory_data['description'] = '\n'.join(description_parts[:3])  # Limit to first 3 paragraphs
            else:
                advisory_data['description'] = ''
            
            # Extract CVE identifiers
            advisory_data['cve_identifiers'] = self._extract_cve_identifiers(soup, url)
            
            # Extract dates
            advisory_data['published_date'] = self._extract_date(soup, 'published')
            advisory_data['updated_date'] = self._extract_date(soup, 'updated')
            
            # Extract severity
            advisory_data['severity'] = self._extract_severity(soup)
            
            # Extract affected packages/products
            advisory_data['affected_packages'] = self._extract_affected_packages(soup)
            
            # Extract references/links
            advisory_data['references'] = self._extract_references(soup, url)
            
            # Store raw HTML for debugging (first 1000 chars)
            advisory_data['raw_html_sample'] = str(soup)[:1000] + "..." if len(str(soup)) > 1000 else str(soup)
            
            return advisory_data
            
        except Exception as e:
            logger.warning(f"Failed to extract data from {url}: {e}")
            return None
    
    def _extract_cve_identifiers(self, soup: BeautifulSoup, url: str) -> List[str]:
        """Extract CVE identifiers from page"""
        cve_ids = set()
        
        # Method 1: Look for CVE links
        cve_links = soup.select(self.site_config['cve_selector'])
        for link in cve_links:
            text = link.get_text()
            matches = re.findall(self.site_config['cve_pattern'], text)
            cve_ids.update(matches)
        
        # Method 2: Search all text content
        page_text = soup.get_text()
        matches = re.findall(self.site_config['cve_pattern'], page_text)
        cve_ids.update(matches)
        
        # Method 3: Check URL for CVE ID
        url_matches = re.findall(self.site_config['cve_pattern'], url)
        cve_ids.update(url_matches)
        
        return list(cve_ids)
    
    def _extract_date(self, soup: BeautifulSoup, date_type: str) -> Optional[str]:
        """Extract date information"""
        date_elements = soup.select(self.site_config['date_selector'])
        
        for element in date_elements:
            # Check element text and attributes
            text_sources = [
                element.get_text(strip=True),
                element.get('datetime', ''),
                element.get('title', ''),
                element.get('data-date', '')
            ]
            
            for text in text_sources:
                if not text:
                    continue
                
                # Try to match date patterns
                for pattern in self.site_config['date_patterns']:
                    match = re.search(pattern, text)
                    if match:
                        return match.group(0)
        
        return None
    
    def _extract_severity(self, soup: BeautifulSoup) -> str:
        """Extract severity information"""
        severity_element = soup.select_one(self.site_config['severity_selector'])
        
        if severity_element:
            severity_text = severity_element.get_text(strip=True).upper()
            
            # Map common severity terms
            severity_mapping = {
                'CRITICAL': 'CRITICAL',
                'HIGH': 'HIGH',
                'MEDIUM': 'MEDIUM',
                'MODERATE': 'MEDIUM',
                'LOW': 'LOW',
                'IMPORTANT': 'HIGH',
                'URGENT': 'CRITICAL'
            }
            
            for term, level in severity_mapping.items():
                if term in severity_text:
                    return level
        
        return 'UNKNOWN'
    
    def _extract_affected_packages(self, soup: BeautifulSoup) -> List[str]:
        """Extract affected packages/products"""
        # Look for common package indicators
        package_selectors = [
            '.package, .product, .affected',
            'li:contains("Package")',
            'td:contains("Package")',
            'code, .code'
        ]
        
        packages = set()
        
        for selector in package_selectors:
            try:
                elements = soup.select(selector)
                for element in elements:
                    text = element.get_text(strip=True)
                    if text and len(text) < 100:  # Reasonable package name length
                        packages.add(text)
            except:
                continue
        
        return list(packages)[:10]  # Limit to 10 packages
    
    def _extract_references(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract reference links"""
        references = set()
        
        # Find all external links
        links = soup.find_all('a', href=True)
        
        for link in links:
            href = link['href']
            full_url = urljoin(base_url, href)
            
            # Filter for external references (not internal navigation)
            if (full_url.startswith('http') and 
                not urlparse(full_url).netloc == urlparse(base_url).netloc and
                len(full_url) < 200):  # Reasonable URL length
                references.add(full_url)
        
        return list(references)[:5]  # Limit to 5 references
    
    def _process_scraped_data(self, scraped_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process and clean scraped data"""
        processed_advisories = []
        
        for advisory in scraped_data:
            try:
                # Clean and standardize the data
                processed_advisory = {
                    'source_url': advisory.get('source_url'),
                    'title': advisory.get('title', '').strip()[:200],  # Limit title length
                    'description': advisory.get('description', '').strip()[:1000],  # Limit description
                    'cve_identifiers': advisory.get('cve_identifiers', []),
                    'severity': advisory.get('severity', 'UNKNOWN'),
                    'published_date': advisory.get('published_date'),
                    'updated_date': advisory.get('updated_date'),
                    'affected_packages': advisory.get('affected_packages', []),
                    'references': advisory.get('references', []),
                    'scraped_timestamp': advisory.get('scraped_timestamp'),
                    'source_name': self.source_name
                }
                
                # Only include advisories with meaningful content
                if (processed_advisory['title'] or 
                    processed_advisory['cve_identifiers'] or 
                    len(processed_advisory['description']) > 20):
                    processed_advisories.append(processed_advisory)
                
            except Exception as e:
                logger.warning(f"Failed to process scraped advisory: {e}")
                continue
        
        return processed_advisories
    
    def _analyze_data_structure(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze the structure of scraped data"""
        if not data:
            return {'data_type': 'empty_list', 'total_size': 0}
        
        sample_advisory = data[0]
        
        # Count advisories with different types of data
        advisories_with_cves = sum(1 for adv in data if adv.get('cve_identifiers'))
        advisories_with_dates = sum(1 for adv in data if adv.get('published_date'))
        advisories_with_packages = sum(1 for adv in data if adv.get('affected_packages'))
        
        analysis = {
            'data_type': 'list_of_scraped_advisories',
            'total_advisories': len(data),
            'advisory_structure': list(sample_advisory.keys()),
            'advisories_with_cves': advisories_with_cves,
            'advisories_with_dates': advisories_with_dates,
            'advisories_with_packages': advisories_with_packages,
            'data_completeness_score': (advisories_with_cves + advisories_with_dates) / (len(data) * 2) if data else 0,
            'scraping_success_rate': len(data) / max(self.stats['pages_scraped'], 1)
        }
        
        return analysis
    
    def _generate_field_mappings(self) -> Dict[str, str]:
        """Generate field mappings for parser"""
        return {
            'title': 'title',
            'description': 'description', 
            'cve_identifiers': 'cve_ids',
            'severity': 'severity',
            'published_date': 'published_date',
            'updated_date': 'last_modified_date',
            'affected_packages': 'affected_packages',
            'references': 'references',
            'source_url': 'source_url'
        }
    
    async def test_connectivity(self) -> Dict[str, Any]:
        """Test website connectivity and basic scraping"""
        logger.info(f"🔍 Testing HTML scraping connectivity for {self.base_url}")
        
        try:
            start_time = datetime.utcnow()
            
            response = self.session.get(
                self.base_url, 
                timeout=self.site_config['timeout_seconds']
            )
            
            response_time = (datetime.utcnow() - start_time).total_seconds()
            
            if response.status_code == 200:
                # Basic HTML parsing test
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Count potential advisory links
                advisory_links = soup.select(self.site_config['advisory_links'])
                
                logger.info(f"✅ Website connectivity test passed ({response_time:.2f}s)")
                logger.info(f"📊 Found {len(advisory_links)} potential advisory links")
                
                return {
                    'status': 'success',
                    'status_code': response.status_code,
                    'response_time_seconds': response_time,
                    'content_length': len(response.content),
                    'potential_advisory_links': len(advisory_links),
                    'has_pagination': bool(soup.select(self.site_config['pagination_links'])),
                    'timestamp': datetime.utcnow().isoformat()
                }
            else:
                return {
                    'status': 'failed',
                    'status_code': response.status_code,
                    'response_time_seconds': response_time,
                    'timestamp': datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            logger.error(f"❌ Website connectivity test failed: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
        finally:
            self.session.close()
    
    def display_statistics(self):
        """Display scraping statistics"""
        logger.info("=" * 70)
        logger.info(f"📊 HTML Scraping Statistics ({self.source_name})")
        logger.info("=" * 70)
        logger.info(f"📄 Pages Scraped: {self.stats['pages_scraped']:,}")
        logger.info(f"📋 Advisories Found: {self.stats['advisories_found']:,}")
        logger.info(f"🛡️ CVEs Extracted: {self.stats['cves_extracted']:,}")
        logger.info(f"❌ Failed Requests: {self.stats['failed_requests']:,}")
        logger.info(f"💾 Data Size: {self.stats['data_size_mb']:.2f} MB")
        
        success_rate = ((self.stats['pages_scraped'] - self.stats['failed_requests']) / 
                       max(self.stats['pages_scraped'], 1) * 100)
        logger.info(f"✅ Success Rate: {success_rate:.1f}%")
        
        logger.info(f"🌐 Base URL: {self.base_url}")
        logger.info("=" * 70)

async def main():
    """Main execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Scrape HTML security advisories')
    parser.add_argument('--source-name', required=True,
                       help='Name of the security source')
    parser.add_argument('--base-url', required=True,
                       help='Base URL for the security advisories')
    parser.add_argument('--test-connectivity', action='store_true',
                       help='Test website connectivity only')
    parser.add_argument('--output-dir', 
                       help='Output directory for downloaded data')
    
    args = parser.parse_args()
    
    scraper = HTMLSecurityAdvisoryScraper(args.source_name, args.base_url)
    
    try:
        if args.test_connectivity:
            results = await scraper.test_connectivity()
            print(f"Connectivity test: {results['status']}")
            if results['status'] == 'success':
                print(f"Found {results['potential_advisory_links']} potential advisory links")
            return
        
        # Download and save data
        output_file = await scraper.download_and_save_data(args.output_dir)
        
        # Display statistics
        scraper.display_statistics()
        
        print(f"✅ HTML scraping completed!")
        print(f"📁 Output file: {output_file}")
        
    except Exception as e:
        print(f"❌ Scraping failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())