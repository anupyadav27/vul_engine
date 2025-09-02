#!/usr/bin/env python3
"""
NVD Initial Data Downloader - Step 1

APPROACH:
1. Download all historical NVD CVE data feeds (2002-2024 + modified feeds)
2. Use NVD API 2.0 for recent data (2023-2024) and real-time updates
3. Download MITRE ATT&CK framework data for technique mapping
4. Store raw data in organized structure for parsing

DATA SOURCES:
- NVD CVE Feeds: https://nvd.nist.gov/vuln/data-feeds (Legacy JSON 1.1 feeds)
- NVD API 2.0: https://services.nvd.nist.gov/rest/json/cves/2.0
- MITRE ATT&CK: https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

OUTPUTS:
- Raw NVD data files by year (2002-2024)
- Modified CVE feeds for updates
- MITRE ATT&CK framework data
- Download metadata and statistics
"""

import sys
import asyncio
import logging
import aiohttp
import json
import gzip
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import time
import zipfile

# Add vuln_db root to Python path
current_dir = Path(__file__).resolve().parent
vuln_db_root = current_dir.parent.parent.parent
sys.path.insert(0, str(vuln_db_root))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class NVDInitialDownloader:
    """NVD initial data downloader with comprehensive coverage"""
    
    def __init__(self):
        self.output_dir = current_dir / "output"
        self.data_downloads_dir = self.output_dir / "data_downloads"
        
        # Create output directories
        self.data_downloads_dir.mkdir(parents=True, exist_ok=True)
        
        # NVD Data Sources
        self.nvd_feeds_base_url = "https://nvd.nist.gov/feeds/json/cve/1.1"
        self.nvd_api_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.mitre_attack_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        
        # Rate limiting for NVD API
        self.api_delay = 6  # 6 seconds between API requests (10 requests per minute)
        self.session = None
        
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=300),  # 5 minute timeout
            connector=aiohttp.TCPConnector(limit=10)
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def download_initial_data(self) -> Dict[str, Any]:
        """Main method to download all initial NVD data"""
        logger.info("🚀 Starting NVD initial data download...")
        start_time = datetime.now(datetime.timezone.utc)
        
        results = {
            'start_time': start_time.isoformat(),
            'downloads': {},
            'errors': [],
            'total_cves': 0,
            'total_files': 0
        }
        
        try:
            # Step 1: Download historical CVE feeds (2002-2022)
            logger.info("📥 Downloading historical NVD CVE feeds (2002-2022)...")
            historical_results = await self.download_historical_feeds()
            results['downloads']['historical_feeds'] = historical_results
            
            # Step 2: Download recent data via API (2023-2024)
            logger.info("📥 Downloading recent CVE data via NVD API (2023-2024)...")
            recent_results = await self.download_recent_via_api()
            results['downloads']['recent_api_data'] = recent_results
            
            # Step 3: Download modified CVE feeds
            logger.info("📥 Downloading modified CVE feeds...")
            modified_results = await self.download_modified_feeds()
            results['downloads']['modified_feeds'] = modified_results
            
            # Step 4: Download MITRE ATT&CK data
            logger.info("📥 Downloading MITRE ATT&CK framework data...")
            mitre_results = await self.download_mitre_attack_data()
            results['downloads']['mitre_attack'] = mitre_results
            
            # Calculate totals
            for download_type, download_data in results['downloads'].items():
                if isinstance(download_data, dict):
                    results['total_cves'] += download_data.get('total_cves', 0)
                    results['total_files'] += download_data.get('files_downloaded', 0)
            
        except Exception as e:
            logger.error(f"❌ Error during initial download: {e}")
            results['errors'].append(str(e))
        
        # Finalize results
        end_time = datetime.now(datetime.timezone.utc)
        results['end_time'] = end_time.isoformat()
        results['duration_seconds'] = (end_time - start_time).total_seconds()
        results['success'] = len(results['errors']) == 0
        
        # Save download metadata
        await self.save_download_metadata(results)
        
        # Log summary
        self.log_download_summary(results)
        
        return results
    
    async def download_historical_feeds(self) -> Dict[str, Any]:
        """Download historical NVD CVE feeds (2002-2022)"""
        historical_results = {
            'years_downloaded': [],
            'files_downloaded': 0,
            'total_cves': 0,
            'errors': []
        }
        
        # Years to download (2002-2022 use feeds, 2023+ use API)
        years = list(range(2002, 2023))
        
        for year in years:
            try:
                logger.info(f"   📄 Downloading CVE data for year {year}...")
                
                # Download main feed
                feed_url = f"{self.nvd_feeds_base_url}/nvdcve-1.1-{year}.json.gz"
                local_path = self.data_downloads_dir / f"nvdcve-1.1-{year}.json"
                
                cve_count = await self.download_and_extract_feed(feed_url, local_path)
                
                if cve_count > 0:
                    historical_results['years_downloaded'].append(year)
                    historical_results['files_downloaded'] += 1
                    historical_results['total_cves'] += cve_count
                    logger.info(f"     ✅ Downloaded {cve_count:,} CVEs for {year}")
                else:
                    historical_results['errors'].append(f"No CVEs downloaded for year {year}")
                
                # Small delay between downloads
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"     ❌ Error downloading year {year}: {e}")
                historical_results['errors'].append(f"Year {year}: {str(e)}")
        
        return historical_results
    
    async def download_recent_via_api(self) -> Dict[str, Any]:
        """Download recent CVE data via NVD API 2.0 (2023-2024)"""
        api_results = {
            'years_downloaded': [],
            'files_downloaded': 0,
            'total_cves': 0,
            'errors': []
        }
        
        # Current year and last year
        current_year = datetime.now().year
        years = [current_year - 1, current_year]  # 2024, 2025
        
        for year in years:
            try:
                logger.info(f"   🔄 Downloading CVE data via API for year {year}...")
                
                # Download year data via API
                cve_count = await self.download_year_via_api(year)
                
                if cve_count > 0:
                    api_results['years_downloaded'].append(year)
                    api_results['files_downloaded'] += 1
                    api_results['total_cves'] += cve_count
                    logger.info(f"     ✅ Downloaded {cve_count:,} CVEs via API for {year}")
                else:
                    api_results['errors'].append(f"No CVEs downloaded via API for year {year}")
                
            except Exception as e:
                logger.error(f"     ❌ Error downloading year {year} via API: {e}")
                api_results['errors'].append(f"API Year {year}: {str(e)}")
        
        return api_results
    
    async def download_year_via_api(self, year: int) -> int:
        """Download all CVEs for a specific year via NVD API"""
        start_date = f"{year}-01-01T00:00:00.000"
        end_date = f"{year + 1}-01-01T00:00:00.000"
        
        all_cves = []
        start_index = 0
        results_per_page = 2000  # Maximum allowed by NVD API
        
        while True:
            try:
                # API request with pagination
                params = {
                    'pubStartDate': start_date,
                    'pubEndDate': end_date,
                    'startIndex': start_index,
                    'resultsPerPage': results_per_page
                }
                
                async with self.session.get(self.nvd_api_base_url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        vulnerabilities = data.get('vulnerabilities', [])
                        if not vulnerabilities:
                            break
                        
                        all_cves.extend(vulnerabilities)
                        
                        # Check if we have more data
                        total_results = data.get('totalResults', 0)
                        if start_index + len(vulnerabilities) >= total_results:
                            break
                        
                        start_index += len(vulnerabilities)
                        logger.info(f"     📊 Downloaded {len(all_cves):,}/{total_results:,} CVEs for {year}...")
                        
                        # Rate limiting
                        await asyncio.sleep(self.api_delay)
                    
                    elif response.status == 403:
                        logger.warning(f"⚠️ Rate limited for year {year}. Waiting longer...")
                        await asyncio.sleep(30)  # Wait 30 seconds on rate limit
                        continue
                    else:
                        logger.error(f"❌ API error for year {year}: HTTP {response.status}")
                        break
                        
            except Exception as e:
                logger.error(f"❌ API request error for year {year}: {e}")
                break
        
        # Save to file
        if all_cves:
            output_file = self.data_downloads_dir / f"nvdcve-api-{year}.json"
            with open(output_file, 'w') as f:
                json.dump({
                    'resultsPerPage': len(all_cves),
                    'startIndex': 0,
                    'totalResults': len(all_cves),
                    'format': 'NVD_CVE',
                    'version': '2.0',
                    'timestamp': datetime.utcnow().isoformat(),
                    'vulnerabilities': all_cves
                }, f, indent=2)
        
        return len(all_cves)
    
    async def download_modified_feeds(self) -> Dict[str, Any]:
        """Download modified CVE feeds for recent updates"""
        modified_results = {
            'feeds_downloaded': [],
            'files_downloaded': 0,
            'total_cves': 0,
            'errors': []
        }
        
        # Modified feeds to download
        modified_feeds = [
            'nvdcve-1.1-modified.json.gz',
            'nvdcve-1.1-recent.json.gz'
        ]
        
        for feed_name in modified_feeds:
            try:
                logger.info(f"   📄 Downloading modified feed: {feed_name}")
                
                feed_url = f"{self.nvd_feeds_base_url}/{feed_name}"
                local_name = feed_name.replace('.gz', '')
                local_path = self.data_downloads_dir / local_name
                
                cve_count = await self.download_and_extract_feed(feed_url, local_path)
                
                if cve_count > 0:
                    modified_results['feeds_downloaded'].append(feed_name)
                    modified_results['files_downloaded'] += 1
                    modified_results['total_cves'] += cve_count
                    logger.info(f"     ✅ Downloaded {cve_count:,} CVEs from {feed_name}")
                else:
                    modified_results['errors'].append(f"No CVEs in {feed_name}")
                
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"     ❌ Error downloading {feed_name}: {e}")
                modified_results['errors'].append(f"{feed_name}: {str(e)}")
        
        return modified_results
    
    async def download_and_extract_feed(self, url: str, local_path: Path) -> int:
        """Download and extract a gzipped NVD feed"""
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    # Download gzipped data
                    gzipped_data = await response.read()
                    
                    # Extract and parse
                    decompressed_data = gzip.decompress(gzipped_data)
                    json_data = json.loads(decompressed_data.decode('utf-8'))
                    
                    # Save extracted JSON
                    with open(local_path, 'w') as f:
                        json.dump(json_data, f, indent=2)
                    
                    # Count CVEs
                    cve_items = json_data.get('CVE_Items', [])
                    return len(cve_items)
                else:
                    logger.error(f"❌ Failed to download {url}: HTTP {response.status}")
                    return 0
                    
        except Exception as e:
            logger.error(f"❌ Error downloading/extracting {url}: {e}")
            return 0
    
    async def download_mitre_attack_data(self) -> Dict[str, Any]:
        """Download MITRE ATT&CK framework data"""
        mitre_results = {
            'file_downloaded': False,
            'files_downloaded': 0,
            'techniques_count': 0,
            'errors': []
        }
        
        try:
            logger.info("   🎯 Downloading MITRE ATT&CK framework data...")
            
            async with self.session.get(self.mitre_attack_url) as response:
                if response.status == 200:
                    attack_data = await response.json()
                    
                    # Save MITRE ATT&CK data
                    mitre_file = self.data_downloads_dir / "mitre_attack_enterprise.json"
                    with open(mitre_file, 'w') as f:
                        json.dump(attack_data, f, indent=2)
                    
                    # Count techniques
                    objects = attack_data.get('objects', [])
                    techniques = [obj for obj in objects if obj.get('type') == 'attack-pattern']
                    
                    mitre_results['file_downloaded'] = True
                    mitre_results['files_downloaded'] = 1
                    mitre_results['techniques_count'] = len(techniques)
                    
                    logger.info(f"     ✅ Downloaded {len(techniques):,} MITRE ATT&CK techniques")
                else:
                    error_msg = f"Failed to download MITRE ATT&CK data: HTTP {response.status}"
                    logger.error(f"     ❌ {error_msg}")
                    mitre_results['errors'].append(error_msg)
                    
        except Exception as e:
            error_msg = f"Error downloading MITRE ATT&CK data: {e}"
            logger.error(f"     ❌ {error_msg}")
            mitre_results['errors'].append(error_msg)
        
        return mitre_results
    
    async def save_download_metadata(self, results: Dict[str, Any]):
        """Save download metadata for tracking"""
        try:
            metadata_file = self.output_dir / "download_metadata.json"
            with open(metadata_file, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"💾 Saved download metadata to {metadata_file}")
        except Exception as e:
            logger.error(f"❌ Error saving download metadata: {e}")
    
    def log_download_summary(self, results: Dict[str, Any]):
        """Log a comprehensive download summary"""
        logger.info("=" * 60)
        logger.info("📊 NVD INITIAL DOWNLOAD SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Success: {results['success']}")
        logger.info(f"Duration: {results['duration_seconds']:.2f} seconds")
        logger.info(f"Total Files Downloaded: {results['total_files']}")
        logger.info(f"Total CVEs Downloaded: {results['total_cves']:,}")
        
        # Download breakdown
        for download_type, download_data in results['downloads'].items():
            if isinstance(download_data, dict):
                logger.info(f"\n{download_type.replace('_', ' ').title()}:")
                logger.info(f"  Files: {download_data.get('files_downloaded', 0)}")
                logger.info(f"  CVEs: {download_data.get('total_cves', 0):,}")
                if download_data.get('errors'):
                    logger.info(f"  Errors: {len(download_data['errors'])}")
        
        if results['errors']:
            logger.info(f"\nGlobal Errors: {len(results['errors'])}")
            for error in results['errors']:
                logger.info(f"  • {error}")
        
        logger.info("=" * 60)

async def main():
    """Main execution function"""
    try:
        async with NVDInitialDownloader() as downloader:
            result = await downloader.download_initial_data()
            if result['success']:
                print("✅ NVD initial download completed successfully!")
                print(f"Downloaded {result['total_cves']:,} CVEs across {result['total_files']} files")
            else:
                print(f"⚠️ NVD initial download completed with {len(result['errors'])} errors")
                sys.exit(1)
    except Exception as e:
        print(f"❌ NVD initial download failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())