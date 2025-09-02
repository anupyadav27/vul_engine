#!/usr/bin/env python3
"""
NVD Incremental Updater - Step 4

APPROACH:
1. Query existing 'cves' table to get latest CVE ID from NVD source
2. Download fresh NVD data (modified feeds + recent API data)
3. Find all CVEs > latest_cve_in_database = ONLY NEW CVEs
4. Process ONLY new/modified CVEs (massive efficiency gain)
5. Handle both new CVEs and updates to existing CVEs

DATABASE INTEGRATION:
- Queries existing 'cves' table for latest NVD CVE
- Uses source filtering to get source-specific latest CVE
- Only processes genuinely incremental CVEs
- Updates database with new/modified CVEs only

NVD-SPECIFIC FEATURES:
- Downloads NVD modified feeds (last 8 days)
- Downloads recent feed (last 8 days)
- Uses NVD API 2.0 for latest data
- Handles both CVE updates and new CVE additions
- Rate limiting for NVD API compliance
"""

import sys
import asyncio
import logging
import asyncpg
import json
import aiohttp
import gzip
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
import re

# Add vuln_db root to Python path
current_dir = Path(__file__).resolve().parent
vuln_db_root = current_dir.parent.parent.parent
sys.path.insert(0, str(vuln_db_root))

# Import consolidated configuration system
from config.schemas_and_config import get_database_connection, get_database_config

# Import the detector from step4a (create a simple one for NVD)
from dataclasses import dataclass
from enum import Enum

class ChangeType(Enum):
    NEW = "new"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"

@dataclass
class CVEComparisonResult:
    cve_id: str
    change_type: ChangeType
    reason: str = ""

class SimpleIncrementalDetector:
    """Simple incremental detector for NVD CVEs"""
    
    def __init__(self, source_name: str):
        self.source_name = source_name
    
    def find_incremental_changes(self, fresh_vulnerabilities: List[Dict], latest_processed_cve: Optional[str] = None) -> List[CVEComparisonResult]:
        """Find incremental changes by comparing CVE IDs"""
        results = []
        
        if not latest_processed_cve:
            # First run - return all as new
            for vuln in fresh_vulnerabilities:
                results.append(CVEComparisonResult(
                    cve_id=vuln.get('cve_id', ''),
                    change_type=ChangeType.NEW,
                    reason="First run - all CVEs are new"
                ))
            return results
        
        # Parse latest processed CVE for comparison
        latest_year, latest_number = self.parse_cve_id(latest_processed_cve)
        
        for vuln in fresh_vulnerabilities:
            cve_id = vuln.get('cve_id', '')
            if not cve_id:
                continue
            
            try:
                cve_year, cve_number = self.parse_cve_id(cve_id)
                
                # CVE is newer if:
                # 1. Year is greater, OR
                # 2. Same year but number is greater
                if cve_year > latest_year or (cve_year == latest_year and cve_number > latest_number):
                    results.append(CVEComparisonResult(
                        cve_id=cve_id,
                        change_type=ChangeType.NEW,
                        reason=f"CVE ID > {latest_processed_cve}"
                    ))
                elif cve_id == latest_processed_cve:
                    # Same CVE - check if it's been modified
                    results.append(CVEComparisonResult(
                        cve_id=cve_id,
                        change_type=ChangeType.MODIFIED,
                        reason="Potential modification in recent/modified feeds"
                    ))
                
            except Exception:
                # If we can't parse CVE ID, treat as new for safety
                results.append(CVEComparisonResult(
                    cve_id=cve_id,
                    change_type=ChangeType.NEW,
                    reason="Could not parse CVE ID for comparison"
                ))
        
        return results
    
    def parse_cve_id(self, cve_id: str) -> tuple:
        """Parse CVE ID into year and number for comparison"""
        match = re.match(r'CVE-(\d{4})-(\d+)', cve_id)
        if match:
            return int(match.group(1)), int(match.group(2))
        else:
            raise ValueError(f"Invalid CVE ID format: {cve_id}")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class NVDIncrementalUpdater:
    """NVD incremental updater with database integration and API support"""
    
    def __init__(self):
        self.output_dir = current_dir / "output"
        self.data_downloads_dir = self.output_dir / "data_downloads" 
        self.incremental_reports_dir = self.output_dir / "incremental_reports"
        
        # Files for tracking state (backup to database)
        self.latest_cve_file = current_dir / "nvd_latest_cve.txt"
        self.stats_file = current_dir / "nvd_update_stats.json"
        
        # Create directories
        self.data_downloads_dir.mkdir(parents=True, exist_ok=True)
        self.incremental_reports_dir.mkdir(parents=True, exist_ok=True)
        
        # NVD Data Sources
        self.nvd_feeds_base_url = "https://nvd.nist.gov/feeds/json/cve/1.1"
        self.nvd_api_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # NVD API Key for authentication
        self.nvd_api_key = "ba82db36-62b5-4651-98c3-30ad75ea6d85"
        
        # Rate limiting for NVD API (with API key: 50 requests per minute)
        self.api_delay = 1.2  # 1.2 seconds between API requests
        
        self.session = None
        self.db_conn = None
        self.detector = SimpleIncrementalDetector("nvd")
        
        # Database connection settings - will be loaded from consolidated config
        self.db_config = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        # Set up headers to avoid being blocked by NVD
        headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; NVD-Incremental-Updater/1.0; +https://github.com/your-repo)',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=300),
            connector=aiohttp.TCPConnector(limit=10),
            headers=headers
        )
        try:
            # Load database configuration from consolidated config system
            logger.info("🔧 Loading database configuration...")
            raw_config = get_database_config('development')  # Default to development
            
            # Convert username to user for asyncpg compatibility
            self.db_config = {
                'host': raw_config['host'],
                'port': raw_config['port'],
                'database': raw_config['database'],
                'user': raw_config['user'],  # Use 'user' directly from consolidated config
                'password': raw_config['password']
            }
            logger.info(f"✅ Loaded database config for host: {self.db_config['host']}")
            
            # Create database connection using converted config
            self.db_conn = await asyncpg.connect(**self.db_config)
            logger.info("✅ Connected to vulnerability database using consolidated config")
        except Exception as e:
            logger.warning(f"⚠️ Could not connect to database: {e}")
            self.db_conn = None
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
        if self.db_conn:
            await self.db_conn.close()
    
    async def get_latest_processed_cve_from_database(self) -> Optional[str]:
        """Get the latest CVE ID from the database for NVD source"""
        if not self.db_conn:
            logger.warning("⚠️ No database connection - cannot query latest CVE")
            return None
        
        try:
            # Query latest CVE ID for NVD source specifically
            query = """
            SELECT c.cve_id 
            FROM cves c
            JOIN vulnerability_sources vs ON c.source_id = vs.id
            WHERE vs.source_name = 'nvd'
            ORDER BY c.cve_id DESC 
            LIMIT 1
            """
            
            result = await self.db_conn.fetchval(query)
            if result:
                logger.info(f"📍 Latest NVD CVE in database: {result}")
                return result
            else:
                logger.info(f"🆕 No NVD CVEs found in database - this is the first run")
                return None
                
        except Exception as e:
            logger.error(f"❌ Error querying database for latest CVE: {e}")
            return None
    
    async def get_latest_processed_cve(self) -> Optional[str]:
        """Get the latest CVE ID we've already processed for NVD"""
        
        # First priority: Query the database
        latest_from_db = await self.get_latest_processed_cve_from_database()
        if latest_from_db:
            return latest_from_db
        
        # Fallback: Check tracking file
        try:
            if self.latest_cve_file.exists():
                with open(self.latest_cve_file, 'r') as f:
                    latest_cve = f.read().strip()
                    if latest_cve:
                        logger.info(f"📍 Latest NVD CVE from file: {latest_cve}")
                        return latest_cve
        except Exception as e:
            logger.error(f"❌ Error reading latest CVE file: {e}")
        
        # For true first run: return None to process recent data only
        logger.info(f"🆕 True first run detected - will process recent NVD data only")
        return None
    
    async def save_latest_processed_cve(self, cve_id: str):
        """Save the latest CVE ID we've processed for NVD"""
        try:
            with open(self.latest_cve_file, 'w') as f:
                f.write(cve_id)
            logger.info(f"💾 Saved latest NVD CVE to file: {cve_id}")
            
        except Exception as e:
            logger.error(f"❌ Error saving latest CVE: {e}")
    
    async def run_incremental_update(self) -> Dict[str, Any]:
        """Main incremental update method: Download → Parse → Upload"""
        logger.info("🚀 Starting NVD incremental vulnerability update...")
        start_time = datetime.now(timezone.utc)
        
        try:
            # Step 1: Get latest processed CVE ID from database
            latest_processed_cve = await self.get_latest_processed_cve()
            logger.info(f"🎯 Starting incremental update from: {latest_processed_cve or 'recent data only (first run)'}")
            
            # Step 2: Download fresh NVD incremental data
            logger.info("📥 Downloading NVD incremental data...")
            downloaded_files = await self.download_incremental_nvd_data()
            
            if not downloaded_files:
                logger.warning(f"⚠️ No new NVD data files downloaded")
                return {
                    'success': True,
                    'changes_detected': False,
                    'total_changes': 0,
                    'message': 'No new NVD data available for download'
                }
            
            logger.info(f"📊 Downloaded {len(downloaded_files)} new NVD data files")
            
            # Step 3: Parse downloaded data to find incremental CVEs
            logger.info(f"🔍 Parsing downloaded data for incremental CVEs...")
            incremental_cves = await self.parse_incremental_data(downloaded_files, latest_processed_cve)
            
            if not incremental_cves:
                logger.info(f"✅ No new CVEs found - NVD data is up to date!")
                logger.info(f"   Database already contains latest CVE: {latest_processed_cve}")
                return {
                    'success': True,
                    'changes_detected': False,
                    'total_changes': 0,
                    'message': 'No new CVEs found in downloaded data'
                }
            
            logger.info(f"📊 Found {len(incremental_cves)} incremental CVEs to process")
            
            # Step 4: Upload incremental CVEs to database
            logger.info(f"📤 Uploading incremental CVEs to database...")
            upload_result = await self.upload_incremental_cves(incremental_cves)
            
            # Step 5: Update latest processed CVE tracking
            if upload_result.get('latest_cve_found') and upload_result['latest_cve_found'] != latest_processed_cve:
                await self.save_latest_processed_cve(upload_result['latest_cve_found'])
            
            # Step 6: Generate and log summary
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            
            summary = {
                'source_name': 'nvd',
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration,
                'files_downloaded': len(downloaded_files),
                'incremental_cves_found': len(incremental_cves),
                'successfully_uploaded': upload_result.get('processed_count', 0),
                'failed_upload': upload_result.get('failed_count', 0),
                'previous_latest_cve': latest_processed_cve,
                'new_latest_cve': upload_result.get('latest_cve_found'),
                'status': 'success' if upload_result.get('failed_count', 0) == 0 else 'partial_success'
            }
            
            # Save update statistics
            await self.save_update_statistics(summary)
            
            # Log completion with efficiency metrics
            logger.info(f"✅ NVD incremental update completed")
            logger.info(f"   • Duration: {duration:.2f} seconds")
            logger.info(f"   • Files downloaded: {len(downloaded_files)}")
            logger.info(f"   • Incremental CVEs found: {len(incremental_cves):,}")
            logger.info(f"   • Successfully uploaded: {upload_result.get('processed_count', 0):,}")
            logger.info(f"   • Upload errors: {upload_result.get('failed_count', 0)}")
            
            return {
                'success': True,
                'changes_detected': len(incremental_cves) > 0,
                'total_changes': len(incremental_cves),
                'processed_cves': upload_result.get('processed_count', 0),
                'failed_cves': upload_result.get('failed_count', 0),
                'summary': summary
            }
            
        except Exception as e:
            logger.error(f"❌ Error during NVD incremental update: {e}")
            return {
                'success': False,
                'error': str(e),
                'changes_detected': False,
                'total_changes': 0
            }
    
    def is_cve_newer(self, cve_id1: str, cve_id2: str) -> bool:
        """Check if cve_id1 is newer than cve_id2"""
        try:
            year1, num1 = self.detector.parse_cve_id(cve_id1)
            year2, num2 = self.detector.parse_cve_id(cve_id2)
            return year1 > year2 or (year1 == year2 and num1 > num2)
        except:
            return False
    
    async def download_incremental_nvd_data(self) -> List[str]:
        """Download incremental NVD data using NVD API 2.0 with authentication"""
        downloaded_files = []
        
        try:
            # Use NVD API 2.0 to get recent CVEs (last 8 days)
            recent_file = self.data_downloads_dir / "nvd_recent_cves.json"
            if await self.download_recent_cves_via_api(recent_file):
                downloaded_files.append(str(recent_file))
                logger.info(f"✅ Downloaded recent CVEs via API: {recent_file.name}")
            

            

            
            logger.info(f"📥 Total files downloaded: {len(downloaded_files)}")
            return downloaded_files
            
        except Exception as e:
            logger.error(f"❌ Error downloading incremental NVD data: {e}")
            return downloaded_files
    
    async def download_file(self, url: str, local_path: Path) -> bool:
        """Download a single file from URL to local path"""
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.read()
                    
                    # Handle gzipped content
                    if url.endswith('.gz'):
                        import gzip
                        content = gzip.decompress(content)
                    
                    with open(local_path, 'wb') as f:
                        f.write(content)
                    
                    return True
                else:
                    logger.warning(f"⚠️ Failed to download {url}: HTTP {response.status}")
                    return False
                    
        except Exception as e:
            logger.error(f"❌ Error downloading {url}: {e}")
            return False
    
    async def download_recent_cves_via_api(self, local_path: Path) -> bool:
        """Download recent CVEs using NVD API 2.0 with authentication"""
        try:
            # Get CVEs from the last 8 days
            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=8)
            
            # NVD API 2.0 expects dates in ISO 8601 format without timezone offset
            url = f"{self.nvd_api_base_url}?pubStartDate={start_date.strftime('%Y-%m-%dT%H:%M:%S')}&pubEndDate={end_date.strftime('%Y-%m-%dT%H:%M:%S')}&resultsPerPage=2000"
            
            logger.info(f"🔗 API URL: {url}")
            headers = {'apiKey': self.nvd_api_key}
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    with open(local_path, 'w') as f:
                        json.dump(data, f, indent=2)
                    logger.info(f"✅ Downloaded {data.get('totalResults', 0)} recent CVEs via API")
                    return True
                else:
                    logger.warning(f"⚠️ Failed to download recent CVEs: HTTP {response.status}")
                    return False
                    
        except Exception as e:
            logger.error(f"❌ Error downloading recent CVEs via API: {e}")
            return False
    
    async def download_modified_cves_via_api(self, local_path: Path) -> bool:
        """Download modified CVEs using NVD API 2.0 with authentication"""
        try:
            # Get CVEs modified in the last 8 days
            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=8)
            
            # NVD API 2.0 expects dates in ISO 8601 format without timezone offset
            url = f"{self.nvd_api_base_url}?lastModStartDate={start_date.strftime('%Y-%m-%dT%H:%M:%S')}&lastModEndDate={end_date.strftime('%Y-%m-%dT%H:%M:%S')}&resultsPerPage=2000"
            
            logger.info(f"🔗 API URL: {url}")
            headers = {'apiKey': self.nvd_api_key}
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    with open(local_path, 'w') as f:
                        json.dump(data, f, indent=2)
                    logger.info(f"✅ Downloaded {data.get('totalResults', 0)} modified CVEs via API")
                    return True
                else:
                    logger.warning(f"⚠️ Failed to download modified CVEs: HTTP {response.status}")
                    return False
                    
        except Exception as e:
            logger.error(f"❌ Error downloading modified CVEs via API: {e}")
            return False
    
    async def parse_incremental_data(self, downloaded_files: List[str], latest_processed_cve: Optional[str]) -> List[Dict]:
        """Parse downloaded data to find incremental CVEs"""
        incremental_cves = []
        
        try:
            for file_path in downloaded_files:
                logger.info(f"🔍 Parsing file: {Path(file_path).name}")
                
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                # Handle both API 2.0 format and legacy feed format
                if 'vulnerabilities' in data:
                    # API 2.0 format
                    cves = data.get('vulnerabilities', [])
                    logger.info(f"   Found {len(cves):,} CVEs in {Path(file_path).name} (API 2.0)")
                    
                    for cve_item in cves:
                        cve_id = cve_item.get('cve', {}).get('id')
                        if not cve_id:
                            continue
                        
                        # Check if this CVE is newer than what we have
                        if self.is_cve_newer_than_latest(cve_id, latest_processed_cve):
                            # Parse the CVE data into our standardized format
                            standardized_cve = self.standardize_cve_data_api2(cve_item)
                            incremental_cves.append(standardized_cve)
                else:
                    # Legacy feed format
                    cves = data.get('CVE_Items', [])
                    logger.info(f"   Found {len(cves):,} CVEs in {Path(file_path).name} (legacy feed)")
                    
                    for cve_item in cves:
                        cve_id = cve_item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
                        if not cve_id:
                            continue
                        
                        # Check if this CVE is newer than what we have
                        if self.is_cve_newer_than_latest(cve_id, latest_processed_cve):
                            # Parse the CVE data into our standardized format
                            standardized_cve = self.standardize_cve_data(cve_item)
                            incremental_cves.append(standardized_cve)
                
                logger.info(f"   Found {len([c for c in incremental_cves if c.get('source_file') == Path(file_path).name]):,} incremental CVEs")
            
            logger.info(f"📊 Total incremental CVEs found: {len(incremental_cves):,}")
            return incremental_cves
            
        except Exception as e:
            logger.error(f"❌ Error parsing incremental data: {e}")
            return incremental_cves
    
    def is_cve_newer_than_latest(self, cve_id: str, latest_processed_cve: Optional[str]) -> bool:
        """Check if a CVE is newer than the latest processed CVE"""
        if not latest_processed_cve:
            return True  # First run - all CVEs are new
        
        try:
            year1, num1 = self.detector.parse_cve_id(cve_id)
            year2, num2 = self.detector.parse_cve_id(latest_processed_cve)
            return year1 > year2 or (year1 == year2 and num1 > num2)
        except:
            return True  # If we can't parse, treat as new for safety
    
    def standardize_cve_data(self, cve_item: Dict) -> Dict:
        """Convert NVD CVE item to our standardized format"""
        try:
            cve_data = cve_item.get('cve', {})
            cve_id = cve_data.get('CVE_data_meta', {}).get('ID', '')
            
            # Extract description
            descriptions = cve_data.get('description', {}).get('description_data', [])
            description = descriptions[0].get('value', '') if descriptions else ''
            
            # Extract CVSS scores
            impact = cve_item.get('impact', {})
            cvss_v3 = impact.get('baseMetricV3', {}).get('cvssV3', {})
            cvss_v2 = impact.get('baseMetricV2', {}).get('cvssV2', {})
            
            # Extract CPE matches
            configurations = cve_item.get('configurations', {})
            cpe_matches = []
            for config in configurations.get('nodes', []):
                for cpe_match in config.get('cpeMatch', []):
                    cpe_matches.append({
                        'cpe23_uri': cpe_match.get('cpe23Uri', ''),
                        'vulnerable': cpe_match.get('vulnerable', True)
                    })
            
            # Extract references
            references = cve_data.get('references', {}).get('reference_data', [])
            reference_urls = [ref.get('url', '') for ref in references if ref.get('url')]
            
            standardized = {
                'cve_id': cve_id,
                'description': description,
                'published_date': cve_item.get('publishedDate', ''),
                'modified_date': cve_item.get('lastModifiedDate', ''),
                'cvss_v3_score': cvss_v3.get('baseScore'),
                'cvss_v3_severity': cvss_v3.get('baseSeverity'),
                'cvss_v2_score': cvss_v2.get('baseScore'),
                'cvss_v2_severity': cvss_v2.get('baseSeverity'),
                'cpe_matches': cpe_matches,
                'reference_urls': reference_urls,
                'source_file': 'incremental_update',
                'nvd_raw_data': cve_item
            }
            
            return standardized
            
        except Exception as e:
            logger.error(f"❌ Error standardizing CVE data: {e}")
            return {'cve_id': 'unknown', 'error': str(e)}
    
    def standardize_cve_data_api2(self, cve_item: Dict) -> Dict:
        """Convert NVD API 2.0 CVE item to our standardized format"""
        try:
            cve_data = cve_item.get('cve', {})
            cve_id = cve_data.get('id', '')
            
            # Extract description
            descriptions = cve_data.get('descriptions', [])
            description = descriptions[0].get('value', '') if descriptions else ''
            
            # Extract CVSS scores
            metrics = cve_data.get('metrics', {})
            cvss_v3 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}) if metrics.get('cvssMetricV31') else metrics.get('cvssMetricV30', [{}])[0].get('cvssData', {}) if metrics.get('cvssMetricV30') else {}
            cvss_v2 = metrics.get('cvssMetricV2', [{}])[0].get('cvssData', {}) if metrics.get('cvssMetricV2') else {}
            
            # Extract CPE matches
            configurations = cve_data.get('configurations', [])
            cpe_matches = []
            for config in configurations:
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        cpe_matches.append({
                            'cpe23_uri': cpe_match.get('criteria', ''),
                            'vulnerable': cpe_match.get('vulnerable', True),
                            'version_start_including': cpe_match.get('versionStartIncluding'),
                            'version_start_excluding': cpe_match.get('versionStartExcluding'),
                            'version_end_including': cpe_match.get('versionEndIncluding'),
                            'version_end_excluding': cpe_match.get('versionEndExcluding')
                        })
            
            # Extract references
            references = cve_data.get('references', [])
            reference_urls = [ref.get('url', '') for ref in references if ref.get('url')]
            
            standardized = {
                'cve_id': cve_id,
                'description': description,
                'published_date': cve_data.get('published', ''),
                'modified_date': cve_data.get('lastModified', ''),
                'cvss_v3_score': cvss_v3.get('baseScore'),
                'cvss_v3_severity': cvss_v3.get('baseSeverity'),
                'cvss_v2_score': cvss_v2.get('baseScore'),
                'cvss_v2_severity': cvss_v2.get('baseSeverity'),
                'cpe_matches': cpe_matches,
                'reference_urls': reference_urls,
                'source_file': 'incremental_update',
                'nvd_raw_data': cve_item
            }
            
            return standardized
            
        except Exception as e:
            logger.error(f"❌ Error standardizing API 2.0 CVE data: {e}")
            return {'cve_id': 'unknown', 'error': str(e)}
    
    async def upload_incremental_cves(self, incremental_cves: List[Dict]) -> Dict[str, Any]:
        """Upload incremental CVEs to the database using existing uploader logic"""
        try:
            # Import the existing uploader to reuse its logic
            from step3_nvd_uploader import NVDDatabaseUploader
            
            processed_count = 0
            failed_count = 0
            latest_cve_found = None
            
            # Create a temporary uploader instance
            async with NVDDatabaseUploader() as uploader:
                # Ensure NVD source exists
                await uploader.ensure_nvd_source_exists()
                
                logger.info(f"📤 Uploading {len(incremental_cves):,} incremental CVEs...")
                
                for cve_data in incremental_cves:
                    try:
                        # Process each CVE individually
                        async with uploader.db_conn.transaction():
                            await uploader.process_single_cve(cve_data)
                            processed_count += 1
                            
                            # Track latest CVE using our own method
                            if not latest_cve_found or self.is_cve_newer_than_latest(cve_data['cve_id'], latest_cve_found):
                                latest_cve_found = cve_data['cve_id']
                            
                            # Log progress every 100 CVEs
                            if processed_count % 100 == 0:
                                logger.info(f"   ✅ Uploaded {processed_count}/{len(incremental_cves)} CVEs...")
                        
                    except Exception as e:
                        logger.error(f"❌ Error uploading CVE {cve_data.get('cve_id', 'unknown')}: {e}")
                        failed_count += 1
                        continue
            
            logger.info(f"📤 Upload completed: {processed_count:,} successful, {failed_count} failed")
            
            return {
                'processed_count': processed_count,
                'failed_count': failed_count,
                'latest_cve_found': latest_cve_found
            }
            
        except Exception as e:
            logger.error(f"❌ Error during incremental CVE upload: {e}")
            return {
                'processed_count': 0,
                'failed_count': len(incremental_cves),
                'latest_cve_found': None
            }
        
        try:
            # Source 1: Modified feed (last 8 days of modifications)
            logger.info("   📄 Downloading NVD modified feed...")
            modified_vulns = await self.download_nvd_feed("nvdcve-1.1-modified.json.gz")
            all_vulnerabilities.extend(modified_vulns)
            logger.info(f"     ✅ Got {len(modified_vulns):,} CVEs from modified feed")
            
            # Source 2: Recent feed (last 8 days of new CVEs)
            logger.info("   📄 Downloading NVD recent feed...")
            recent_vulns = await self.download_nvd_feed("nvdcve-1.1-recent.json.gz")
            all_vulnerabilities.extend(recent_vulns)
            logger.info(f"     ✅ Got {len(recent_vulns):,} CVEs from recent feed")
            
            # Source 3: API data for last 7 days (most up-to-date)
            logger.info("   🔄 Downloading latest CVEs via NVD API...")
            api_vulns = await self.download_recent_via_api(days=7)
            all_vulnerabilities.extend(api_vulns)
            logger.info(f"     ✅ Got {len(api_vulns):,} CVEs from NVD API")
            
            # Remove duplicates by CVE ID
            unique_vulnerabilities = self.deduplicate_cves(all_vulnerabilities)
            logger.info(f"📊 Total unique CVEs after deduplication: {len(unique_vulnerabilities):,}")
            
            return unique_vulnerabilities
            
        except Exception as e:
            logger.error(f"❌ Error downloading incremental NVD data: {e}")
            return []
    
    async def download_nvd_feed(self, feed_name: str) -> List[Dict]:
        """Download and parse an NVD feed"""
        try:
            feed_url = f"{self.nvd_feeds_base_url}/{feed_name}"
            
            async with self.session.get(feed_url) as response:
                if response.status == 200:
                    # Download and decompress
                    gzipped_data = await response.read()
                    decompressed_data = gzip.decompress(gzipped_data)
                    json_data = json.loads(decompressed_data.decode('utf-8'))
                    
                    # Convert NVD feed format to our standardized format
                    vulnerabilities = []
                    for item in json_data.get('CVE_Items', []):
                        vuln = self.convert_nvd_feed_item_to_standard_format(item)
                        if vuln:
                            vulnerabilities.append(vuln)
                    
                    return vulnerabilities
                else:
                    logger.error(f"❌ Failed to download {feed_name}: HTTP {response.status}")
                    return []
                    
        except Exception as e:
            logger.error(f"❌ Error downloading NVD feed {feed_name}: {e}")
            return []
    
    async def download_recent_via_api(self, days: int = 7) -> List[Dict]:
        """Download recent CVEs via NVD API 2.0"""
        try:
            # Calculate date range
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
            start_date_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
            end_date_str = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
            
            all_cves = []
            start_index = 0
            results_per_page = 2000
            
            while True:
                params = {
                    'lastModStartDate': start_date_str,
                    'lastModEndDate': end_date_str,
                    'startIndex': start_index,
                    'resultsPerPage': results_per_page
                }
                
                async with self.session.get(self.nvd_api_base_url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        vulnerabilities = data.get('vulnerabilities', [])
                        
                        if not vulnerabilities:
                            break
                        
                        # Convert API format to our standardized format
                        for vuln_data in vulnerabilities:
                            vuln = self.convert_nvd_api_item_to_standard_format(vuln_data)
                            if vuln:
                                all_cves.append(vuln)
                        
                        # Check if we have more data
                        total_results = data.get('totalResults', 0)
                        if start_index + len(vulnerabilities) >= total_results:
                            break
                        
                        start_index += len(vulnerabilities)
                        
                        # Rate limiting
                        await asyncio.sleep(self.api_delay)
                    
                    elif response.status == 403:
                        logger.warning(f"⚠️ Rate limited. Waiting longer...")
                        await asyncio.sleep(30)
                        continue
                    else:
                        logger.error(f"❌ API error: HTTP {response.status}")
                        break
            
            return all_cves
            
        except Exception as e:
            logger.error(f"❌ Error downloading recent CVEs via API: {e}")
            return []
    
    def convert_nvd_feed_item_to_standard_format(self, item: Dict) -> Optional[Dict]:
        """Convert NVD feed item to standardized vulnerability format"""
        try:
            cve_data = item.get('cve', {})
            cve_id = cve_data.get('CVE_data_meta', {}).get('ID', '')
            
            if not cve_id:
                return None
            
            # Extract description
            description_data = cve_data.get('description', {}).get('description_data', [])
            description = ''
            for desc in description_data:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            return {
                'cve_id': cve_id,
                'description': description,
                'published_date': item.get('publishedDate', ''),
                'last_modified_date': item.get('lastModifiedDate', ''),
                'source': 'nvd',
                'source_url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                'nvd_raw_data': item
            }
            
        except Exception as e:
            logger.error(f"❌ Error converting NVD feed item: {e}")
            return None
    
    def convert_nvd_api_item_to_standard_format(self, vuln_data: Dict) -> Optional[Dict]:
        """Convert NVD API 2.0 item to standardized vulnerability format"""
        try:
            cve_data = vuln_data.get('cve', {})
            cve_id = cve_data.get('id', '')
            
            if not cve_id:
                return None
            
            # Extract description
            descriptions = cve_data.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            return {
                'cve_id': cve_id,
                'description': description,
                'published_date': cve_data.get('published', ''),
                'last_modified_date': cve_data.get('lastModified', ''),
                'source': 'nvd',
                'source_url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                'nvd_raw_data': vuln_data
            }
            
        except Exception as e:
            logger.error(f"❌ Error converting NVD API item: {e}")
            return None
    
    def deduplicate_cves(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Remove duplicate CVEs, keeping the most recent version"""
        cve_dict = {}
        
        for vuln in vulnerabilities:
            cve_id = vuln.get('cve_id')
            if not cve_id:
                continue
            
            # Keep the CVE with the most recent last_modified_date
            if cve_id not in cve_dict:
                cve_dict[cve_id] = vuln
            else:
                existing_modified = cve_dict[cve_id].get('last_modified_date', '')
                new_modified = vuln.get('last_modified_date', '')
                
                # Simple string comparison works for ISO datetime strings
                if new_modified > existing_modified:
                    cve_dict[cve_id] = vuln
        
        return list(cve_dict.values())
    
    async def insert_or_update_vulnerability(self, vulnerability: Dict):
        """Insert or update a vulnerability in the database"""
        if not self.db_conn:
            logger.warning(f"💾 Would insert/update CVE: {vulnerability['cve_id']} (DB not connected)")
            return
        
        try:
            # Get NVD source ID
            source_id = await self.db_conn.fetchval(
                "SELECT id FROM vulnerability_sources WHERE source_name = 'nvd'"
            )
            
            if not source_id:
                raise Exception("NVD source not found in database")
            
            # Parse dates
            try:
                published_date = datetime.fromisoformat(vulnerability['published_date'].replace('Z', '+00:00'))
            except:
                published_date = datetime.now(timezone.utc)
            
            try:
                last_modified_date = datetime.fromisoformat(vulnerability['last_modified_date'].replace('Z', '+00:00'))
            except:
                last_modified_date = datetime.now(timezone.utc)
            
            # Insert or update vulnerability in cves table
            query = """
            INSERT INTO cves (
                cve_id, source_id, description, 
                published_date, last_modified_date,
                source_specific_data, source_url,
                created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9
            )
            ON CONFLICT (cve_id) DO UPDATE SET
                description = CASE 
                    WHEN EXCLUDED.source_id = cves.source_id THEN EXCLUDED.description
                    ELSE cves.description 
                END,
                last_modified_date = CASE 
                    WHEN EXCLUDED.source_id = cves.source_id THEN EXCLUDED.last_modified_date
                    ELSE cves.last_modified_date 
                END,
                source_specific_data = CASE 
                    WHEN EXCLUDED.source_id = cves.source_id THEN EXCLUDED.source_specific_data
                    ELSE cves.source_specific_data 
                END,
                source_url = CASE 
                    WHEN EXCLUDED.source_id = cves.source_id THEN EXCLUDED.source_url
                    ELSE cves.source_url 
                END,
                updated_at = EXCLUDED.updated_at
            """
            
            await self.db_conn.execute(
                query,
                vulnerability['cve_id'],
                source_id,
                vulnerability['description'],
                published_date,
                last_modified_date,
                json.dumps(vulnerability['nvd_raw_data']),
                vulnerability['source_url'],
                datetime.now(timezone.utc),
                datetime.now(timezone.utc)
            )
            
        except Exception as e:
            logger.error(f"❌ Database error for CVE {vulnerability['cve_id']}: {e}")
            raise
    
    async def save_update_statistics(self, stats: Dict):
        """Save update statistics for monitoring and debugging"""
        try:
            with open(self.stats_file, 'w') as f:
                json.dump(stats, f, indent=2)
        except Exception as e:
            logger.error(f"❌ Error saving update statistics: {e}")
    
    def reset_to_full_scan(self):
        """Reset incremental state to force full historical scan on next update"""
        try:
            if self.latest_cve_file.exists():
                self.latest_cve_file.unlink()
            logger.info(f"🔄 Reset to full scan mode - next run will process all historical CVEs")
        except Exception as e:
            logger.error(f"❌ Error resetting incremental state: {e}")

async def main():
    """Main execution function"""
    try:
        async with NVDIncrementalUpdater() as updater:
            result = await updater.run_incremental_update()
            if result['success']:
                print("✅ NVD incremental update completed successfully!")
                if result.get('changes_detected'):
                    print(f"Processed {result.get('processed_cves', 0)} incremental CVEs")
                    print(f"Files downloaded: {result.get('summary', {}).get('files_downloaded', 0)}")
                    print(f"CVEs found: {result.get('total_changes', 0)}")
                    print(f"Errors: {result.get('failed_cves', 0)}")
                else:
                    print("No new CVEs found - database is up to date")
            else:
                print(f"❌ NVD incremental update failed: {result.get('error', 'Unknown error')}")
                sys.exit(1)
    except Exception as e:
        print(f"❌ NVD incremental update failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())