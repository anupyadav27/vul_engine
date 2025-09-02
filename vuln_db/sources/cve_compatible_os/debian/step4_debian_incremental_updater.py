#!/usr/bin/env python3
"""
Debian Incremental Updater with Database-Integrated CVE ID Detection

FIXED APPROACH:
1. Query existing 'cves' table to get latest CVE ID from Debian source
2. Download fresh Debian Security Tracker data  
3. Flatten nested package structure to CVE list
4. Find all CVEs > latest_cve_in_database = ONLY NEW CVEs
5. Process ONLY new CVEs (massive efficiency gain)

DATABASE INTEGRATION:
- Queries existing 'cves' table for latest Debian CVE
- Uses source filtering to get source-specific latest CVE
- Only processes genuinely incremental CVEs
- Updates database with new CVEs only
"""

import sys
import asyncio
import logging
import asyncpg
import json
import aiohttp
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
import re

# Add vuln_db root to Python path
current_dir = Path(__file__).resolve().parent
vuln_db_root = current_dir.parent.parent.parent
sys.path.insert(0, str(vuln_db_root))

from step4a_incremental_cve_detector import SimpleIncrementalDetector, CVEComparisonResult, ChangeType

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DebianIncrementalUpdater:
    """Debian incremental updater with proper database integration"""
    
    def __init__(self, base_url="https://security-tracker.debian.org/tracker/data/json"):
        self.base_url = base_url
        self.output_dir = current_dir / "output"
        self.data_downloads_dir = self.output_dir / "data_downloads"
        self.incremental_reports_dir = self.output_dir / "incremental_reports"
        
        # Files for tracking state (backup to database)
        self.latest_cve_file = current_dir / "debian_latest_cve.txt"
        self.stats_file = current_dir / "debian_update_stats.json"
        
        # Create directories
        self.data_downloads_dir.mkdir(parents=True, exist_ok=True)
        self.incremental_reports_dir.mkdir(parents=True, exist_ok=True)
        
        self.session = None
        self.db_conn = None
        self.detector = SimpleIncrementalDetector("debian")
        
        # Database connection settings
        self.db_config = {
            'host': 'localhost',
            'port': 5432,
            'database': 'vulnerability_db',
            'user': 'vuln_user',
            'password': 'vuln_secure_pass'
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        try:
            self.db_conn = await asyncpg.connect(**self.db_config)
            logger.info("✅ Connected to vulnerability database")
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
        """Get the latest CVE ID from the database for Debian source"""
        if not self.db_conn:
            logger.warning("⚠️ No database connection - cannot query latest CVE")
            return None
        
        try:
            # First, ensure Debian source exists in vulnerability_sources table
            await self.ensure_debian_source_exists()
            
            # Query latest CVE for Debian source specifically
            query = """
            SELECT c.cve_id 
            FROM cves c
            JOIN vulnerability_sources vs ON c.source_id = vs.id
            WHERE vs.source_name = 'debian_security_tracker'
            ORDER BY c.cve_id DESC 
            LIMIT 1
            """
            
            result = await self.db_conn.fetchval(query)
            if result:
                logger.info(f"📍 Latest Debian CVE in database: {result}")
                return result
            else:
                logger.info(f"🆕 No Debian CVEs found in database - this is the first run")
                return None
                
        except Exception as e:
            logger.error(f"❌ Error querying database for latest CVE: {e}")
            return None
    
    async def ensure_debian_source_exists(self):
        """Ensure Debian source is registered in vulnerability_sources table"""
        try:
            # Check if Debian source exists
            check_query = "SELECT id FROM vulnerability_sources WHERE source_name = 'debian_security_tracker'"
            source_id = await self.db_conn.fetchval(check_query)
            
            if not source_id:
                # Insert Debian source
                insert_query = """
                INSERT INTO vulnerability_sources (
                    source_name, category, display_name, url, status, priority,
                    enhancement_needed, engine_type, vulnerability_engine_priority
                ) VALUES (
                    'debian_security_tracker', 
                    'linux_distro',
                    'Debian Security Tracker',
                    'https://security-tracker.debian.org',
                    'active',
                    7,
                    false,
                    'existing',
                    'high'
                ) RETURNING id
                """
                source_id = await self.db_conn.fetchval(insert_query)
                logger.info(f"✅ Created Debian source entry with ID: {source_id}")
            else:
                logger.info(f"✅ Debian source exists with ID: {source_id}")
                
            return source_id
            
        except Exception as e:
            logger.error(f"❌ Error ensuring Debian source exists: {e}")
            raise
    
    async def get_latest_processed_cve(self) -> Optional[str]:
        """Get the latest CVE ID we've already processed for Debian"""
        
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
                        logger.info(f"📍 Latest Debian CVE from file: {latest_cve}")
                        return latest_cve
        except Exception as e:
            logger.error(f"❌ Error reading latest CVE file: {e}")
        
        # For true first run: return None to process all available CVEs
        # (but with smart filtering in the detection logic)
        logger.info(f"🆕 True first run detected - will process with smart incremental logic")
        return None
    
    async def save_latest_processed_cve(self, cve_id: str):
        """Save the latest CVE ID we've processed for Debian"""
        try:
            with open(self.latest_cve_file, 'w') as f:
                f.write(cve_id)
            logger.info(f"💾 Saved latest Debian CVE to file: {cve_id}")
            
        except Exception as e:
            logger.error(f"❌ Error saving latest CVE: {e}")
    
    async def run_incremental_update(self) -> Dict[str, Any]:
        """Main incremental update method using CVE ID-based detection"""
        logger.info("🚀 Starting Debian incremental vulnerability update...")
        start_time = datetime.utcnow()
        
        try:
            # Step 1: Get latest processed CVE ID from database
            latest_processed_cve = await self.get_latest_processed_cve()
            logger.info(f"🎯 Starting incremental update from: {latest_processed_cve or 'beginning (first run)'}")
            
            # Step 2: Download fresh Debian data
            logger.info("📥 Downloading latest Debian Security Tracker data...")
            fresh_debian_data = await self.download_security_data()
            
            if not fresh_debian_data:
                logger.error("❌ Failed to download security data")
                return {
                    'success': False,
                    'error': 'Failed to download security data',
                    'changes_detected': False,
                    'total_changes': 0
                }
            
            # Step 3: Flatten Debian data to CVE list
            fresh_vulnerabilities = self.flatten_debian_data_to_cve_list(fresh_debian_data)
            
            if not fresh_vulnerabilities:
                logger.warning(f"⚠️ No vulnerabilities found in Debian data")
                return {
                    'success': True,
                    'changes_detected': False,
                    'total_changes': 0,
                    'message': 'No vulnerabilities found in Debian data'
                }
            
            logger.info(f"📊 Loaded {len(fresh_vulnerabilities):,} total vulnerabilities from Debian")
            
            # Step 4: Find incremental changes using CVE ID comparison
            logger.info(f"🔍 Detecting incremental changes...")
            incremental_results = self.detector.find_incremental_changes(
                fresh_vulnerabilities, latest_processed_cve
            )
            
            # Step 5: Process ONLY new vulnerabilities  
            processed_count = 0
            failed_count = 0
            latest_cve_found = latest_processed_cve
            
            new_results = [r for r in incremental_results if r.change_type == ChangeType.NEW]
            
            if new_results:
                logger.info(f"🔄 Processing {len(new_results)} NEW CVEs (skipping {len(fresh_vulnerabilities) - len(new_results):,} existing)...")
                
                for result in new_results:
                    try:
                        # Find the vulnerability data for this CVE
                        vuln_data = next((v for v in fresh_vulnerabilities if v.get('cve_id') == result.cve_id), None)
                        
                        if vuln_data:
                            # Insert/update in database
                            await self.insert_or_update_vulnerability(vuln_data)
                            
                            processed_count += 1
                            latest_cve_found = result.cve_id  # Track latest processed
                            
                            # Log progress every 100 CVEs
                            if processed_count % 100 == 0:
                                logger.info(f"   ✅ Processed {processed_count}/{len(new_results)} CVEs...")
                        
                    except Exception as e:
                        logger.error(f"❌ Error processing CVE {result.cve_id}: {e}")
                        failed_count += 1
            else:
                logger.info(f"✅ No new CVEs found - Debian data is up to date!")
                logger.info(f"   Database already contains latest CVE: {latest_processed_cve}")
            
            # Step 6: Update latest processed CVE tracking
            if latest_cve_found and latest_cve_found != latest_processed_cve:
                await self.save_latest_processed_cve(latest_cve_found)
            
            # Step 7: Generate and log summary
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            
            summary = {
                'source_name': 'debian',
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration,
                'total_packages': len(fresh_debian_data.get('data', {})),
                'total_fresh_vulnerabilities': len(fresh_vulnerabilities),
                'new_cves_found': len(new_results),
                'successfully_processed': processed_count,
                'failed_processing': failed_count,
                'previous_latest_cve': latest_processed_cve,
                'new_latest_cve': latest_cve_found,
                'status': 'success' if failed_count == 0 else 'partial_success',
                'efficiency_gained': f"{len(fresh_vulnerabilities) - len(new_results):,} CVEs skipped"
            }
            
            # Save update statistics
            await self.save_update_statistics(summary)
            
            # Log completion with efficiency metrics
            logger.info(f"✅ Debian incremental update completed")
            logger.info(f"   • Duration: {duration:.2f} seconds")
            logger.info(f"   • Packages: {summary['total_packages']:,}")
            logger.info(f"   • Total CVEs available: {len(fresh_vulnerabilities):,}")
            logger.info(f"   • NEW CVEs processed: {processed_count:,}")
            logger.info(f"   • EXISTING CVEs skipped: {len(fresh_vulnerabilities) - len(new_results):,}")
            logger.info(f"   • Failed: {failed_count}")
            if len(fresh_vulnerabilities) > 0:
                logger.info(f"   • Efficiency: {((len(fresh_vulnerabilities) - len(new_results))/len(fresh_vulnerabilities)*100):.1f}% skipped")
            logger.info(f"   • Latest CVE: {latest_cve_found}")
            
            # Return comprehensive result for orchestrator
            return {
                'success': True,
                'changes_detected': len(new_results) > 0,
                'total_changes': len(new_results),
                'update_stats': summary,
                'processed_cves': processed_count,
                'failed_cves': failed_count,
                'skipped_cves': len(fresh_vulnerabilities) - len(new_results),
                'total_available_cves': len(fresh_vulnerabilities)
            }
            
        except Exception as e:
            logger.error(f"❌ Debian incremental update failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'changes_detected': False,
                'total_changes': 0
            }
    
    def flatten_debian_data_to_cve_list(self, debian_data: Dict) -> List[Dict]:
        """
        Convert Debian nested package structure to flat CVE list
        
        Transforms:
        {
          "package_name": {
            "CVE-ID": {cve_data}
          }
        }
        
        To:
        [
          {
            "cve_id": "CVE-ID",
            "affected_packages": ["package_name"],
            "debian_data": {cve_data},
            ...
          }
        ]
        """
        logger.info(f"🔄 Flattening Debian package structure to CVE list...")
        
        vulnerabilities = []
        cve_to_packages = {}  # Track which packages are affected by each CVE
        
        # First pass: collect all CVEs and their package associations
        for package_name, package_cves in debian_data.items():
            for cve_id, cve_data in package_cves.items():
                if cve_id.startswith(('CVE-', 'TEMP-')):
                    if cve_id not in cve_to_packages:
                        cve_to_packages[cve_id] = {
                            'packages': [],
                            'cve_data': cve_data  # Use first occurrence data
                        }
                    cve_to_packages[cve_id]['packages'].append(package_name)
        
        # Second pass: create standardized vulnerability objects
        for cve_id, cve_info in cve_to_packages.items():
            cve_data = cve_info['cve_data']
            affected_packages = cve_info['packages']
            
            # Create standardized vulnerability
            vulnerability = {
                'cve_id': cve_id,
                'description': cve_data.get('description', ''),
                'source': 'debian_security_tracker',
                'source_url': f'https://security-tracker.debian.org/tracker/{cve_id}',
                'affected_packages': affected_packages,
                'package_count': len(affected_packages),
                'debian_releases': cve_data.get('releases', {}),
                'debian_scope': cve_data.get('scope', ''),
                'debian_bug': cve_data.get('debianbug', ''),
                'debian_nodsa': cve_data.get('nodsa', ''),
                'debian_nodsa_reason': cve_data.get('nodsa_reason', ''),
                'severity': self._determine_severity_from_description(cve_data.get('description', '')),
                'status': self._determine_overall_status(cve_data.get('releases', {})),
                'last_updated': datetime.utcnow().isoformat()
            }
            
            vulnerabilities.append(vulnerability)
        
        # Sort by CVE ID for consistent processing order
        vulnerabilities.sort(key=lambda v: self.detector.parse_cve_id(v['cve_id']))
        
        logger.info(f"✅ Flattened {len(vulnerabilities):,} unique CVEs from {len(debian_data):,} packages")
        return vulnerabilities
    
    def _determine_severity_from_description(self, description: str) -> str:
        """Determine severity from CVE description text"""
        desc_lower = description.lower()
        
        if any(keyword in desc_lower for keyword in ['critical', 'severe']):
            return 'CRITICAL'
        elif any(keyword in desc_lower for keyword in ['high', 'important', 'remote code execution', 'privilege escalation']):
            return 'HIGH'  
        elif any(keyword in desc_lower for keyword in ['medium', 'moderate']):
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _determine_overall_status(self, releases: Dict) -> str:
        """Determine overall status from Debian release data"""
        if not releases:
            return 'unknown'
        
        # If any release is open, overall status is open
        for release_data in releases.values():
            if release_data.get('status') == 'open':
                return 'open'
        
        # If all releases are fixed, overall status is fixed
        return 'fixed'
    
    async def download_security_data(self) -> Dict:
        """Download Debian Security Tracker data"""
        try:
            async with self.session.get(self.base_url) as response:
                if (response.status != 200):
                    raise Exception(f"HTTP {response.status}: {await response.text()}")
                
                data = await response.json()
                logger.info(f"📥 Downloaded data structure: {type(data)}")
                if isinstance(data, dict):
                    logger.info(f"📊 Data keys: {list(data.keys())}")
                    if 'data' in data:
                        logger.info(f"📦 Packages in data: {len(data['data'])}")
                        # Show first few package names
                        package_names = list(data['data'].keys())[:5]
                        logger.info(f"📋 Sample packages: {package_names}")
                    else:
                        # Show the actual structure if no 'data' key
                        logger.info(f"🔍 No 'data' key found. Direct keys: {list(data.keys())[:10]}")
                        # Show first few items to understand structure
                        first_items = list(data.items())[:3]
                        for key, value in first_items:
                            if isinstance(value, dict):
                                logger.info(f"📋 Package '{key}' has {len(value)} CVEs")
                                if value:
                                    first_cve = list(value.keys())[0]
                                    logger.info(f"📋 First CVE in '{key}': {first_cve}")
                            else:
                                logger.info(f"📋 Package '{key}' has value type: {type(value)}")
                return data
        except Exception as e:
            logger.error(f"❌ Failed to download security data: {e}")
            return {}
    
    async def insert_or_update_vulnerability(self, vulnerability: Dict):
        """Insert or update a vulnerability in the database"""
        if not self.db_conn:
            logger.warning(f"💾 Would insert/update CVE: {vulnerability['cve_id']} (DB not connected)")
            return
        
        try:
            # Get Debian source ID
            source_id = await self.db_conn.fetchval(
                "SELECT id FROM vulnerability_sources WHERE source_name = 'debian_security_tracker'"
            )
            
            if not source_id:
                raise Exception("Debian source not found in database")
            
            # Insert or update vulnerability in cves table
            query = """
            INSERT INTO cves (
                cve_id, source_id, description, 
                source_specific_data, affected_packages,
                created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7
            )
            ON CONFLICT (cve_id) DO UPDATE SET
                description = CASE 
                    WHEN EXCLUDED.source_id = cves.source_id THEN EXCLUDED.description
                    ELSE cves.description 
                END,
                source_specific_data = CASE 
                    WHEN EXCLUDED.source_id = cves.source_id THEN EXCLUDED.source_specific_data
                    ELSE cves.source_specific_data 
                END,
                affected_packages = CASE 
                    WHEN EXCLUDED.source_id = cves.source_id THEN EXCLUDED.affected_packages
                    ELSE cves.affected_packages 
                END,
                updated_at = EXCLUDED.updated_at
            """
            
            await self.db_conn.execute(
                query,
                vulnerability['cve_id'],
                source_id,
                vulnerability['description'],
                json.dumps(vulnerability),  # Store full Debian data as JSON
                json.dumps(vulnerability['affected_packages']),  # Store packages as JSON array
                datetime.utcnow(),
                datetime.utcnow()
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
        async with DebianIncrementalUpdater() as updater:
            result = await updater.run_incremental_update()
            if result['success']:
                print("✅ Incremental update completed successfully!")
            else:
                print(f"❌ Incremental update failed: {result.get('error', 'Unknown error')}")
                sys.exit(1)
    except Exception as e:
        print(f"❌ Incremental update failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())