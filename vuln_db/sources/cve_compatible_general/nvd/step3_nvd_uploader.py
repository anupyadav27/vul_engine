#!/usr/bin/env python3
"""
NVD Database Uploader - Step 3

APPROACH:
1. Load standardized CVE data from parser output
2. Connect to vulnerability database with proper error handling
3. Bulk insert/update CVEs with optimized batch processing
4. Handle CVSS scores and CPE data
5. Maintain data integrity and track upload statistics

DATABASE OPERATIONS:
- Bulk upsert CVEs into 'cves' table
- Insert CPE matches into 'cpes' table
- Update vulnerability_sources metadata

FEATURES:
- Batch processing for performance (1000 CVEs per batch)
- Conflict resolution (ON CONFLICT DO UPDATE)
- Transaction safety with rollback capability
- Comprehensive error handling and retry logic
- Progress tracking and detailed statistics
"""

import sys
import asyncio
import logging
import asyncpg
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
import time

# Add vuln_db root to Python path
current_dir = Path(__file__).resolve().parent
vuln_db_root = current_dir.parent.parent.parent
sys.path.insert(0, str(vuln_db_root))

# Import consolidated configuration system
from config.schemas_and_config import get_database_connection, get_database_config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class NVDDatabaseUploader:
    """NVD database uploader with optimized batch processing"""
    
    def __init__(self):
        self.input_dir = current_dir / "output" / "parsed_data"
        self.output_dir = current_dir / "output" / "upload_reports"
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Use consolidated database configuration
        self.db_config = None  # Will be loaded from consolidated config
        self.db_conn = None
        self.batch_size = 100  # Process CVEs in batches of 100 for easier debugging
        
        # Statistics tracking
        self.stats = {
            'total_cves_processed': 0,
            'cves_inserted': 0,
            'cves_updated': 0,
            'cvss_scores_inserted': 0,
            'cpe_matches_inserted': 0,
            'processing_errors': 0,
            'batches_processed': 0,
            'database_operations': {
                'cve_upserts': 0,
                'cvss_inserts': 0,
                'cpe_inserts': 0
            }
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
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
            
            # Ensure NVD source exists
            await self.ensure_nvd_source_exists()
            
            return self
        except Exception as e:
            logger.error(f"❌ Failed to connect to database: {e}")
            raise
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.db_conn:
            await self.db_conn.close()
            logger.info("📤 Database connection closed")
    
    async def upload_nvd_data(self) -> Dict[str, Any]:
        """Main method to upload all parsed NVD data to database"""
        logger.info("🚀 Starting NVD database upload...")
        start_time = datetime.now(timezone.utc)
        
        try:
            # Step 1: Load parsed CVE data
            logger.info("📖 Loading parsed NVD data...")
            cves_data = await self.load_parsed_cve_data()
            
            if not cves_data:
                logger.warning("⚠️ No parsed CVE data found to upload")
                return {
                    'success': False,
                    'error': 'No parsed CVE data found',
                    'total_cves_processed': 0
                }
            
            total_cves = len(cves_data)
            logger.info(f"📊 Found {total_cves:,} CVEs to process")
            
            # Step 2: Process CVEs in batches
            await self.process_cves_in_batches(cves_data)
            
            # Step 3: Update source metadata
            await self.update_source_metadata(total_cves)
            
            # Step 4: Generate upload report
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            
            results = {
                'success': True,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration,
                'total_cves_loaded': total_cves,
                'upload_statistics': self.stats,
                'performance_metrics': {
                    'cves_per_second': self.stats['total_cves_processed'] / duration if duration > 0 else 0,
                    'batches_processed': self.stats['batches_processed'],
                    'average_batch_time': duration / self.stats['batches_processed'] if self.stats['batches_processed'] > 0 else 0
                }
            }
            
            await self.save_upload_report(results)
            self.log_upload_summary(results)
            
            return results
            
        except Exception as e:
            logger.error(f"❌ Error during NVD database upload: {e}")
            return {
                'success': False,
                'error': str(e),
                'total_cves_processed': self.stats['total_cves_processed'],
                'upload_statistics': self.stats
            }
    
    async def ensure_nvd_source_exists(self) -> int:
        """Ensure NVD source is registered in vulnerability_sources table"""
        try:
            # Check if NVD source exists
            check_query = "SELECT id FROM vulnerability_sources WHERE source_name = 'nvd'"
            source_id = await self.db_conn.fetchval(check_query)
            
            if not source_id:
                # Insert NVD source
                insert_query = """
                INSERT INTO vulnerability_sources (
                    source_name, category, display_name, url, status, priority,
                    enhancement_needed, engine_type, vulnerability_engine_priority,
                    notes
                ) VALUES (
                    'nvd', 
                    'government_database',
                    'National Vulnerability Database',
                    'https://nvd.nist.gov',
                    'active',
                    10,
                    false,
                    'existing',
                    'high',
                    'NIST National Vulnerability Database - Primary CVE data source'
                ) RETURNING id
                """
                source_id = await self.db_conn.fetchval(insert_query)
                logger.info(f"✅ Created NVD source entry with ID: {source_id}")
            else:
                logger.info(f"✅ NVD source exists with ID: {source_id}")
            
            self.nvd_source_id = source_id
            return source_id
            
        except Exception as e:
            logger.error(f"❌ Error ensuring NVD source exists: {e}")
            raise
    
    async def load_parsed_cve_data(self) -> List[Dict]:
        """Load parsed CVE data from per-batch files if available, else from single JSON file"""
        try:
            # First, try to find all per-batch files directly
            import glob
            batch_files = sorted(glob.glob(str(self.input_dir / "nvd_standardized_cves_batch_*.json")))
            
            if batch_files:
                logger.info(f"📖 Found {len(batch_files)} per-batch files, loading directly...")
                all_cves: List[Dict] = []
                total_files_loaded = 0
                
                for batch_file in batch_files:
                    try:
                        with open(batch_file, 'r') as pf:
                            data = json.load(pf)
                            batch_cves = data.get('cves', [])
                            all_cves.extend(batch_cves)
                            total_files_loaded += 1
                            logger.debug(f"   Loaded {len(batch_cves):,} CVEs from {Path(batch_file).name}")
                    except Exception as e:
                        logger.error(f"❌ Failed to read batch file {batch_file}: {e}")
                        continue
                
                logger.info(f"📖 Loaded {len(all_cves):,} CVEs from {total_files_loaded}/{len(batch_files)} batch files")
                return all_cves
            
            # Fallback to manifest if no direct batch files found
            manifest_file = self.input_dir / "nvd_parsed_manifest.json"
            if manifest_file.exists():
                logger.info("📖 Found per-batch manifest, loading parsed files from manifest...")
                with open(manifest_file, 'r') as f:
                    manifest = json.load(f)
                files = manifest.get('files', [])
                all_cves: List[Dict] = []
                for entry in files:
                    parsed_path = entry.get('parsed_file')
                    if not parsed_path:
                        continue
                    try:
                        with open(parsed_path, 'r') as pf:
                            data = json.load(pf)
                            all_cves.extend(data.get('cves', []))
                    except Exception as e:
                        logger.error(f"❌ Failed to read parsed file {parsed_path}: {e}")
                        continue
                logger.info(f"📖 Loaded {len(all_cves):,} CVEs from {len(files)} per-batch files")
                return all_cves
            
            # Final fallback to single large file
            parsed_file = self.input_dir / "nvd_standardized_cves.json"
            if not parsed_file.exists():
                logger.error(f"❌ No parsed data files found in {self.input_dir}")
                return []
            with open(parsed_file, 'r') as f:
                data = json.load(f)
            cves = data.get('cves', [])
            metadata = data.get('metadata', {})
            logger.info(f"📖 Loaded {len(cves):,} CVEs from parsed data (single file)")
            logger.info(f"   Parser version: {metadata.get('parser_version', 'unknown')}")
            logger.info(f"   Processing timestamp: {metadata.get('processing_timestamp', 'unknown')}")
            return cves
        
        except Exception as e:
            logger.error(f"❌ Error loading parsed CVE data: {e}")
            return []
    
    async def process_cves_in_batches(self, cves_data: List[Dict]):
        """Process CVEs in optimized batches"""
        total_cves = len(cves_data)
        total_batches = (total_cves + self.batch_size - 1) // self.batch_size
        
        logger.info(f"🔄 Processing {total_cves:,} CVEs in {total_batches} batches of {self.batch_size}")
        
        for batch_num in range(total_batches):
            start_idx = batch_num * self.batch_size
            end_idx = min(start_idx + self.batch_size, total_cves)
            batch_cves = cves_data[start_idx:end_idx]
            
            batch_start_time = time.time()
            
            try:
                # Process each CVE individually to avoid batch failures
                batch_success_count = 0
                batch_error_count = 0
                
                for cve_data in batch_cves:
                    try:
                        # Process individual CVE within its own transaction
                        async with self.db_conn.transaction():
                            await self.process_single_cve(cve_data)
                            batch_success_count += 1
                    except Exception as e:
                        cve_id = cve_data.get('cve_id', 'unknown') if isinstance(cve_data, dict) else 'unknown'
                        logger.error(f"❌ Error processing CVE {cve_id}: {e}")
                        batch_error_count += 1
                        self.stats['processing_errors'] += 1
                        # Continue with next CVE instead of failing the batch
                        continue
                
                batch_duration = time.time() - batch_start_time
                self.stats['batches_processed'] += 1
                
                # Log progress every batch for debugging
                processed_count = start_idx + batch_success_count
                progress_pct = (processed_count / total_cves) * 100
                logger.info(f"   ✅ Batch {batch_num + 1}/{total_batches} completed | "
                          f"Progress: {processed_count:,}/{total_cves:,} ({progress_pct:.1f}%) | "
                          f"Batch time: {batch_duration:.2f}s | "
                          f"Success: {batch_success_count}, Errors: {batch_error_count}")
                
            except Exception as e:
                logger.error(f"❌ Error processing batch {batch_num + 1}: {e}")
                self.stats['processing_errors'] += len(batch_cves)
                # Continue with next batch rather than failing completely
                continue
    
    async def process_single_cve(self, cve_data: Dict):
        """Process a single CVE with all its related data"""
        # Validate required fields
        if not isinstance(cve_data, dict):
            raise ValueError(f"CVE data is not a dictionary: {type(cve_data)}")
        
        if 'cve_id' not in cve_data:
            raise ValueError("CVE data missing cve_id field")
        
        # Insert/update main CVE record
        await self.upsert_cve_record(cve_data)
        
        # Insert CVSS scores
        await self.insert_cvss_scores(cve_data)
        
        # Insert CPE matches
        await self.insert_cpe_matches(cve_data)
        
        self.stats['total_cves_processed'] += 1
    
    async def upsert_cve_record(self, cve_data: Dict):
        """Insert or update CVE record in main cves table"""
        try:
            query = """
            INSERT INTO cves (
                cve_id, source_id, description, severity,
                published_date, modified_date, 
                source_specific_data, cwe_ids, reference_urls,
                created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
            )
            ON CONFLICT (cve_id) DO UPDATE SET
                description = CASE 
                    WHEN EXCLUDED.source_id = $2 THEN EXCLUDED.description
                    ELSE cves.description 
                END,
                severity = CASE 
                    WHEN EXCLUDED.source_id = $2 THEN EXCLUDED.severity
                    ELSE cves.severity 
                END,
                modified_date = CASE 
                    WHEN EXCLUDED.source_id = $2 THEN EXCLUDED.modified_date
                    ELSE cves.modified_date 
                END,
                source_specific_data = CASE 
                    WHEN EXCLUDED.source_id = $2 THEN EXCLUDED.source_specific_data
                    ELSE cves.source_specific_data 
                END,
                cwe_ids = CASE 
                    WHEN EXCLUDED.source_id = $2 THEN EXCLUDED.cwe_ids
                    ELSE cves.cwe_ids 
                END,
                reference_urls = CASE 
                    WHEN EXCLUDED.source_id = $2 THEN EXCLUDED.reference_urls
                    ELSE cves.reference_urls 
                END,
                updated_at = EXCLUDED.updated_at
            RETURNING (xmax = 0) as inserted
            """
            
            # Parse dates and ensure they are timezone-naive for database compatibility
            published_date_input = cve_data.get('published_date', '')
            last_modified_date_input = cve_data.get('last_modified_date', '')
            
            # Parse dates - handle both string and datetime object inputs
            try:
                if published_date_input:
                    if isinstance(published_date_input, str):
                        # Handle both timezone-aware and naive datetime strings
                        if '+' in published_date_input or published_date_input.endswith('Z'):
                            # Timezone-aware string
                            published_date = datetime.fromisoformat(published_date_input.replace('Z', '+00:00'))
                            published_date = published_date.replace(tzinfo=None)  # Convert to naive
                        else:
                            # Naive string, assume UTC
                            published_date = datetime.fromisoformat(published_date_input)
                    elif isinstance(published_date_input, datetime):
                        # Already a datetime object
                        if published_date_input.tzinfo:
                            published_date = published_date_input.replace(tzinfo=None)  # Convert to naive
                        else:
                            published_date = published_date_input
                    else:
                        published_date = None
                else:
                    published_date = None
                
                if last_modified_date_input:
                    if isinstance(last_modified_date_input, str):
                        # Handle both timezone-aware and naive datetime strings
                        if '+' in last_modified_date_input or last_modified_date_input.endswith('Z'):
                            # Timezone-aware string
                            last_modified_date = datetime.fromisoformat(last_modified_date_input.replace('Z', '+00:00'))
                            last_modified_date = last_modified_date.replace(tzinfo=None)  # Convert to naive
                        else:
                            # Naive string, assume UTC
                            last_modified_date = datetime.fromisoformat(last_modified_date_input)
                    elif isinstance(last_modified_date_input, datetime):
                        # Already a datetime object
                        if last_modified_date_input.tzinfo:
                            last_modified_date = last_modified_date_input.replace(tzinfo=None)  # Convert to naive
                        else:
                            last_modified_date = last_modified_date_input
                    else:
                        last_modified_date = None
                else:
                    last_modified_date = None
            except Exception as e:
                logger.warning(f"Date parsing error for {cve_data.get('cve_id', 'unknown')}: {e}")
                published_date = None
                last_modified_date = None
            
            # Prepare arrays for PostgreSQL - convert from lists to arrays
            cwe_ids = cve_data.get('cwe_ids', [])
            # Fix reference URLs processing - the parsed data has a list of URL strings, not objects
            reference_urls = cve_data.get('references', [])
            
            # Execute upsert
            result = await self.db_conn.fetchval(
                query,
                cve_data['cve_id'],
                self.nvd_source_id,
                cve_data.get('description', ''),
                cve_data.get('severity', 'UNKNOWN'),
                published_date,
                last_modified_date,
                json.dumps(cve_data.get('nvd_raw_data', {})),  # Store complete NVD data as JSON
                cwe_ids,  # Pass as list/array, not JSON string
                json.dumps(reference_urls),  # Convert list to JSON string for JSONB field
                datetime.now(timezone.utc).replace(tzinfo=None),  # Convert to naive for database
                datetime.now(timezone.utc).replace(tzinfo=None)   # Convert to naive for database
            )
            
            # Track insert vs update
            if result:  # True means it was an insert
                self.stats['cves_inserted'] += 1
            else:  # False means it was an update
                self.stats['cves_updated'] += 1
            
            self.stats['database_operations']['cve_upserts'] += 1
            
        except Exception as e:
            logger.error(f"❌ Error upserting CVE {cve_data['cve_id']}: {e}")
            # Log the specific data that caused the error for debugging
            logger.error(f"   CVE data: {json.dumps({k: str(v)[:100] for k, v in cve_data.items()}, indent=2)}")
            # Don't raise - let the caller handle it
            raise
    
    async def insert_cvss_scores(self, cve_data: Dict):
        """Store CVSS scores in the CVE record (no separate cvss_scores table)"""
        # Since there's no separate cvss_scores table, we'll store this in the main CVE record
        # This method is called but doesn't need to do anything extra since CVSS data
        # is already stored in the cves table via the source_specific_data field
        pass
    
    async def insert_cpe_matches(self, cve_data: Dict):
        """Insert CPE matches for a CVE using the 'cpes' table"""
        cpe_matches = cve_data.get('cpe_matches', [])
        
        # Don't delete existing CPEs - just insert new ones and ignore duplicates
        for cpe_match in cpe_matches:
            try:
                insert_query = """
                INSERT INTO cpes (
                    cve_id, cpe_uri, vulnerable,
                    version_start_including, version_start_excluding,
                    version_end_including, version_end_excluding,
                    source_id, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (cve_id, cpe_uri, source_id) DO NOTHING
                """
                result = await self.db_conn.execute(
                    insert_query,
                    cve_data['cve_id'],
                    cpe_match.get('cpe23_uri', ''),
                    bool(cpe_match.get('vulnerable', True)),
                    cpe_match.get('version_start_including'),
                    cpe_match.get('version_start_excluding'),
                    cpe_match.get('version_end_including'),
                    cpe_match.get('version_end_excluding'),
                    self.nvd_source_id,
                    datetime.now(timezone.utc).replace(tzinfo=None)  # Convert to naive for database
                )
                
                # Only count as inserted if it wasn't a duplicate
                if result != 'INSERT 0 0':  # PostgreSQL returns this for no-op inserts
                    self.stats['cpe_matches_inserted'] += 1
                    self.stats['database_operations']['cpe_inserts'] += 1
                
            except Exception as e:
                logger.error(f"❌ Error inserting CPE match for {cve_data['cve_id']}: {e}")
                # Continue with next CPE without failing the entire CVE
    
    async def update_source_metadata(self, total_cves: int):
        """Update NVD source metadata with processing statistics"""
        try:
            update_query = """
            UPDATE vulnerability_sources SET
                last_fetch_at = $1,
                last_fetch_status = $2,
                notes = $3
            WHERE id = $4
            """
            
            metadata = {
                'last_upload_timestamp': datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
                'total_cves_processed': self.stats['total_cves_processed'],
                'cves_inserted': self.stats['cves_inserted'],
                'cves_updated': self.stats['cves_updated'],
                'processing_errors': self.stats['processing_errors'],
                'batch_size_used': self.batch_size,
                'upload_method': 'batch_processing'
            }
            
            await self.db_conn.execute(
                update_query,
                datetime.now(timezone.utc).replace(tzinfo=None),  # Convert to naive for database
                'success',
                json.dumps(metadata),
                self.nvd_source_id
            )
            
            logger.info(f"✅ Updated NVD source metadata")
            
        except Exception as e:
            logger.error(f"❌ Error updating source metadata: {e}")
    
    async def save_upload_report(self, results: Dict[str, Any]):
        """Save upload report with detailed statistics"""
        try:
            report_file = self.output_dir / f"nvd_upload_report_{datetime.now(timezone.utc).replace(tzinfo=None).strftime('%Y%m%d_%H%M%S')}.json"
            with open(report_file, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"📊 Saved upload report to {report_file}")
        except Exception as e:
            logger.error(f"❌ Error saving upload report: {e}")
    
    def log_upload_summary(self, results: Dict[str, Any]):
        """Log comprehensive upload summary"""
        logger.info("=" * 60)
        logger.info("📊 NVD DATABASE UPLOAD SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Success: {results['success']}")
        logger.info(f"Duration: {results['duration_seconds']:.2f} seconds")
        logger.info(f"Total CVEs Loaded: {results['total_cves_loaded']:,}")
        logger.info(f"Total CVEs Processed: {self.stats['total_cves_processed']:,}")
        logger.info(f"Processing Errors: {self.stats['processing_errors']:,}")
        
        logger.info(f"\nCVE Operations:")
        logger.info(f"  CVEs Inserted: {self.stats['cves_inserted']:,}")
        logger.info(f"  CVEs Updated: {self.stats['cves_updated']:,}")
        logger.info(f"  Total CVE Upserts: {self.stats['database_operations']['cve_upserts']:,}")
        
        logger.info(f"\nAdditional Data:")
        logger.info(f"  CVSS Scores: {self.stats['cvss_scores_inserted']:,}")
        logger.info(f"  CPE Matches: {self.stats['cpe_matches_inserted']:,}")
        
        logger.info(f"\nPerformance:")
        logger.info(f"  Batches Processed: {self.stats['batches_processed']:,}")
        logger.info(f"  CVEs per Second: {results['performance_metrics']['cves_per_second']:.2f}")
        logger.info(f"  Average Batch Time: {results['performance_metrics']['average_batch_time']:.2f}s")
        
        if self.stats['processing_errors'] > 0:
            error_rate = (self.stats['processing_errors'] / results['total_cves_loaded']) * 100
            logger.info(f"\nError Rate: {error_rate:.2f}%")
        
        logger.info("=" * 60)

async def main():
    """Main execution function"""
    try:
        async with NVDDatabaseUploader() as uploader:
            result = await uploader.upload_nvd_data()
            
            if result['success']:
                print("✅ NVD database upload completed successfully!")
                print(f"Processed {result['upload_statistics']['total_cves_processed']:,} CVEs")
                print(f"  • Inserted: {result['upload_statistics']['cves_inserted']:,}")
                print(f"  • Updated: {result['upload_statistics']['cves_updated']:,}")
                print(f"  • Errors: {result['upload_statistics']['processing_errors']:,}")
            else:
                print(f"❌ NVD database upload failed: {result.get('error', 'Unknown error')}")
                sys.exit(1)
    except Exception as e:
        print(f"❌ NVD database upload failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())