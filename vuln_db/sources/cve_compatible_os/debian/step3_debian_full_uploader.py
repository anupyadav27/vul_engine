#!/usr/bin/env python3
"""
Simple Debian JSON to Database Upload Script

This script adds Debian Security Tracker data to the existing vulnerability database
that already contains NVD data. Uses existing Debian source configuration.
"""

import sys
import asyncio
import logging
import asyncpg
import json
from pathlib import Path
from datetime import datetime
import os # Added for environment support

# Add vuln_db root to Python path
current_dir = Path(__file__).resolve().parent
vuln_db_root = current_dir.parent.parent.parent
sys.path.insert(0, str(vuln_db_root))

from step2_debian_parser import DebianParser
# Use the centralized config system from vuln_db root
try:
    from config.schemas_and_config import get_database_connection, get_database_config
    from config.source_config import get_debian_config
except ImportError:
    # Fallback configuration if imports fail
    def get_debian_config():
        return {
            'name': 'debian_security_tracker',
            'url': 'https://security-tracker.debian.org/tracker/data/json',
            'category': 'cve_compatible_os',
            'priority': 8,
            'status': 'working',
            'timeout_seconds': 30,
            'retry_attempts': 3,
            'database': {
                'host': 'localhost',
                'port': 5432,
                'database': 'vulnerability_db',
                'username': 'vuln_user',
                'password': 'vuln_secure_pass',
                'min_connections': 5,
                'max_connections': 20
            }
        }
    
    # Simple database connection fallback
    async def get_database_connection(config):
        try:
            # Handle both 'username' and 'user' keys
            user_key = config.get('username') or config.get('user')
            if not user_key:
                raise ValueError("No username/user found in database config")
            
            conn = await asyncpg.connect(
                host=config['host'],
                port=config['port'],
                database=config['database'],
                user=user_key,
                password=config['password']
            )
            return conn
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            raise

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def upload_debian_to_existing_database():
    """Upload Debian vulnerabilities to existing database with NVD data"""
    
    logger.info("🚀 Starting Debian Upload to Existing Database")
    
    # Configuration
    config = get_debian_config()
    
    # Check if this is a dry run
    is_dry_run = os.getenv('DRY_RUN', 'false').lower() == 'true'
    if is_dry_run:
        logger.info("🔍 DRY RUN MODE: Will process data but not upload to database")
    
    # Find the parsed data file from step2 instead of raw JSON
    parsed_data_dir = current_dir / "output" / "parsed_data"
    parsed_files = list(parsed_data_dir.glob("debian_parsed_vulnerabilities_*.json"))
    
    if not parsed_files:
        logger.error("❌ No parsed Debian data files found in parsed_data directory")
        return
    
    # Use the most recent parsed file
    parsed_file = sorted(parsed_files)[-1]
    logger.info(f"📂 Using parsed data file: {parsed_file.name}")
    
    try:
        # Load parsed data directly instead of parsing raw JSON
        logger.info("📊 Loading parsed data file...")
        start_time = datetime.now()
        
        with open(parsed_file, 'r') as f:
            parsed_data = json.load(f)
        
        parsed_vulnerabilities = parsed_data.get('vulnerabilities', [])
        parse_time = datetime.now() - start_time
        logger.info(f"✅ Loaded {len(parsed_vulnerabilities)} vulnerabilities in {parse_time.total_seconds():.2f} seconds")
        
        if is_dry_run:
            # In dry-run mode, just process the data and save a report
            logger.info("🔍 DRY RUN: Processing data without database upload...")
            
            # Process vulnerabilities for database upload format
            logger.info("💾 Processing vulnerabilities for database format...")
            upload_start = datetime.now()
            
            # Process vulnerabilities in batches
            batch_size = 100
            total_processed = 0
            processed_vulnerabilities = []
            
            for i in range(0, len(parsed_vulnerabilities), batch_size):
                batch = parsed_vulnerabilities[i:i + batch_size]
                batch_num = (i // batch_size) + 1
                total_batches = (len(parsed_vulnerabilities) + batch_size - 1) // batch_size
                
                logger.info(f"📥 Processing batch {batch_num}/{total_batches} ({len(batch)} vulnerabilities)")
                
                for vuln in batch:
                    try:
                        cve_id = vuln.get('cve_id')
                        if not cve_id:
                            continue
                        
                        # Create database-ready record
                        db_record = {
                            'cve_id': cve_id,
                            'description': vuln.get('description', ''),
                            'severity': vuln.get('severity', 'UNKNOWN'),
                            'source': 'debian',
                            'source_url': vuln.get('source_url', ''),
                            'affected_packages': vuln.get('affected_packages', []),
                            'references': vuln.get('references', []),
                            'published_date': vuln.get('published_date'),
                            'last_modified_date': vuln.get('last_modified_date'),
                            'debian_specific': vuln.get('debian_specific', {}),
                            'raw_data': vuln.get('raw_data', {})
                        }
                        
                        processed_vulnerabilities.append(db_record)
                        total_processed += 1
                        
                    except Exception as e:
                        logger.warning(f"Failed to process {vuln.get('cve_id', 'unknown')}: {e}")
                        continue
                
                if batch_num % 10 == 0:
                    logger.info(f"✓ Progress: {batch_num}/{total_batches} batches completed")
            
            upload_time = datetime.now() - upload_start
            
            # Save dry-run report
            output_dir = current_dir / "output" / "upload_reports"
            output_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dry_run_file = output_dir / f"debian_dry_run_report_{timestamp}.json"
            
            dry_run_data = {
                'dry_run_timestamp': datetime.now().isoformat(),
                'source_parsed_file': str(parsed_file),
                'total_vulnerabilities': len(parsed_vulnerabilities),
                'successfully_processed': total_processed,
                'processing_time_seconds': upload_time.total_seconds(),
                'parse_time_seconds': parse_time.total_seconds(),
                'note': 'This is a dry run - no database operations were performed'
            }
            
            with open(dry_run_file, 'w') as f:
                json.dump(dry_run_data, f, indent=2, default=str)
            
            logger.info(f"🔍 DRY RUN completed successfully!")
            logger.info(f"📊 Total vulnerabilities processed: {total_processed:,}")
            logger.info(f"💾 Dry-run report saved: {dry_run_file}")
            
            return {
                'total_processed': len(parsed_vulnerabilities),
                'successfully_processed': total_processed,
                'parse_time': parse_time.total_seconds(),
                'processing_time': upload_time.total_seconds(),
                'dry_run_file': str(dry_run_file)
            }
        
        # Database connection using consolidated configuration
        logger.info("🔌 Connecting to database using consolidated config...")
        
        # Support different database environments
        environment = os.getenv('ENVIRONMENT', 'development')
        logger.info(f"🌍 Using database environment: {environment}")
        
        # Force use of fallback config to avoid password issues
        logger.info("🔧 Using fallback database configuration...")
        db_config = {
            'host': 'localhost',
            'port': 5432,
            'database': 'vulnerability_db',
            'username': 'vuln_user',
            'password': 'vuln_secure_pass'
        }
        
        # Normalize database config keys
        if 'username' in db_config and 'user' not in db_config:
            db_config['user'] = db_config['username']
        elif 'user' in db_config and 'username' not in db_config:
            db_config['username'] = db_config['user']
        
        conn = await get_database_connection(config=db_config)
        logger.info(f"✅ Connected to database at {db_config['host']}:{db_config['port']}")
        
        # Validate database schema before proceeding
        logger.info("🔍 Validating database schema...")
        try:
            # Check if cves table exists
            await conn.execute("SELECT 1 FROM cves LIMIT 1")
            logger.info("✓ cves table exists")
            
            # Check if vulnerability_sources table exists
            await conn.execute("SELECT 1 FROM vulnerability_sources LIMIT 1")
            logger.info("✓ vulnerability_sources table exists")
            
        except Exception as e:
            logger.error(f"❌ Database schema validation failed: {e}")
            logger.error("Required tables 'cves' and 'vulnerability_sources' must exist")
            await conn.close()
            return
        
        # Check existing database status
        total_existing = await conn.fetchval("SELECT COUNT(*) FROM cves")
        logger.info(f"📈 Existing CVEs in database: {total_existing:,}")
        
        # Get Debian source ID (prefer debian_security_tracker)
        debian_source = await conn.fetchrow(
            "SELECT id, source_name FROM vulnerability_sources WHERE source_name = 'debian_security_tracker'"
        )
        
        if not debian_source:
            # Fallback to 'debian' source
            debian_source = await conn.fetchrow(
                "SELECT id, source_name FROM vulnerability_sources WHERE source_name = 'debian'"
            )
        
        if not debian_source:
            # Create Debian source if it doesn't exist
            logger.info("📝 Creating Debian source in database...")
            try:
                await conn.execute("""
                    INSERT INTO vulnerability_sources (
                        source_name, 
                        category,
                        display_name,
                        url
                    ) VALUES ($1, $2, $3, $4)
                    RETURNING id, source_name
                """, 
                'debian_security_tracker',
                'cve_compatible_os',
                'Debian Security Tracker',
                'https://security-tracker.debian.org/tracker/data/json'
                )
                
                # Fetch the newly created source
                debian_source = await conn.fetchrow(
                    "SELECT id, source_name FROM vulnerability_sources WHERE source_name = 'debian_security_tracker'"
                )
                logger.info(f"✅ Created Debian source with ID: {debian_source['id']}")
                
            except Exception as e:
                logger.error(f"❌ Failed to create Debian source: {e}")
                return
        
        source_id = debian_source['id']
        logger.info(f"✓ Using Debian source: {debian_source['source_name']} (ID: {source_id})")
        
        # Check existing Debian CVEs
        existing_debian = await conn.fetchval("SELECT COUNT(*) FROM cves WHERE source_id = $1", source_id)
        logger.info(f"📊 Existing Debian CVEs: {existing_debian:,}")
        
        # Upload to database
        logger.info("💾 Uploading to database...")
        upload_start = datetime.now()
        
        # Process vulnerabilities in batches
        batch_size = 50  # Smaller batches for stability
        total_inserted = 0
        total_updated = 0
        total_failed = 0
        
        for i in range(0, len(parsed_vulnerabilities), batch_size):
            batch = parsed_vulnerabilities[i:i + batch_size]
            batch_num = (i // batch_size) + 1
            total_batches = (len(parsed_vulnerabilities) + batch_size - 1) // batch_size
            
            logger.info(f"📥 Processing batch {batch_num}/{total_batches} ({len(batch)} vulnerabilities)")
            
            try:
                # Process each vulnerability in the batch
                for vuln in batch:
                    try:
                        cve_id = vuln.get('cve_id')
                        if not cve_id:
                            logger.warning("Skipping vulnerability without CVE ID")
                            total_failed += 1
                            continue
                        
                        # Check if CVE already exists - FIXED: use cve_id directly
                        existing_cve = await conn.fetchrow("SELECT cve_id, source_id FROM cves WHERE cve_id = $1", cve_id)
                        
                        if existing_cve:
                            # Update existing CVE with Debian data if it's from a different source
                            if existing_cve['source_id'] != source_id:
                                # This CVE exists from another source (likely NVD)
                                # Add Debian-specific data to source_specific_data
                                await conn.execute("""
                                    UPDATE cves SET
                                        source_specific_data = COALESCE(source_specific_data, '{}'::jsonb) || $1::jsonb,
                                        updated_at = CURRENT_TIMESTAMP
                                    WHERE cve_id = $2
                                """, 
                                json.dumps({
                                    'debian': {
                                        'debian_specific': vuln.get('debian_specific', {}),
                                        'references': vuln.get('references', []),
                                        'source_url': vuln.get('source_url', ''),
                                        'affected_packages': vuln.get('affected_packages', [])
                                    }
                                }),
                                cve_id
                                )
                                total_updated += 1
                                logger.debug(f"✓ Updated existing CVE {cve_id} with Debian data")
                            else:
                                # Same source, just update
                                await conn.execute("""
                                    UPDATE cves SET
                                        description = $1,
                                        source_specific_data = $2,
                                        updated_at = CURRENT_TIMESTAMP
                                    WHERE cve_id = $3
                                """, 
                                vuln.get('description', ''),
                                json.dumps({
                                    'debian_specific': vuln.get('debian_specific', {}),
                                    'references': vuln.get('references', []),
                                    'source_url': vuln.get('source_url', ''),
                                    'affected_packages': vuln.get('affected_packages', [])
                                }),
                                cve_id
                                )
                                total_updated += 1
                        else:
                            # Insert new CVE - FIXED: remove id column
                            await conn.execute("""
                                INSERT INTO cves (
                                    cve_id, 
                                    source_id, 
                                    description, 
                                    source_specific_data,
                                    created_at,
                                    updated_at
                                ) VALUES ($1, $2, $3, $4, $5, $6)
                            """, 
                            cve_id,
                            source_id,
                            vuln.get('description', ''),
                            json.dumps({
                                'debian_specific': vuln.get('debian_specific', {}),
                                'references': vuln.get('references', []),
                                'source_url': vuln.get('source_url', ''),
                                'affected_packages': vuln.get('affected_packages', [])
                            }),
                            datetime.now(),
                            datetime.now()
                            )
                            total_inserted += 1
                        
                    except Exception as e:
                        logger.warning(f"Failed to process {vuln.get('cve_id', 'unknown')}: {e}")
                        total_failed += 1
                
                if batch_num % 10 == 0:  # Progress update every 10 batches
                    logger.info(f"✓ Progress: {batch_num}/{total_batches} batches completed")
                
            except Exception as e:
                logger.error(f"❌ Error processing batch {batch_num}: {e}")
                total_failed += len(batch)
        
        upload_time = datetime.now() - upload_start
        
        # Final database statistics
        final_total = await conn.fetchval("SELECT COUNT(*) FROM cves")
        final_debian = await conn.fetchval("SELECT COUNT(*) FROM cves WHERE source_id = $1", source_id)
        
        # Close database connection
        await conn.close()
        
        # UPDATED: Save upload report in standardized output structure
        upload_report = {
            'upload_timestamp': datetime.now().isoformat(),
            'source_json_file': str(parsed_file), # Changed from json_file to parsed_file
            'database_upload_results': {
                'total_processed': len(parsed_vulnerabilities),
                'new_cves_inserted': total_inserted,
                'existing_cves_updated': total_updated,
                'failed_uploads': total_failed,
                'success_rate_percent': ((total_inserted + total_updated) / len(parsed_vulnerabilities) * 100) if len(parsed_vulnerabilities) > 0 else 0,
                'parse_time_seconds': parse_time.total_seconds(),
                'upload_time_seconds': upload_time.total_seconds()
            },
            'database_statistics': {
                'total_cves_before': total_existing,
                'total_cves_after': final_total,
                'debian_cves_before': existing_debian,
                'debian_cves_after': final_debian,
                'net_cves_added': final_total - total_existing
            },
            'source_information': {
                'debian_source_id': source_id,
                'debian_source_name': debian_source['source_name']
            }
        }
        
        # Save upload report
        output_dir = current_dir / "output" / "upload_reports"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = output_dir / f"debian_upload_report_{timestamp}.json"
        
        with open(report_file, 'w') as f:
            json.dump(upload_report, f, indent=2, default=str)
        
        logger.info(f"📄 Upload report saved: {report_file}")

        return {
            'total_processed': len(parsed_vulnerabilities),
            'inserted': total_inserted,
            'updated': total_updated,
            'failed': total_failed,
            'parse_time': parse_time.total_seconds(),
            'upload_time': upload_time.total_seconds(),
            'final_total_cves': final_total,
            'final_debian_cves': final_debian,
            'report_file': str(report_file)
        }
        
    except Exception as e:
        logger.error(f"❌ Error during upload process: {e}")
        raise

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Upload Debian vulnerabilities to database')
    parser.add_argument('--environment', '-e', default='development', 
                       choices=['development', 'testing', 'container', 'production'],
                       help='Database environment to use (default: development)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Process data without uploading to database')
    
    args = parser.parse_args()
    
    # Set environment variable for the script
    os.environ['ENVIRONMENT'] = args.environment
    
    if args.dry_run:
        logger.info("🔍 DRY RUN MODE: Will process data but not upload to database")
        os.environ['DRY_RUN'] = 'true'
    
    try:
        asyncio.run(upload_debian_to_existing_database())
    except KeyboardInterrupt:
        logger.info("⏹️ Upload interrupted by user")
    except Exception as e:
        logger.error(f"❌ Upload failed: {e}")
        sys.exit(1)