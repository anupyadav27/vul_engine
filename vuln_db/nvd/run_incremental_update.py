import logging
from pathlib import Path
import argparse
from datetime import datetime, timedelta
from .database import NVDDatabase, get_db_config, DBConfig
from .nvd_fetcher import NVDFetcher

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('incremental_update.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def get_latest_cve_date(db):
    """Get the latest CVE date from the database to determine the gap"""
    try:
        with db.conn.cursor() as cursor:
            cursor.execute("""
                SELECT 
                    MAX(published_date) as latest_published,
                    MAX(last_modified_date) as latest_modified
                FROM cves 
                WHERE published_date != '1970-01-01 00:00:00'
            """)
            
            result = cursor.fetchone()
            latest_published, latest_modified = result
            
            # Use the more recent of the two dates as our starting point
            if latest_published and latest_modified:
                latest_date = max(latest_published, latest_modified)
            elif latest_published:
                latest_date = latest_published
            elif latest_modified:
                latest_date = latest_modified
            else:
                # If no valid dates found, default to 30 days ago
                latest_date = datetime.now() - timedelta(days=30)
            
            return latest_date
            
    except Exception as e:
        logger.error(f"❌ Error getting latest CVE date: {e}")
        # Return 30 days ago as fallback
        return datetime.now() - timedelta(days=30)

def run_intelligent_incremental_update(force_mitre_update: bool = False, max_days: int = None):
    """
    Orchestrates an intelligent incremental update process:
    1. Detects the gap between latest CVE in database and today
    2. Downloads only the missing CVEs from that gap period
    3. Optionally updates MITRE ATT&CK data
    4. Prints updated database statistics
    """
    
    data_dir = Path("./nvd_data")
    fetcher = NVDFetcher(data_dir=data_dir)
    
    try:
        db_config_dict = get_db_config()
        db_config = DBConfig(**db_config_dict)
    except ValueError as e:
        logger.error(f"❌ Configuration error: {e}")
        return

    try:
        with NVDDatabase(db_config) as db:
            # 1. Determine the gap automatically
            latest_cve_date = get_latest_cve_date(db)
            today = datetime.now()
            gap_days = (today.date() - latest_cve_date.date()).days
            
            logger.info(f"🔍 Intelligent Gap Analysis:")
            logger.info(f"   Latest CVE in database: {latest_cve_date.strftime('%Y-%m-%d %H:%M:%S')}")
            logger.info(f"   Today's date: {today.strftime('%Y-%m-%d %H:%M:%S')}")
            logger.info(f"   Detected gap: {gap_days} days")
            
            # Apply max_days limit if specified
            if max_days and gap_days > max_days:
                gap_days = max_days
                logger.info(f"   Limited to maximum: {max_days} days")
            
            if gap_days <= 0:
                logger.info("✅ Database is already up to date!")
                return
                
            logger.info(f"🚀 Starting intelligent incremental update for {gap_days} days...")

            # 2. Download CVEs for the gap period
            recent_cves_file = fetcher.download_recent_cves(days_back=gap_days)
            
            if recent_cves_file:
                logger.info("--- Starting Gap CVEs Import ---")
                initial_count = db.get_database_stats().get('total_cves', 0)
                db.import_cve_data(recent_cves_file)
                final_count = db.get_database_stats().get('total_cves', 0)
                new_cves = final_count - initial_count
                logger.info(f"--- ✅ Imported {new_cves} new/updated CVEs ---")
            else:
                logger.warning("⚠️ No recent CVEs were downloaded. The database may already be up to date.")

            # 3. Optionally update MITRE data
            if force_mitre_update:
                logger.info("--- Force updating MITRE ATT&CK data ---")
                mitre_json_file = fetcher.download_mitre_attack()
                if mitre_json_file:
                    db.import_mitre_attack(mitre_json_file)
                    logger.info("--- ✅ Finished MITRE ATT&CK Import ---")
                else:
                    logger.warning("⚠️ Could not update MITRE data, download failed.")

            # 4. Print final stats
            logger.info("\n--- Updated Database Statistics ---")
            db.print_stats()
            logger.info(f"--- ✅ Intelligent incremental update complete! ---")

    except Exception as e:
        logger.error(f"❌ An unexpected error occurred during the incremental update: {e}", exc_info=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run an intelligent incremental update of the NVD database.")
    parser.add_argument(
        "--max-days",
        type=int,
        default=None,
        help="Maximum number of days to look back (optional limit)"
    )
    parser.add_argument(
        "--update-mitre",
        action="store_true",
        help="Force a re-download and update of the MITRE ATT&CK dataset."
    )
    args = parser.parse_args()
    
    run_intelligent_incremental_update(force_mitre_update=args.update_mitre, max_days=args.max_days)
