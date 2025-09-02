import logging
from pathlib import Path
import glob
from .database import NVDDatabase, get_db_config, DBConfig

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('initial_load.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def run_full_import():
    """
    Orchestrates the entire initial data load process using local data files:
    1. Initializes the database schema (dropping existing tables).
    2. Imports all NVD JSON files from the local nvd_data directory.
    3. Imports the MITRE ATT&CK data if available.
    4. Prints final database statistics.
    """
    logger.info("🚀 Starting initial data load process using local data files...")
    
    # Use the existing nvd_data directory
    data_dir = Path(__file__).parent / "nvd_data"
    if not data_dir.exists():
        logger.error(f"❌ Data directory not found: {data_dir}")
        return
        
    logger.info(f"📂 Using local data directory: {data_dir}")
    
    try:
        db_config_dict = get_db_config()
        db_config = DBConfig(**db_config_dict)
    except ValueError as e:
        logger.error(f"❌ Configuration error: {e}")
        return

    try:
        with NVDDatabase(db_config) as db:
            # 1. Initialize schema
            logger.info("Initializing database schema (this will delete existing data)...")
            db.initialize_enhanced_schema()
            logger.info("✅ Schema initialized successfully.")

            # 2. Find all NVD JSON files in the local directory
            json_pattern = str(data_dir / "nvdcve-*.json")
            json_files = glob.glob(json_pattern)
            json_files.sort()  # Process in chronological order
            
            if not json_files:
                logger.error("❌ No NVD JSON files found in local data directory.")
                return
            
            logger.info(f"📋 Found {len(json_files)} NVD JSON files to process")

            # 3. Import NVD data from local files
            logger.info("--- Starting NVD Data Import from Local Files ---")
            for json_file_path in json_files:
                json_file = Path(json_file_path)
                logger.info(f"📂 Processing file: {json_file.name}")
                try:
                    db.import_cve_data(json_file)
                except Exception as e:
                    logger.error(f"❌ Failed to process {json_file.name}: {e}")
                    continue
            logger.info("--- ✅ Finished NVD Data Import ---")

            # 4. Import MITRE data if available
            mitre_file = data_dir / "mitre_attack.json"
            if mitre_file.exists():
                logger.info("--- Starting MITRE ATT&CK Import ---")
                try:
                    db.import_mitre_attack(mitre_file)
                    logger.info("--- ✅ Finished MITRE ATT&CK Import ---")
                except Exception as e:
                    logger.error(f"❌ Failed to import MITRE data: {e}")
            else:
                logger.warning("⚠️ MITRE ATT&CK file not found, skipping MITRE import.")

            # 5. Print final stats
            logger.info("\n--- Final Database Statistics ---")
            db.print_stats()
            logger.info("--- ✅ Initial data load complete! ---")

    except Exception as e:
        logger.error(f"❌ An unexpected error occurred during the initial load: {e}", exc_info=True)

if __name__ == "__main__":
    run_full_import()
