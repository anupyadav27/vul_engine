import psycopg2
import logging
from typing import List, Dict, Optional
from dataclasses import dataclass
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
import json
from pathlib import Path
import re
from ..db_schema.vulnerability_schema import SCHEMA_QUERIES

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('nvd_update.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class DBConfig:
    host: str
    port: int
    database: str
    user: str
    password: str

class NVDDatabase:
    def __init__(self, config: DBConfig):
        self.config = config
        self.conn = None
        self.batch_size = 500  # Records per transaction
        self.data_dir = Path("./nvd_data")
        self.data_dir.mkdir(exist_ok=True)

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def connect(self):
        try:
            logger.info(f"Attempting to connect to database: {self.config}")
            self.conn = psycopg2.connect(
                host=self.config.host,
                port=self.config.port,
                database=self.config.database,
                user=self.config.user,
                password=self.config.password,
                sslmode="disable"
            )
            self.conn.autocommit = False
            logger.info("Database connection established successfully.")
        except psycopg2.OperationalError as e:
            logger.error(f"OperationalError: Unable to connect to the database. {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during database connection: {e}")
            raise

    def close(self):
        if self.conn and not self.conn.closed:
            self.conn.close()
            logger.info("Connection closed")

    def initialize_enhanced_schema(self):
        """Create enhanced schema using the centralized schema definition."""
        try:
            with self.conn.cursor() as cursor:
                for query in SCHEMA_QUERIES:
                    logger.info(f"Executing schema query...")
                    cursor.execute(query)
            self.conn.commit()
            logger.info("✅ Enhanced database schema initialized successfully from centralized schema.")
        except Exception as e:
            self.conn.rollback()
            logger.error(f"❌ Schema initialization failed: {e}")
            raise

    def import_cve_data(self, json_file):
        """Import CVE data from JSON file"""
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Handle different JSON formats
            if 'CVE_Items' in data:  # Legacy format
                cve_items = data['CVE_Items']
                parser_func = self._parse_legacy_cve
            elif 'vulnerabilities' in data:  # New format
                cve_items = data['vulnerabilities']
                parser_func = self._parse_modern_cve
            else:
                logger.error(f"❌ Unknown JSON format in {json_file}")
                return
            
            logger.info(f"📊 Importing {len(cve_items)} CVEs from {json_file}")
            
            cve_batch = []
            cpe_batch = []
            imported_count = 0
            
            for item in cve_items:
                try:
                    cve_data, cpe_data = parser_func(item)
                    if cve_data:
                        cve_batch.append(cve_data)
                        cpe_batch.extend(cpe_data)
                        imported_count += 1
                        
                        if len(cve_batch) >= self.batch_size:
                            self._insert_cve_batch_enhanced(cve_batch)
                            self._insert_cpe_batch_enhanced(cpe_batch)
                            cve_batch = []
                            cpe_batch = []
                            logger.info(f"📈 Imported {imported_count} CVEs...")
                
                except Exception as e:
                    logger.error(f"❌ Error processing CVE: {e}")
                    continue
            
            # Insert remaining batches
            if cve_batch:
                self._insert_cve_batch_enhanced(cve_batch)
                self._insert_cpe_batch_enhanced(cpe_batch)
            
            logger.info(f"✅ Successfully imported {imported_count} CVEs from {json_file}")
            
        except Exception as e:
            logger.error(f"❌ Failed to import CVE data from {json_file}: {e}")

    def import_mitre_attack(self, json_file):
        """Import MITRE ATT&CK techniques"""
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            techniques = []
            for obj in data.get('objects', []):
                if (obj.get('type') == 'attack-pattern' and
                    obj.get('external_references', [{}])[0].get('source_name') == 'mitre-attack'):
                    technique_id = obj.get('external_references', [{}])[0].get('external_id', '')
                    parent_id = None
                    if obj.get('x_mitre_is_subtechnique') and '.' in technique_id:
                        parent_id = technique_id.split('.')[0]

                    technique_data = {
                        'technique_id': technique_id,
                        'technique_name': obj.get('name', ''),
                        'description': obj.get('description', ''),
                        'tactic': ','.join([phase['phase_name'] for phase in obj.get('kill_chain_phases', [])]),
                        'subtechnique_of': parent_id,
                        'platforms': obj.get('x_mitre_platforms', []),
                        'data_sources': obj.get('x_mitre_data_sources', []),
                        'url': f"https://attack.mitre.org/techniques/{technique_id}"
                    }
                    
                    if technique_data['technique_id']:
                        techniques.append(technique_data)
            
            self._insert_mitre_techniques(techniques)
            logger.info(f"✅ Imported {len(techniques)} MITRE ATT&CK techniques")
            
        except Exception as e:
            logger.error(f"❌ Failed to import MITRE ATT&CK data: {e}")

    def _parse_modern_cve(self, item):
        """Parse modern NVD format (API 2.0)"""
        try:
            cve = item.get('cve', {})
            cve_id = cve.get('id', '')
            
            # Description
            descriptions = cve.get('descriptions', [])
            description = next((d['value'] for d in descriptions if d.get('lang') == 'en'), '')
            
            # CVSS scores
            metrics = item.get('metrics', {})
            cvss_v3 = None
            cvss_v2 = None
            
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_v3 = metrics['cvssMetricV31'][0]['cvssData']
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss_v3 = metrics['cvssMetricV30'][0]['cvssData']
            
            if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_v2 = metrics['cvssMetricV2'][0]['cvssData']
            
            # CWE and references
            weaknesses = cve.get('weaknesses', [])
            cwe_ids = []
            for weakness in weaknesses:
                for desc in weakness.get('description', []):
                    if desc.get('lang') == 'en' and 'CWE-' in desc.get('value', ''):
                        cwe_ids.append(desc['value'])
            
            references = [ref.get('url', '') for ref in cve.get('references', [])]
            
            cve_data = {
                'cve_id': cve_id,
                'published_date': self._parse_date(cve.get('published')),
                'last_modified_date': self._parse_date(cve.get('lastModified')),
                'description': description,
                'cvss_v3_score': cvss_v3.get('baseScore') if cvss_v3 else None,
                'cvss_v3_severity': cvss_v3.get('baseSeverity') if cvss_v3 else None,
                'cvss_v3_vector': cvss_v3.get('vectorString') if cvss_v3 else None,
                'cvss_v2_score': cvss_v2.get('baseScore') if cvss_v2 else None,
                'cvss_v2_severity': cvss_v2.get('baseSeverity') if cvss_v2 else None,
                'cvss_v2_vector': cvss_v2.get('vectorString') if cvss_v2 else None,
                'cwe_ids': cwe_ids,
                'reference_urls': references,
                'source_identifier': item.get('sourceIdentifier', ''),
                'vuln_status': item.get('vulnStatus', '')
            }
            
            # Parse CPE data
            cpe_data = []
            for config in item.get('configurations', []):
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        if cpe_match.get('vulnerable', False):
                            cpe_parts = self._parse_cpe_uri(cpe_match.get('criteria', ''))
                            cpe_entry = {
                                'cve_id': cve_id,
                                'cpe_uri': cpe_match.get('criteria', ''),
                                'part': cpe_parts.get('part', ''),
                                'vendor': cpe_parts.get('vendor', ''),
                                'product': cpe_parts.get('product', ''),
                                'version': cpe_parts.get('version', ''),
                                'version_start_including': cpe_match.get('versionStartIncluding'),
                                'version_start_excluding': cpe_match.get('versionStartExcluding'),
                                'version_end_including': cpe_match.get('versionEndIncluding'),
                                'version_end_excluding': cpe_match.get('versionEndExcluding'),
                                'vulnerable': cpe_match.get('vulnerable', True)
                            }
                            cpe_data.append(cpe_entry)
            
            return cve_data, cpe_data
            
        except Exception as e:
            logger.error(f"Error parsing modern CVE: {e}")
            return None, []

    def _parse_legacy_cve(self, item):
        """Parse legacy NVD format (1.1)"""
        cve_meta = item['cve']['CVE_data_meta']
        description = item['cve']['description']['description_data'][0]['value'] if item['cve']['description']['description_data'] else None
        
        cvss_v3 = item['impact'].get('baseMetricV3', {})
        cvss_v2 = item['impact'].get('baseMetricV2', {})
        
        # Enhanced parsing for legacy format
        cwe_ids = []
        for ptype in item['cve'].get('problemtype', {}).get('problemtype_data', []):
            for desc in ptype.get('description', []):
                if 'CWE-' in desc.get('value', ''):
                    cwe_ids.append(desc['value'])
        
        references = [ref['url'] for ref in item['cve'].get('references', {}).get('reference_data', [])]
        
        cve_data = {
            'cve_id': cve_meta['ID'],
            'published_date': self._parse_date(item.get('publishedDate', '1970-01-01T00:00:00.000Z')),
            'last_modified_date': self._parse_date(item.get('lastModifiedDate', '1970-01-01T00:00:00.000Z')),
            'description': description,
            'cvss_v3_score': cvss_v3.get('cvssV3', {}).get('baseScore', None),
            'cvss_v3_severity': cvss_v3.get('cvssV3', {}).get('baseSeverity', None),
            'cvss_v3_vector': cvss_v3.get('cvssV3', {}).get('vectorString', None),
            'cvss_v2_score': cvss_v2.get('cvssV2', {}).get('baseScore', None),
            'cvss_v2_severity': cvss_v2.get('severity', None),
            'cvss_v2_vector': cvss_v2.get('vectorString', None),
            'cwe_ids': cwe_ids,
            'reference_urls': references,
            'source_identifier': '',
            'vuln_status': ''
        }
        
        # Parse CPE data for legacy format
        cpe_data = []
        for node in item.get('configurations', {}).get('nodes', []):
            for cpe_match in node.get('cpe_match', []):
                if cpe_match.get('vulnerable', False):
                    cpe_parts = self._parse_cpe_uri(cpe_match.get('cpe23Uri', ''))
                    cpe_entry = {
                        'cve_id': cve_meta['ID'],
                        'cpe_uri': cpe_match.get('cpe23Uri', ''),
                        'part': cpe_parts.get('part', ''),
                        'vendor': cpe_parts.get('vendor', ''),
                        'product': cpe_parts.get('product', ''),
                        'version': cpe_parts.get('version', ''),
                        'version_start_including': cpe_match.get('versionStartIncluding'),
                        'version_start_excluding': cpe_match.get('versionStartExcluding'),
                        'version_end_including': cpe_match.get('versionEndIncluding'),
                        'version_end_excluding': cpe_match.get('versionEndExcluding'),
                        'vulnerable': cpe_match.get('vulnerable', True)
                    }
                    cpe_data.append(cpe_entry)
        
        return cve_data, cpe_data

    def _parse_cpe_uri(self, cpe_uri):
        """Parse CPE URI into components"""
        try:
            parts = cpe_uri.split(':')
            return {
                'part': parts[2] if len(parts) > 2 else '',
                'vendor': parts[3] if len(parts) > 3 else '',
                'product': parts[4] if len(parts) > 4 else '',
                'version': parts[5] if len(parts) > 5 else '',
                'update': parts[6] if len(parts) > 6 else '',
                'edition': parts[7] if len(parts) > 7 else '',
                'language': parts[8] if len(parts) > 8 else ''
            }
        except Exception as e:
            logger.debug(f"Error parsing CPE: {cpe_uri} - {e}")
            return {'part': '', 'vendor': '', 'product': '', 'version': ''}

    def _parse_date(self, date_str: str) -> datetime:
        """Parse date string from NVD into a datetime object"""
        if not date_str:
            return datetime.strptime('1970-01-01T00:00:00.000Z', '%Y-%m-%dT%H:%M:%S.%fZ')
        
        try:
            return datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S.%fZ')
        except ValueError:
            try:
                return datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S.%f')
            except ValueError:
                try:
                    return datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S')
                except ValueError:
                    try:
                        return datetime.strptime(date_str, '%Y-%m-%dT%H:%MZ')
                    except ValueError:
                        logger.warning(f"Failed to parse date: {date_str}. Using default date.")
                        return datetime.strptime('1970-01-01T00:00:00.000Z', '%Y-%m-%dT%H:%M:%S.%fZ')

    def _insert_cve_batch_enhanced(self, cves: List[Dict]):
        """Insert CVE batch with enhanced fields"""
        query = """
        INSERT INTO cves (
            cve_id, published_date, last_modified_date, description,
            cvss_v3_score, cvss_v3_severity, cvss_v3_vector,
            cvss_v2_score, cvss_v2_severity, cvss_v2_vector,
            cwe_ids, reference_urls, source_identifier, vuln_status
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (cve_id) DO UPDATE SET
            last_modified_date = EXCLUDED.last_modified_date,
            description = EXCLUDED.description,
            cvss_v3_score = EXCLUDED.cvss_v3_score,
            cvss_v3_severity = EXCLUDED.cvss_v3_severity,
            cvss_v3_vector = EXCLUDED.cvss_v3_vector,
            cvss_v2_score = EXCLUDED.cvss_v2_score,
            cvss_v2_severity = EXCLUDED.cvss_v2_severity,
            cvss_v2_vector = EXCLUDED.cvss_v2_vector,
            cwe_ids = EXCLUDED.cwe_ids,
            reference_urls = EXCLUDED.reference_urls,
            source_identifier = EXCLUDED.source_identifier,
            vuln_status = EXCLUDED.vuln_status,
            updated_at = CURRENT_TIMESTAMP
        """
        self._execute_batch_enhanced(query, cves)

    def _insert_cpe_batch_enhanced(self, cpes: List[Dict]):
        """Insert CPE batch with enhanced fields"""
        if not cpes:
            return
            
        # First delete existing CPEs for these CVEs
        cve_ids = list(set(cpe['cve_id'] for cpe in cpes))
        
        try:
            with self.conn.cursor() as cursor:
                if cve_ids:
                    cursor.execute(
                        "DELETE FROM cpes WHERE cve_id = ANY(%s)",
                        (cve_ids,)
                    )
        except Exception as e:
            logger.error(f"Error deleting existing CPEs: {e}")
        
        query = """
        INSERT INTO cpes (
            cve_id, cpe_uri, part, vendor, product, version,
            version_start_including, version_start_excluding,
            version_end_including, version_end_excluding, vulnerable
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        self._execute_batch_enhanced(query, cpes)

    def _insert_mitre_techniques(self, techniques: List[Dict]):
        """Insert MITRE ATT&CK techniques"""
        query = """
        INSERT INTO mitre_techniques (
            technique_id, technique_name, description, tactic,
            subtechnique_of, platforms, data_sources, url
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (technique_id) DO UPDATE SET
            technique_name = EXCLUDED.technique_name,
            description = EXCLUDED.description,
            tactic = EXCLUDED.tactic,
            subtechnique_of = EXCLUDED.subtechnique_of,
            platforms = EXCLUDED.platforms,
            data_sources = EXCLUDED.data_sources,
            url = EXCLUDED.url
        """
        self._execute_batch_enhanced(query, techniques)

    def _execute_batch_enhanced(self, query: str, data: List[Dict]):
        """Enhanced batch execution with better error handling"""
        try:
            with self.conn.cursor() as cursor:
                for i in range(0, len(data), self.batch_size):
                    batch = data[i:i + self.batch_size]
                    batch_tuples = [tuple(item.values()) for item in batch]
                    cursor.executemany(query, batch_tuples)
                self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            logger.error(f"Batch insert failed: {e}")
            raise

    def get_database_stats(self):
        """Get comprehensive database statistics"""
        try:
            with self.conn.cursor() as cursor:
                stats = {}
                
                # CVE statistics
                cursor.execute("SELECT COUNT(*) FROM cves")
                stats['total_cves'] = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM cves WHERE cvss_v3_severity = 'CRITICAL'")
                stats['critical_cves'] = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM cves WHERE cvss_v3_severity = 'HIGH'")
                stats['high_cves'] = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM cves WHERE cvss_v3_severity = 'MEDIUM'")
                stats['medium_cves'] = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM cves WHERE cvss_v3_severity = 'LOW'")
                stats['low_cves'] = cursor.fetchone()[0]
                
                # CPE statistics
                cursor.execute("SELECT COUNT(*) FROM cpes")
                stats['total_cpes'] = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(DISTINCT vendor) FROM cpes WHERE vendor != ''")
                stats['unique_vendors'] = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(DISTINCT product) FROM cpes WHERE product != ''")
                stats['unique_products'] = cursor.fetchone()[0]
                
                # MITRE statistics
                cursor.execute("SELECT COUNT(*) FROM mitre_techniques")
                stats['mitre_techniques'] = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM cve_attack_mappings")
                stats['cve_mitre_mappings'] = cursor.fetchone()[0]
                
                # Recent data
                cursor.execute("""
                    SELECT COUNT(*) FROM cves 
                    WHERE published_date >= NOW() - INTERVAL '30 days'
                """)
                stats['recent_cves_30d'] = cursor.fetchone()[0]
                
                return stats
                
        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            return {}

    def print_stats(self):
        """Print formatted database statistics"""
        stats = self.get_database_stats()
        
        logger.info("📊 Database Statistics:")
        logger.info(f"   Total CVEs: {stats.get('total_cves', 0):,}")
        logger.info(f"   ├─ Critical: {stats.get('critical_cves', 0):,}")
        logger.info(f"   ├─ High: {stats.get('high_cves', 0):,}")
        logger.info(f"   ├─ Medium: {stats.get('medium_cves', 0):,}")
        logger.info(f"   └─ Low: {stats.get('low_cves', 0):,}")
        logger.info(f"   Recent (30d): {stats.get('recent_cves_30d', 0):,}")
        logger.info(f"")
        logger.info(f"   Total CPE entries: {stats.get('total_cpes', 0):,}")
        logger.info(f"   Unique vendors: {stats.get('unique_vendors', 0):,}")
        logger.info(f"   Unique products: {stats.get('unique_products', 0):,}")
        logger.info(f"")
        logger.info(f"   MITRE ATT&CK techniques: {stats.get('mitre_techniques', 0):,}")
        logger.info(f"   CVE-MITRE mappings: {stats.get('cve_mitre_mappings', 0):,}")

# Legacy compatibility
Database = NVDDatabase  # Keep backward compatibility

def get_db_config():
    config = {
        "host": os.getenv("DB_HOST"),
        "port": os.getenv("DB_PORT"),
        "database": os.getenv("DB_NAME"),
        "user": os.getenv("DB_USER"),
        "password": os.getenv("DB_PASSWORD"),
    }
    logger.info(f"Loaded environment variables: {config}")
    
    if not config["database"] or not config["user"] or not config["password"]:
        logger.error("Missing required database configuration. Check your .env file.")
        raise ValueError("Missing required database configuration.")
    
    try:
        config["port"] = int(config["port"])
    except ValueError:
        logger.error("Invalid DB_PORT value. Must be an integer.")
        raise ValueError("Invalid DB_PORT value. Must be an integer.")
    
    return config

# Explicitly load the .env file
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)
    logger.info(f".env file loaded from {dotenv_path}")
else:
    logger.error(f".env file not found at {dotenv_path}. Using system environment variables.")

# Debugging: Print loaded environment variables
logger.info(f"DB_HOST: {os.getenv('DB_HOST')}")
logger.info(f"DB_PORT: {os.getenv('DB_PORT')}")
logger.info(f"DB_NAME: {os.getenv('DB_NAME')}")
logger.info(f"DB_USER: {os.getenv('DB_USER')}")
logger.info(f"DB_PASSWORD: {os.getenv('DB_PASSWORD')}")