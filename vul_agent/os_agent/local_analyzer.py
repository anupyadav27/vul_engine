"""
Local Vulnerability Analyzer for Agent
Provides local vulnerability analysis capabilities with cached CVE data
"""

import json
import sqlite3
import requests
import os
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import re

logger = logging.getLogger(__name__)

class LocalVulnerabilityAnalyzer:
    """Local vulnerability analysis with cached CVE database"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.local_config = config.get('local_analysis', {})
        self.cache_file = 'vuln_cache.db'
        self.last_update_file = 'cache_last_update.json'
        self.severity_threshold = self.local_config.get('severity_threshold', 'MEDIUM')
        self.init_cache_db()
    
    def init_cache_db(self):
        """Initialize local SQLite cache database"""
        try:
            self.conn = sqlite3.connect(self.cache_file)
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY,
                    cve_id TEXT UNIQUE,
                    product TEXT,
                    vendor TEXT,
                    version_start TEXT,
                    version_end TEXT,
                    version_start_including BOOLEAN,
                    version_end_including BOOLEAN,
                    severity TEXT,
                    score REAL,
                    description TEXT,
                    published_date TEXT,
                    last_modified TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            self.conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_product ON vulnerabilities(product)
            ''')
            self.conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_severity ON vulnerabilities(severity)
            ''')
            self.conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_cve_id ON vulnerabilities(cve_id)
            ''')
            
            self.conn.commit()
            logger.info("Local vulnerability cache database initialized")
        except Exception as e:
            logger.error(f"Failed to initialize cache database: {e}")
            self.conn = None
    
    def should_update_cache(self) -> bool:
        """Check if cache needs updating"""
        if not self.local_config.get('vuln_db_cache', True):
            return False
        
        if not os.path.exists(self.last_update_file):
            return True
        
        try:
            with open(self.last_update_file, 'r') as f:
                last_update = json.load(f)
            
            last_update_time = datetime.fromisoformat(last_update['timestamp'])
            update_interval = self.local_config.get('cache_update_interval', 86400)  # 24 hours
            
            return (datetime.utcnow() - last_update_time).total_seconds() > update_interval
        except Exception as e:
            logger.warning(f"Error checking cache update time: {e}")
            return True
    
    def update_cache_from_engine(self, engine_url: str, api_key: str) -> bool:
        """Update local cache from central engine"""
        if not self.conn:
            return False
        
        try:
            logger.info("Updating local vulnerability cache from engine...")
            
            # Get vulnerability data from engine
            headers = {"Authorization": f"Bearer {api_key}"}
            response = requests.get(
                f"{engine_url}/api/v1/vulnerabilities?limit=10000",
                headers=headers,
                timeout=60
            )
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                # Clear old cache and insert new data
                self.conn.execute('DELETE FROM vulnerabilities')
                
                for vuln in vulnerabilities:
                    self.conn.execute('''
                        INSERT OR REPLACE INTO vulnerabilities 
                        (cve_id, product, vendor, version_start, version_end,
                         version_start_including, version_end_including,
                         severity, score, description, published_date, last_modified)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        vuln.get('cve_id'),
                        vuln.get('package_name', ''),
                        vuln.get('vendor', ''),
                        vuln.get('version_start'),
                        vuln.get('version_end'),
                        vuln.get('version_start_including', True),
                        vuln.get('version_end_including', False),
                        vuln.get('severity'),
                        vuln.get('score'),
                        vuln.get('description'),
                        vuln.get('published_date'),
                        vuln.get('last_modified')
                    ))
                
                self.conn.commit()
                
                # Update last update timestamp
                with open(self.last_update_file, 'w') as f:
                    json.dump({
                        'timestamp': datetime.utcnow().isoformat(),
                        'count': len(vulnerabilities)
                    }, f)
                
                logger.info(f"Cache updated with {len(vulnerabilities)} vulnerabilities")
                return True
            else:
                logger.error(f"Failed to fetch vulnerabilities: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error updating cache: {e}")
            return False
    
    def analyze_packages_locally(self, packages: List[Dict]) -> List[Dict]:
        """Analyze packages for vulnerabilities using local cache"""
        if not self.conn:
            logger.warning("Local cache not available, skipping local analysis")
            return []
        
        vulnerabilities = []
        logger.info(f"Analyzing {len(packages)} packages locally...")
        
        for package in packages:
            package_vulns = self._check_package_locally(package)
            vulnerabilities.extend(package_vulns)
        
        # Filter by severity threshold
        filtered_vulns = self._filter_by_severity(vulnerabilities)
        
        logger.info(f"Found {len(filtered_vulns)} vulnerabilities locally")
        return filtered_vulns
    
    def _check_package_locally(self, package: Dict) -> List[Dict]:
        """Check single package against local cache"""
        package_name = package.get('name', '').lower()
        package_version = package.get('version', '')
        
        if not package_name or not package_version:
            return []
        
        try:
            cursor = self.conn.execute('''
                SELECT cve_id, product, severity, score, description,
                       version_start, version_end, version_start_including, version_end_including
                FROM vulnerabilities 
                WHERE LOWER(product) = ? OR LOWER(product) LIKE ?
                ORDER BY score DESC
                LIMIT 50
            ''', (package_name, f"%{package_name}%"))
            
            vulnerabilities = []
            for row in cursor.fetchall():
                cve_data = {
                    'cve_id': row[0],
                    'product': row[1],
                    'severity': row[2],
                    'score': row[3],
                    'description': row[4],
                    'version_start': row[5],
                    'version_end': row[6],
                    'version_start_including': bool(row[7]),
                    'version_end_including': bool(row[8])
                }
                
                # Check if version is affected
                if self._is_version_affected(package_version, cve_data):
                    vuln = {
                        'cve_id': row[0],
                        'package_name': package_name,
                        'package_version': package_version,
                        'package_type': package.get('type'),
                        'package_manager': package.get('manager'),
                        'severity': row[2],
                        'score': row[3],
                        'description': row[4],
                        'analysis_source': 'local_cache',
                        'remediation': self._generate_remediation(package_name, package_version, row[0])
                    }
                    vulnerabilities.append(vuln)
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error checking package {package_name}: {e}")
            return []
    
    def _is_version_affected(self, package_version: str, cve_data: Dict) -> bool:
        """Check if package version is affected by vulnerability"""
        try:
            clean_version = self._clean_version(package_version)
            
            version_start = cve_data.get('version_start')
            version_end = cve_data.get('version_end')
            start_including = cve_data.get('version_start_including', True)
            end_including = cve_data.get('version_end_including', False)
            
            # If no version range specified, assume affected
            if not version_start and not version_end:
                return True
            
            # Compare versions
            if version_start:
                start_clean = self._clean_version(version_start)
                if start_including:
                    if self._compare_versions(clean_version, start_clean) < 0:
                        return False
                else:
                    if self._compare_versions(clean_version, start_clean) <= 0:
                        return False
            
            if version_end:
                end_clean = self._clean_version(version_end)
                if end_including:
                    if self._compare_versions(clean_version, end_clean) > 0:
                        return False
                else:
                    if self._compare_versions(clean_version, end_clean) >= 0:
                        return False
            
            return True
            
        except Exception as e:
            logger.debug(f"Version comparison error: {e}")
            return True  # Default to affected if can't determine
    
    def _clean_version(self, version: str) -> str:
        """Clean version string for comparison"""
        if not version:
            return "0.0.0"
        
        # Remove common prefixes and suffixes
        version = re.sub(r'^[vV]', '', version)
        version = re.sub(r'[-+].*$', '', version)  # Remove build metadata
        
        # Ensure we have at least major.minor.patch
        parts = version.split('.')
        while len(parts) < 3:
            parts.append('0')
        
        return '.'.join(parts[:3])
    
    def _compare_versions(self, version1: str, version2: str) -> int:
        """Compare two version strings"""
        try:
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]
            
            # Pad shorter version with zeros
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            for i in range(max_len):
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1
            
            return 0
            
        except (ValueError, AttributeError):
            # Fallback to string comparison
            return -1 if version1 < version2 else (1 if version1 > version2 else 0)
    
    def _filter_by_severity(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Filter vulnerabilities by severity threshold"""
        severity_order = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1,
            'NONE': 0
        }
        
        threshold = severity_order.get(self.severity_threshold, 2)
        
        filtered = []
        for vuln in vulnerabilities:
            vuln_severity = severity_order.get(vuln.get('severity', 'NONE'), 0)
            if vuln_severity >= threshold:
                filtered.append(vuln)
        
        return filtered
    
    def _generate_remediation(self, package_name: str, current_version: str, cve_id: str) -> str:
        """Generate remediation advice"""
        remediation = f"Update {package_name} from version {current_version} to the latest secure version."
        
        if "CRITICAL" in str(cve_id) or any(word in str(cve_id).upper() for word in ["RCE", "CRITICAL"]):
            remediation += " This is a critical vulnerability that should be patched immediately."
        
        remediation += f" For more details, see: https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
        
        return remediation
    
    def get_cache_stats(self) -> Dict:
        """Get local cache statistics"""
        if not self.conn:
            return {"status": "unavailable"}
        
        try:
            cursor = self.conn.execute('SELECT COUNT(*) FROM vulnerabilities')
            total_vulns = cursor.fetchone()[0]
            
            cursor = self.conn.execute('SELECT COUNT(*) FROM vulnerabilities WHERE severity = "CRITICAL"')
            critical_vulns = cursor.fetchone()[0]
            
            # Get last update info
            last_update = {"timestamp": "never", "count": 0}
            if os.path.exists(self.last_update_file):
                with open(self.last_update_file, 'r') as f:
                    last_update = json.load(f)
            
            return {
                "status": "available",
                "total_vulnerabilities": total_vulns,
                "critical_vulnerabilities": critical_vulns,
                "last_update": last_update,
                "cache_file_size_mb": round(os.path.getsize(self.cache_file) / 1024 / 1024, 2)
            }
            
        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
            return {"status": "error", "error": str(e)}
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()