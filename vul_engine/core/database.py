"""
Database manager for Vulnerability Engine
Handles connections to PostgreSQL vulnerability database using centralized configuration
"""

import asyncpg
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import json

# Import centralized database configuration
from cspm_vul.vuln_db.config.schemas_and_config.database_config import get_database_config, create_database_pool

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Manages database connections and operations"""
    
    def __init__(self, environment: str = None):
        self.pool = None
        self.environment = environment
        self.config = get_database_config(environment)
    
    async def initialize(self):
        """Initialize database connection pool"""
        try:
            self.pool = await create_database_pool(self.config, self.environment)
            logger.info(f"Database connection pool created successfully for environment: {self.environment}")
            
            # Ensure required tables exist
            await self._ensure_tables()
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
    
    async def close(self):
        """Close database connection pool"""
        if self.pool:
            await self.pool.close()
            logger.info("Database connection pool closed")
    
    async def check_connection(self) -> bool:
        """Check if database connection is healthy"""
        try:
            if not self.pool:
                return False
            
            async with self.pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
                return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False
    
    def get_connection_info(self) -> Dict[str, Any]:
        """Get current database connection information (without sensitive data)"""
        if not self.config:
            return {}
        
        safe_config = {
            'host': self.config.get('host'),
            'port': self.config.get('port'),
            'database': self.config.get('database'),
            'user': self.config.get('user'),
            'environment': self.environment,
            'pool_size': self.config.get('max_connections', self.config.get('pool_size'))
        }
        return safe_config
    
    async def change_environment(self, new_environment: str):
        """Change database environment and reinitialize connection"""
        if self.pool:
            await self.close()
        
        self.environment = new_environment
        self.config = get_database_config(new_environment)
        await self.initialize()
        logger.info(f"Switched to environment: {new_environment}")
    
    def get_available_environments(self) -> List[str]:
        """Get list of available database environments"""
        try:
            from cspm_vul.vuln_db.config.schemas_and_config.database_config import db_config_manager
            all_configs = db_config_manager._load_json_config()
            return list(all_configs.keys())
        except Exception as e:
            logger.error(f"Failed to get available environments: {e}")
            return ['development']  # fallback
    
    @classmethod
    async def test_connection(cls, environment: str = None) -> Dict[str, Any]:
        """Test database connection for specified environment"""
        try:
            from cspm_vul.vuln_db.config.schemas_and_config.database_config import test_database_connection
            return await test_database_connection(environment)
        except Exception as e:
            logger.error(f"Failed to test database connection: {e}")
            return {
                'success': False,
                'environment': environment or 'default',
                'error': str(e)
            }
    
    def get_database_url(self) -> str:
        """Get database URL for tools that need connection strings"""
        try:
            from cspm_vul.vuln_db.config.schemas_and_config.database_config import get_database_url
            return get_database_url(self.config, self.environment)
        except Exception as e:
            logger.error(f"Failed to get database URL: {e}")
            return ""
    
    def validate_config(self) -> bool:
        """Validate current database configuration"""
        try:
            required_fields = ['host', 'port', 'database', 'user', 'password']
            missing_fields = [field for field in required_fields if not self.config.get(field)]
            
            if missing_fields:
                logger.error(f"Missing required database configuration fields: {missing_fields}")
                return False
            
            # Validate port is a number
            if not isinstance(self.config.get('port'), int):
                logger.error("Database port must be a number")
                return False
            
            return True
        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            return False
    
    async def _ensure_tables(self):
        """Ensure required tables exist for the vulnerability engine"""
        create_tables_sql = """
        -- Agents table (for vulnerability engine functionality)
        CREATE TABLE IF NOT EXISTS agents (
            agent_id VARCHAR(32) PRIMARY KEY,
            hostname VARCHAR(255) NOT NULL,
            platform VARCHAR(100),
            architecture VARCHAR(100),
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status VARCHAR(20) DEFAULT 'active',
            metadata JSONB
        );
        
        -- Scans table (for vulnerability engine functionality)
        CREATE TABLE IF NOT EXISTS scans (
            scan_id SERIAL PRIMARY KEY,
            agent_id VARCHAR(32) REFERENCES agents(agent_id),
            scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            scan_duration FLOAT,
            packages_found INTEGER DEFAULT 0,
            services_found INTEGER DEFAULT 0,
            vulnerabilities_found INTEGER DEFAULT 0,
            status VARCHAR(20) DEFAULT 'completed',
            scan_data JSONB
        );
        
        -- Scan vulnerabilities table (for vulnerability engine functionality)
        CREATE TABLE IF NOT EXISTS scan_vulnerabilities (
            id SERIAL PRIMARY KEY,
            scan_id INTEGER REFERENCES scans(scan_id),
            cve_id VARCHAR(20),
            package_name VARCHAR(255),
            package_version VARCHAR(100),
            severity VARCHAR(20),
            score FLOAT,
            description TEXT,
            remediation TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        -- Note: CVE tables (cves, cpes, mitre_techniques, cve_attack_mappings) 
        -- are managed by the NVD database system in vuln_db/nvd/
        -- We don't create them here to avoid conflicts
        
        -- Create indexes for better performance
        CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen);
        CREATE INDEX IF NOT EXISTS idx_scans_agent_timestamp ON scans(agent_id, scan_timestamp);
        CREATE INDEX IF NOT EXISTS idx_scan_vulns_scan_id ON scan_vulnerabilities(scan_id);
        CREATE INDEX IF NOT EXISTS idx_scan_vulns_cve ON scan_vulnerabilities(cve_id);
        CREATE INDEX IF NOT EXISTS idx_scan_vulns_severity ON scan_vulnerabilities(severity);
        """
        
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(create_tables_sql)
            logger.info("Database tables ensured successfully")
        except Exception as e:
            logger.error(f"Failed to create tables: {e}")
            raise
    
    async def register_agent(self, agent_data: Dict) -> bool:
        """Register or update an agent"""
        try:
            async with self.pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO agents (agent_id, hostname, platform, architecture, metadata)
                    VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT (agent_id) 
                    DO UPDATE SET 
                        hostname = EXCLUDED.hostname,
                        platform = EXCLUDED.platform,
                        architecture = EXCLUDED.architecture,
                        last_seen = CURRENT_TIMESTAMP,
                        metadata = EXCLUDED.metadata
                """, 
                agent_data['agent_id'],
                agent_data.get('hostname', ''),
                agent_data.get('platform', ''),
                agent_data.get('architecture', ''),
                json.dumps(agent_data)
                )
            logger.info(f"Agent registered: {agent_data['agent_id']}")
            return True
        except Exception as e:
            logger.error(f"Failed to register agent: {e}")
            return False
    
    async def store_scan_results(self, scan_data: Dict) -> Optional[int]:
        """Store scan results in database"""
        try:
            async with self.pool.acquire() as conn:
                async with conn.transaction():
                    # Insert scan record
                    scan_id = await conn.fetchval("""
                        INSERT INTO scans (agent_id, scan_duration, packages_found, 
                                         services_found, scan_data)
                        VALUES ($1, $2, $3, $4, $5)
                        RETURNING scan_id
                    """,
                    scan_data['agent_id'],
                    scan_data.get('scan_duration', 0),
                    len(scan_data.get('packages', [])),
                    len(scan_data.get('services', [])),
                    json.dumps(scan_data)
                    )
                    
                    logger.info(f"Scan stored with ID: {scan_id}")
                    return scan_id
        except Exception as e:
            logger.error(f"Failed to store scan results: {e}")
            return None
    
    async def store_vulnerabilities(self, scan_id: int, vulnerabilities: List[Dict]) -> bool:
        """Store vulnerabilities found in scan"""
        try:
            async with self.pool.acquire() as conn:
                async with conn.transaction():
                    for vuln in vulnerabilities:
                        await conn.execute("""
                            INSERT INTO scan_vulnerabilities 
                            (scan_id, cve_id, package_name, package_version, 
                             severity, score, description, remediation)
                            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                        """,
                        scan_id,
                        vuln.get('cve_id'),
                        vuln.get('package_name'),
                        vuln.get('package_version'),
                        vuln.get('severity'),
                        vuln.get('score'),
                        vuln.get('description'),
                        vuln.get('remediation')
                        )
                    
                    # Update scan with vulnerability count
                    await conn.execute("""
                        UPDATE scans SET vulnerabilities_found = $1 WHERE scan_id = $2
                    """, len(vulnerabilities), scan_id)
                    
            logger.info(f"Stored {len(vulnerabilities)} vulnerabilities for scan {scan_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to store vulnerabilities: {e}")
            return False
    
    async def get_agent_list(self) -> List[Dict]:
        """Get list of all registered agents"""
        try:
            async with self.pool.acquire() as conn:
                rows = await conn.fetch("""
                    SELECT agent_id, hostname, platform, architecture, 
                           first_seen, last_seen, status
                    FROM agents 
                    ORDER BY last_seen DESC
                """)
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to get agent list: {e}")
            return []
    
    async def get_scan_history(self, agent_id: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """Get scan history"""
        try:
            async with self.pool.acquire() as conn:
                if (agent_id):
                    rows = await conn.fetch("""
                        SELECT scan_id, agent_id, scan_timestamp, scan_duration,
                               packages_found, services_found, vulnerabilities_found, status
                        FROM scans 
                        WHERE agent_id = $1
                        ORDER BY scan_timestamp DESC
                        LIMIT $2
                    """, agent_id, limit)
                else:
                    rows = await conn.fetch("""
                        SELECT scan_id, agent_id, scan_timestamp, scan_duration,
                               packages_found, services_found, vulnerabilities_found, status
                        FROM scans 
                        ORDER BY scan_timestamp DESC
                        LIMIT $1
                    """, limit)
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to get scan history: {e}")
            return []
    
    async def search_vulnerabilities(self, **filters) -> List[Dict]:
        """Search vulnerabilities with filters"""
        try:
            conditions = []
            params = []
            param_count = 0
            
            if filters.get('cve_id'):
                param_count += 1
                conditions.append(f"cve_id = ${param_count}")
                params.append(filters['cve_id'])
            
            if filters.get('severity'):
                param_count += 1
                conditions.append(f"severity = ${param_count}")
                params.append(filters['severity'])
            
            if filters.get('package_name'):
                param_count += 1
                conditions.append(f"package_name ILIKE ${param_count}")
                params.append(f"%{filters['package_name']}%")
            
            where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""
            
            async with self.pool.acquire() as conn:
                rows = await conn.fetch(f"""
                    SELECT sv.*, s.agent_id, s.scan_timestamp
                    FROM scan_vulnerabilities sv
                    JOIN scans s ON sv.scan_id = s.scan_id
                    {where_clause}
                    ORDER BY sv.created_at DESC
                    LIMIT 1000
                """, *params)
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to search vulnerabilities: {e}")
            return []