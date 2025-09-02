#!/usr/bin/env python3
"""
Simplified Database Initialization Script

Initializes the vulnerability database schema using the consolidated configuration.
Designed for local database setup and development.
"""

import asyncio
import logging
import argparse
import sys
from pathlib import Path

# Add project root to path for imports
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from config.schemas_and_config import get_database_config, get_database_connection

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SimpleDatabaseInitializer:
    """Simplified database initialization for local setup"""
    
    def __init__(self, environment: str = 'development'):
        self.environment = environment
        self.config = get_database_config(environment)
        self.schema_file = project_root / 'config' / 'schemas_and_config' / 'vulnerability_schema.sql'
    
    async def initialize_database(self) -> dict:
        """Initialize database with schema"""
        results = {
            'success': False,
            'tables_created': [],
            'errors': []
        }
        
        try:
            logger.info(f"🚀 Initializing database for environment: {self.environment}")
            
            # Test connection
            conn = await get_database_connection(environment=self.environment)
            logger.info("✅ Database connection successful")
            
            # Load and execute schema if it exists
            if self.schema_file.exists():
                await self._execute_schema(conn, results)
            else:
                logger.warning(f"⚠️  Schema file not found: {self.schema_file}")
                await self._create_basic_tables(conn, results)
            
            await conn.close()
            results['success'] = len(results['errors']) == 0
            
            if results['success']:
                logger.info("🎉 Database initialization completed successfully")
                logger.info(f"   Tables created: {len(results['tables_created'])}")
            else:
                logger.error("❌ Database initialization failed")
                
        except Exception as e:
            error_msg = f"Database initialization failed: {e}"
            logger.error(error_msg)
            results['errors'].append(error_msg)
        
        return results
    
    async def _execute_schema(self, conn, results: dict):
        """Execute SQL schema file"""
        try:
            logger.info("📋 Loading schema from SQL file...")
            schema_sql = self.schema_file.read_text()
            
            # Split into statements and execute
            statements = [stmt.strip() for stmt in schema_sql.split(';') if stmt.strip()]
            
            for stmt in statements:
                if stmt.upper().startswith('CREATE TABLE'):
                    table_name = self._extract_table_name(stmt)
                    try:
                        await conn.execute(stmt)
                        if table_name:
                            results['tables_created'].append(table_name)
                            logger.info(f"   ✅ Created table: {table_name}")
                    except Exception as e:
                        if "already exists" in str(e).lower():
                            logger.info(f"   ⚠️  Table already exists: {table_name}")
                        else:
                            results['errors'].append(f"Failed to create table {table_name}: {e}")
                else:
                    # Execute other statements (indexes, constraints, etc.)
                    try:
                        await conn.execute(stmt)
                    except Exception as e:
                        if "already exists" not in str(e).lower():
                            results['errors'].append(f"Statement failed: {e}")
                            
        except Exception as e:
            results['errors'].append(f"Schema execution failed: {e}")
    
    async def _create_basic_tables(self, conn, results: dict):
        """Create basic tables if schema file is not available"""
        logger.info("📋 Creating basic database tables...")
        
        basic_tables = [
            """
            CREATE TABLE IF NOT EXISTS vulnerability_sources (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL UNIQUE,
                description TEXT,
                url VARCHAR(500),
                active BOOLEAN DEFAULT true,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS cves (
                id VARCHAR(20) PRIMARY KEY,
                description TEXT,
                severity VARCHAR(20),
                score DECIMAL(3,1),
                published_date TIMESTAMP,
                modified_date TIMESTAMP,
                source_id INTEGER REFERENCES vulnerability_sources(id),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS pipeline_executions (
                id SERIAL PRIMARY KEY,
                source_name VARCHAR(100),
                status VARCHAR(50),
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                records_processed INTEGER DEFAULT 0,
                errors_count INTEGER DEFAULT 0,
                execution_log TEXT
            )
            """
        ]
        
        table_names = ['vulnerability_sources', 'cves', 'pipeline_executions']
        
        for i, sql in enumerate(basic_tables):
            try:
                await conn.execute(sql)
                results['tables_created'].append(table_names[i])
                logger.info(f"   ✅ Created table: {table_names[i]}")
            except Exception as e:
                if "already exists" in str(e).lower():
                    logger.info(f"   ⚠️  Table already exists: {table_names[i]}")
                else:
                    results['errors'].append(f"Failed to create table {table_names[i]}: {e}")
    
    def _extract_table_name(self, sql: str) -> str:
        """Extract table name from CREATE TABLE statement"""
        try:
            parts = sql.upper().split()
            table_idx = parts.index('TABLE')
            if table_idx + 1 < len(parts):
                table_name = parts[table_idx + 1]
                # Handle "IF NOT EXISTS" case
                if table_name == 'IF':
                    table_name = parts[table_idx + 4] if len(parts) > table_idx + 4 else ''
                # Clean up table name
                return table_name.replace('(', '').replace(',', '').strip()
        except:
            pass
        return ''
    
    async def test_connection(self) -> dict:
        """Test database connection"""
        try:
            conn = await get_database_connection(environment=self.environment)
            version = await conn.fetchval('SELECT version()')
            await conn.close()
            
            return {
                'success': True,
                'version': version,
                'environment': self.environment,
                'config': {k: v if k != 'password' else '***' for k, v in self.config.items()}
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'environment': self.environment
            }

async def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(description='Simplified Database Initializer')
    parser.add_argument('--environment', '-e', default='development', 
                       choices=['development', 'testing', 'container', 'production'],
                       help='Database environment')
    parser.add_argument('--test-only', action='store_true', help='Only test connection')
    parser.add_argument('--force', action='store_true', help='Force initialization even if tables exist')
    
    args = parser.parse_args()
    
    initializer = SimpleDatabaseInitializer(args.environment)
    
    try:
        if args.test_only:
            logger.info("🔍 Testing database connection...")
            result = await initializer.test_connection()
            
            if result['success']:
                logger.info("✅ Connection test successful")
                logger.info(f"   Environment: {result['environment']}")
                logger.info(f"   PostgreSQL Version: {result['version']}")
            else:
                logger.error("❌ Connection test failed")
                logger.error(f"   Error: {result['error']}")
                return 1
        else:
            result = await initializer.initialize_database()
            
            if result['success']:
                logger.info("✅ Database initialization successful")
                if result['tables_created']:
                    logger.info(f"   Tables: {', '.join(result['tables_created'])}")
            else:
                logger.error("❌ Database initialization failed")
                for error in result['errors']:
                    logger.error(f"   Error: {error}")
                return 1
        
        return 0
        
    except Exception as e:
        logger.error(f"Initialization failed: {e}")
        return 1

if __name__ == "__main__":
    exit(asyncio.run(main()))