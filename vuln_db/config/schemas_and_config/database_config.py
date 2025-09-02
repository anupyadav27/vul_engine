#!/usr/bin/env python3
"""
Database Configuration Module

Handles database connection configuration for different environments.
Supports PostgreSQL connections with environment-specific settings.
Reads configuration from database_settings.json as the single source of truth.
"""

import os
import json
from typing import Dict, Any, Optional
import asyncpg
from pathlib import Path

class DatabaseConfigManager:
    """Manages database configuration with multiple sources"""
    
    def __init__(self):
        self.config_file = Path(__file__).parent / "database_settings.json"
        self._cached_config = None
    
    def _load_json_config(self) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        if self._cached_config is not None:
            return self._cached_config
            
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    self._cached_config = json.load(f)
                    return self._cached_config
            else:
                raise FileNotFoundError(f"Configuration file not found: {self.config_file}")
        except Exception as e:
            raise RuntimeError(f"Failed to load database configuration: {e}")
    
    def get_database_config(self, environment: str = None) -> Dict[str, Any]:
        """
        Get database configuration for specified environment
        
        Args:
            environment: Environment name (development, testing, container, production)
                        If None, tries to read from ENVIRONMENT or defaults to development
            
        Returns:
            Dictionary with database connection parameters
        """
        # Determine environment
        if not environment:
            environment = os.getenv('ENVIRONMENT', 'development')
        
        # Load configurations
        all_configs = self._load_json_config()
        
        # Get base config
        if environment in all_configs:
            config = all_configs[environment].copy()
        else:
            # Fallback to development config
            config = all_configs.get('development', {}).copy()
        
        # Normalize field names (JSON uses 'username', code expects 'user')
        if 'username' in config:
            config['user'] = config.pop('username')
        
        # Add pool size mapping from JSON settings
        if 'max_connections' in config:
            config['pool_size'] = config['max_connections']
        
        # Override with environment variables if they exist
        env_mappings = {
            'DB_HOST': 'host',
            'DB_PORT': 'port',
            'DB_NAME': 'database',
            'DB_USER': 'user',
            'DB_PASSWORD': 'password',
            'DB_POOL_SIZE': 'pool_size',
            'DB_MAX_CONNECTIONS': 'max_connections'
        }
        
        for env_var, config_key in env_mappings.items():
            env_value = os.getenv(env_var)
            if env_value:
                if config_key in ['port', 'pool_size', 'max_connections', 'min_connections']:
                    config[config_key] = int(env_value)
                else:
                    config[config_key] = env_value
        
        # Special handling for password - try environment-specific variables
        if not config.get('password') or config.get('password') == 'change_this_password_in_production':
            password_env_vars = [
                f'DB_PASSWORD_{environment.upper()}',
                'DB_PASSWORD',
                f'POSTGRES_PASSWORD_{environment.upper()}',
                'POSTGRES_PASSWORD'
            ]
            
            for env_var in password_env_vars:
                password = os.getenv(env_var)
                if password:
                    config['password'] = password
                    break
        
        # Validate required fields
        required_fields = ['host', 'port', 'database', 'user', 'password']
        missing_fields = [field for field in required_fields if not config.get(field)]
        
        if missing_fields:
            raise ValueError(f"Missing required database configuration fields: {missing_fields}")
        
        return config

# Global instance
db_config_manager = DatabaseConfigManager()

# Convenience functions for backward compatibility
def get_database_config(environment: str = None) -> Dict[str, Any]:
    """Get database configuration for specified environment"""
    return db_config_manager.get_database_config(environment)

async def get_database_connection(config: Dict[str, Any] = None, environment: str = None) -> asyncpg.Connection:
    """
    Get database connection using provided config or environment
    
    Args:
        config: Database configuration dictionary
        environment: Environment name if config not provided
        
    Returns:
        AsyncPG connection object
    """
    if not config:
        config = get_database_config(environment)
    
    return await asyncpg.connect(
        host=config['host'],
        port=config['port'],
        database=config['database'],
        user=config['user'],
        password=config['password']
    )

async def create_database_pool(config: Dict[str, Any] = None, environment: str = None) -> asyncpg.Pool:
    """
    Create database connection pool
    
    Args:
        config: Database configuration dictionary
        environment: Environment name if config not provided
        
    Returns:
        AsyncPG connection pool
    """
    if not config:
        config = get_database_config(environment)
    
    min_size = config.get('min_connections', 1)
    max_size = config.get('max_connections', config.get('pool_size', 10))
    
    return await asyncpg.create_pool(
        host=config['host'],
        port=config['port'],
        database=config['database'],
        user=config['user'],
        password=config['password'],
        min_size=min_size,
        max_size=max_size
    )

def get_database_url(config: Dict[str, Any] = None, environment: str = None) -> str:
    """
    Get database URL for tools that need connection strings
    
    Args:
        config: Database configuration dictionary
        environment: Environment name if config not provided
        
    Returns:
        PostgreSQL connection URL
    """
    if not config:
        config = get_database_config(environment)
    
    return f"postgresql://{config['user']}:{config['password']}@{config['host']}:{config['port']}/{config['database']}"

async def test_database_connection(environment: str = None) -> Dict[str, Any]:
    """
    Test database connection for specified environment
    
    Args:
        environment: Environment to test
        
    Returns:
        Dictionary with test results
    """
    result = {
        'success': False,
        'environment': environment or 'default',
        'config': {},
        'connection_time': None,
        'database_version': None,
        'error': None
    }
    
    try:
        import time
        start_time = time.time()
        
        config = get_database_config(environment)
        result['config'] = {k: v if k != 'password' else '***' for k, v in config.items()}
        
        conn = await get_database_connection(config)
        result['connection_time'] = time.time() - start_time
        
        # Get database version
        version = await conn.fetchval('SELECT version()')
        result['database_version'] = version
        
        await conn.close()
        result['success'] = True
        
    except Exception as e:
        result['error'] = str(e)
    
    return result

def save_config_template(output_path: str = None):
    """
    Save a configuration template file for reference
    
    Args:
        output_path: Path to save the template file
    """
    if not output_path:
        output_path = str(Path(__file__).parent / "database_config_template.env")
    
    template_content = """# Database Configuration Template
# Copy this file and set actual values for your environment

# Environment selection (development, testing, container, production)
ENVIRONMENT=development

# Database connection settings
DB_HOST=localhost
DB_PORT=5432
DB_NAME=vulnerability_db
DB_USER=vuln_user
DB_PASSWORD=your_password_here

# Connection pool settings
DB_POOL_SIZE=10
DB_MAX_CONNECTIONS=20

# Environment-specific password variables (optional)
# DB_PASSWORD_DEVELOPMENT=dev_password
# DB_PASSWORD_TESTING=test_password
# DB_PASSWORD_CONTAINER=container_password
# DB_PASSWORD_PRODUCTION=prod_password
"""
    
    with open(output_path, 'w') as f:
        f.write(template_content)
    
    print(f"Database configuration template saved to: {output_path}")

if __name__ == "__main__":
    import asyncio
    import argparse
    
    parser = argparse.ArgumentParser(description='Database Configuration Tool')
    parser.add_argument('--test', action='store_true', help='Test database connection')
    parser.add_argument('--environment', '-e', help='Environment to test')
    parser.add_argument('--save-template', action='store_true', help='Save configuration template')
    parser.add_argument('--template-path', help='Path to save template file')
    parser.add_argument('--show-config', action='store_true', help='Show current configuration')
    
    args = parser.parse_args()
    
    if args.save_template:
        save_config_template(args.template_path)
    elif args.show_config:
        config = get_database_config(args.environment)
        config_safe = {k: v if k != 'password' else '***' for k, v in config.items()}
        print(f"Configuration for environment '{args.environment or 'default'}':")
        for key, value in config_safe.items():
            print(f"  {key}: {value}")
    elif args.test:
        async def test():
            result = await test_database_connection(args.environment)
            print(f"Connection test: {'SUCCESS' if result['success'] else 'FAILED'}")
            print(f"Environment: {result['environment']}")
            print(f"Connection time: {result['connection_time']:.3f}s" if result['connection_time'] else "N/A")
            print(f"Database version: {result['database_version']}" if result['database_version'] else "N/A")
            if result['error']:
                print(f"Error: {result['error']}")
        
        asyncio.run(test())
    else:
        parser.print_help()