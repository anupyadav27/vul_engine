"""
Database Schemas and Configuration Package

Consolidated package containing database configuration, schema definitions,
and related files for the vulnerability database system.

This package is used by sources and other components of the vulnerability database.
"""

from .database_config import (
    get_database_config,
    get_database_connection,
    create_database_pool,
    get_database_url,
    test_database_connection,
    save_config_template,
    DatabaseConfigManager,
    db_config_manager
)

__all__ = [
    'get_database_config',
    'get_database_connection', 
    'create_database_pool',
    'get_database_url',
    'test_database_connection',
    'save_config_template',
    'DatabaseConfigManager',
    'db_config_manager'
]