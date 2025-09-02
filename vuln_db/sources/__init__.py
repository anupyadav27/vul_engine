"""
Multi-Source Vulnerability System

This module implements a comprehensive vulnerability data collection system that aggregates
data from 49 different sources across 5 categories. All sources are unified through a
common schema and database structure.

Architecture:
- base/: Common infrastructure used by all sources
- cve_compatible_os/: Operating system vulnerability sources (11 sources)
- cve_compatible_languages/: Programming language package sources (5 sources)  
- advisory_cloud_bulletins/: Cloud provider security bulletins (5 sources)
- database_vendor_advisories/: Database vendor security advisories (6 sources)
- middleware_vendor_advisories/: Middleware security advisories (7 sources)

All sources follow the same pattern:
1. Fetcher: Retrieves raw data from source
2. Parser: Converts source format to common schema
3. Loader: Stores data with source tracking

Dependencies:
- ../db_schema/vulnerability_schema.py: Enhanced database schema with source tracking
- ../nvd/database.py: Database operations (enhanced for multi-source)
- ../interest_datasource_final.json: Source configurations and priorities

Usage:
    from vuln_db.sources.base import CommonLoader, DataNormalizer
    from vuln_db.sources.cve_compatible_os.debian import DebianFetcher, DebianParser
    
    # Each source can be used independently or via orchestration system
"""

# Import base infrastructure for common use
from .base import (
    BaseFetcher, 
    BaseParser, 
    DataNormalizer, 
    CommonLoader, 
    DuplicateManager,
    VulnSourceException
)

__version__ = "1.0.0"
__all__ = [
    'BaseFetcher',
    'BaseParser', 
    'DataNormalizer',
    'CommonLoader',
    'DuplicateManager', 
    'VulnSourceException'
]