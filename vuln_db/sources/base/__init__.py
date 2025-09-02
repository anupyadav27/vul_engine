"""
Base Infrastructure for Multi-Source Vulnerability System

This module provides the foundational classes and utilities that all vulnerability sources use.
All source-specific implementations inherit from these base classes to ensure consistency.

Key Components:
- BaseFetcher: Abstract interface for data fetching
- BaseParser: Common parsing utilities
- DataNormalizer: Converts source formats to common schema
- CommonLoader: Universal database loader
- DuplicateManager: Handles cross-source duplicates

Dependencies:
- ../db_schema/vulnerability_schema.py: Database schema
- ../nvd/database.py: Database operations (reused)
- interest_datasource_final.json: Source configurations

Related Files:
- All source implementations in ../sources/* inherit from these classes
- orchestration/source_manager.py uses these for unified processing
"""

from .base_fetcher import BaseFetcher
from .base_parser import BaseParser  
from .data_normalizer import DataNormalizer
from .common_loader import CommonLoader
from .duplicate_manager import DuplicateManager
from .exceptions import VulnSourceException, FetchException, ParseException

__all__ = [
    'BaseFetcher',
    'BaseParser', 
    'DataNormalizer',
    'CommonLoader',
    'DuplicateManager',
    'VulnSourceException',
    'FetchException', 
    'ParseException'
]

# Version information
__version__ = '1.0.0'
__author__ = 'Multi-Source Vulnerability Team'
__description__ = 'Base infrastructure for 49-source vulnerability intelligence system'