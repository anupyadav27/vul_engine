"""
Source Configuration Management System

OBJECTIVE:
Centralized configuration management for all 49 vulnerability sources.
Loads configurations from interest_datasource_final.json and provides
runtime configuration management, validation, and dynamic updates.

INTEGRATION WITH LOCAL CODES:
- Reads from ../interest_datasource_final.json
- Provides configurations to all source fetchers and parsers
- Integrates with orchestration system for runtime management

INTEGRATION ACROSS COMMON CODES:
- Used by all BaseFetcher implementations for API settings
- Provides rate limiting and timeout configurations
- Manages source priority and duplicate resolution settings

INTEGRATION WITH OVERALL PROGRAM:
- Central configuration point for entire multi-source system
- Enables dynamic configuration updates without restarts
- Provides validation and error checking for all source configs
"""

import json
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class SourceStatus(Enum):
    """Source operational status"""
    WORKING = "working"
    NOT_TESTED = "not_tested"
    ERROR = "error"
    ERROR_404 = "error_404"
    CSMP_COVERED = "csmp_covered"
    ALTERNATIVE_AVAILABLE = "alternative_available"

class SourceCategory(Enum):
    """Source categories from interest_datasource_final.json"""
    CVE_COMPATIBLE_OS = "cve_compatible_os"
    CVE_COMPATIBLE_LANGUAGES = "cve_compatible_languages"
    ADVISORY_CLOUD_BULLETINS = "advisory_cloud_bulletins"
    DATABASE_VENDOR_ADVISORIES = "database_vendor_advisories"
    MIDDLEWARE_VENDOR_ADVISORIES = "middleware_vendor_advisories"

@dataclass
class SourceConfig:
    """Configuration for a single vulnerability source"""
    name: str
    category: str
    url: str
    status: SourceStatus
    priority: int
    response_time: Optional[float]
    last_tested: Optional[str]
    vulnerability_engine_priority: str
    enhancement_needed: bool
    notes: str
    
    # Runtime configuration
    fetch_frequency_hours: int = 24
    timeout_seconds: int = 30
    retry_attempts: int = 3
    rate_limit_per_hour: int = 1000
    enable_incremental: bool = True

class SourceConfigManager:
    """
    Manages configuration for all vulnerability sources
    
    RESPONSIBILITIES:
    1. Load configurations from interest_datasource_final.json
    2. Provide runtime configuration management
    3. Validate source configurations
    4. Enable dynamic configuration updates
    5. Map sources to their implementations
    """
    
    def __init__(self, config_path: str = None):
        if config_path is None:
            config_path = Path(__file__).parent.parent / "interest_datasource_final.json"
        
        self.config_path = Path(config_path)
        self.source_configs: Dict[str, SourceConfig] = {}
        self.category_mappings: Dict[SourceCategory, List[str]] = {}
        self.priority_mappings: Dict[int, List[str]] = {}
        
    def load_configurations(self) -> Dict[str, SourceConfig]:
        """
        Load all source configurations from interest_datasource_final.json
        
        STEPS:
        1. Read and parse interest_datasource_final.json
        2. Extract vulnerability_engine_sources section
        3. Create SourceConfig objects for each source
        4. Build category and priority mappings
        5. Validate configurations
        
        Returns:
            Dictionary mapping source names to SourceConfig objects
        """
        logger.info(f"Loading source configurations from {self.config_path}")
        
        try:
            with open(self.config_path, 'r') as f:
                data = json.load(f)
            
            # Extract vulnerability engine sources
            vuln_sources = data.get('vulnerability_engine_sources', {})
            
            # Map categories to enum values
            category_mapping = {
                'cve_compatible_os': SourceCategory.CVE_COMPATIBLE_OS,
                'cve_compatible_languages': SourceCategory.CVE_COMPATIBLE_LANGUAGES,
                'advisory_cloud_bulletins': SourceCategory.ADVISORY_CLOUD_BULLETINS,
                'database_vendor_advisories': SourceCategory.DATABASE_VENDOR_ADVISORIES,
                'middleware_vendor_advisories': SourceCategory.MIDDLEWARE_VENDOR_ADVISORIES
            }
            
            # Process each category
            for category_key, sources in vuln_sources.items():
                if category_key not in category_mapping:
                    logger.warning(f"Unknown category: {category_key}")
                    continue
                
                category = category_mapping[category_key]
                category_sources = []
                
                for source_data in sources:
                    source_config = self._create_source_config(source_data, category_key)
                    if source_config:
                        self.source_configs[source_config.name] = source_config
                        category_sources.append(source_config.name)
                
                self.category_mappings[category] = category_sources
            
            # Build priority mappings
            self._build_priority_mappings()
            
            logger.info(f"Loaded {len(self.source_configs)} source configurations")
            logger.info(f"Categories: {list(self.category_mappings.keys())}")
            
            return self.source_configs
            
        except Exception as e:
            logger.error(f"Failed to load source configurations: {e}")
            raise
    
    def _create_source_config(self, source_data: Dict[str, Any], category: str) -> Optional[SourceConfig]:
        """Create SourceConfig from JSON data"""
        try:
            # Extract basic information
            name = source_data.get('name', '').lower().replace(' ', '_')
            if not name:
                logger.warning("Source missing name, skipping")
                return None
            
            # Map status string to enum
            status_str = source_data.get('status', 'not_tested')
            try:
                status = SourceStatus(status_str)
            except ValueError:
                logger.warning(f"Invalid status '{status_str}' for source {name}")
                status = SourceStatus.NOT_TESTED
            
            # Determine priority based on category and vulnerability_engine_priority
            priority = self._calculate_priority(
                category, 
                source_data.get('vulnerability_engine_priority', 'low')
            )
            
            # Create configuration
            source_config = SourceConfig(
                name=name,
                category=category,
                url=source_data.get('url', ''),
                status=status,
                priority=priority,
                response_time=source_data.get('response_time'),
                last_tested=source_data.get('last_tested'),
                vulnerability_engine_priority=source_data.get('vulnerability_engine_priority', 'low'),
                enhancement_needed=source_data.get('enhancement_needed', False),
                notes=source_data.get('notes', ''),
                
                # Set default runtime configuration based on category
                **self._get_default_runtime_config(category, source_data)
            )
            
            return source_config
            
        except Exception as e:
            logger.error(f"Failed to create source config: {e}")
            return None
    
    def _calculate_priority(self, category: str, vuln_priority: str) -> int:
        """
        Calculate numerical priority for source
        
        PRIORITY SYSTEM:
        - cve_compatible_os: 8-10 (highest, OS vulnerabilities)
        - cve_compatible_languages: 6-8 (high, package vulnerabilities)
        - advisory_cloud_bulletins: 4-6 (medium, cloud advisories)
        - database_vendor_advisories: 3-5 (medium-low, database vendors)
        - middleware_vendor_advisories: 2-4 (low, middleware vendors)
        
        Within category, vuln_priority adds modifier:
        - high: +2
        - medium: +1
        - low: +0
        """
        base_priorities = {
            'cve_compatible_os': 8,
            'cve_compatible_languages': 6,
            'advisory_cloud_bulletins': 4,
            'database_vendor_advisories': 3,
            'middleware_vendor_advisories': 2
        }
        
        priority_modifiers = {
            'high': 2,
            'medium': 1,
            'low': 0
        }
        
        base = base_priorities.get(category, 2)
        modifier = priority_modifiers.get(vuln_priority, 0)
        
        return min(base + modifier, 10)  # Cap at 10
    
    def _get_default_runtime_config(self, category: str, source_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get default runtime configuration based on category"""
        # High-frequency categories need more frequent updates
        high_frequency_categories = ['cve_compatible_os', 'cve_compatible_languages']
        
        return {
            'fetch_frequency_hours': 12 if category in high_frequency_categories else 24,
            'timeout_seconds': 30,
            'retry_attempts': 3,
            'rate_limit_per_hour': 1000,
            'enable_incremental': True
        }
    
    def _build_priority_mappings(self):
        """Build mappings of priorities to source names"""
        for source_name, config in self.source_configs.items():
            priority = config.priority
            if priority not in self.priority_mappings:
                self.priority_mappings[priority] = []
            self.priority_mappings[priority].append(source_name)
    
    def get_sources_by_category(self, category: SourceCategory) -> List[SourceConfig]:
        """Get all source configurations for a category"""
        source_names = self.category_mappings.get(category, [])
        return [self.source_configs[name] for name in source_names if name in self.source_configs]
    
    def get_sources_by_priority(self, min_priority: int = 0, max_priority: int = 10) -> List[SourceConfig]:
        """Get sources within priority range, ordered by priority (highest first)"""
        sources = []
        
        for priority in sorted(range(min_priority, max_priority + 1), reverse=True):
            if priority in self.priority_mappings:
                for source_name in self.priority_mappings[priority]:
                    if source_name in self.source_configs:
                        sources.append(self.source_configs[source_name])
        
        return sources
    
    def get_working_sources(self) -> List[SourceConfig]:
        """Get only sources with 'working' status"""
        return [
            config for config in self.source_configs.values()
            if config.status == SourceStatus.WORKING
        ]
    
    def get_sources_needing_enhancement(self) -> List[SourceConfig]:
        """Get sources that need enhancement"""
        return [
            config for config in self.source_configs.values()
            if config.enhancement_needed
        ]
    
    def update_source_config(self, source_name: str, updates: Dict[str, Any]) -> bool:
        """Update runtime configuration for a source"""
        if source_name not in self.source_configs:
            logger.error(f"Source {source_name} not found")
            return False
        
        try:
            config = self.source_configs[source_name]
            
            # Update allowed fields
            allowed_updates = [
                'fetch_frequency_hours', 'timeout_seconds', 'retry_attempts',
                'rate_limit_per_hour', 'enable_incremental'
            ]
            
            for key, value in updates.items():
                if key in allowed_updates:
                    setattr(config, key, value)
                else:
                    logger.warning(f"Cannot update field {key} for source {source_name}")
            
            logger.info(f"Updated configuration for source {source_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update source config: {e}")
            return False
    
    def validate_configurations(self) -> Dict[str, List[str]]:
        """
        Validate all source configurations
        
        Returns:
            Dictionary with validation results:
            - 'errors': List of critical errors
            - 'warnings': List of warnings
        """
        errors = []
        warnings = []
        
        for source_name, config in self.source_configs.items():
            # Check required fields
            if not config.url:
                errors.append(f"Source {source_name} missing URL")
            
            if not config.name:
                errors.append(f"Source {source_name} missing name")
            
            # Check status consistency
            if config.status == SourceStatus.WORKING and config.response_time is None:
                warnings.append(f"Source {source_name} marked as working but no response time")
            
            if config.enhancement_needed and config.status == SourceStatus.WORKING:
                warnings.append(f"Source {source_name} working but marked for enhancement")
            
            # Check priority ranges
            if config.priority < 1 or config.priority > 10:
                warnings.append(f"Source {source_name} has unusual priority: {config.priority}")
        
        return {
            'errors': errors,
            'warnings': warnings
        }
    
    def get_configuration_summary(self) -> Dict[str, Any]:
        """Get summary of all configurations"""
        total_sources = len(self.source_configs)
        working_sources = len(self.get_working_sources())
        enhancement_needed = len(self.get_sources_needing_enhancement())
        
        category_counts = {
            category.value: len(sources) 
            for category, sources in self.category_mappings.items()
        }
        
        priority_distribution = {
            priority: len(sources)
            for priority, sources in self.priority_mappings.items()
        }
        
        return {
            'total_sources': total_sources,
            'working_sources': working_sources,
            'enhancement_needed': enhancement_needed,
            'category_distribution': category_counts,
            'priority_distribution': priority_distribution,
            'config_file': str(self.config_path)
        }
    
    def get_database_config(self, environment: str = None) -> Dict[str, Any]:
        """Get database configuration for sources to use - delegates to consolidated config"""
        try:
            from .schemas_and_config import get_database_config
            
            # Simply delegate to the consolidated database config
            db_config = get_database_config(environment)
            
            # Return in the format expected by sources (with 'username' field)
            return {
                'host': db_config['host'],
                'port': db_config['port'],
                'database': db_config['database'],
                'username': db_config['user'],  # Sources expect 'username'
                'password': db_config['password'],
                'min_connections': db_config.get('min_connections', 5),
                'max_connections': 20,
                'connection_timeout': db_config.get('connection_timeout', 30),
                'query_timeout': db_config.get('query_timeout', 60),
                'ssl_mode': db_config.get('ssl_mode', 'prefer'),
                'schema_name': db_config.get('schema_name', 'public')
            }
        except ImportError as e:
            logger.error(f"Could not import consolidated database config: {e}")
            raise ImportError("Consolidated database config is required but not available")
    
    async def sync_sources_to_database(self, environment: str = None) -> Dict[str, Any]:
        """
        Sync source configurations to the vulnerability_sources table
        Uses consolidated database configuration.
        """
        try:
            from .schemas_and_config import get_database_connection, get_database_config
            
            # Use consolidated database config
            db_config = get_database_config(environment)
            self.load_configurations()
            
            sync_results = {
                'success': False,
                'sources_processed': 0,
                'sources_inserted': 0,
                'sources_updated': 0,
                'sources_skipped': 0,
                'errors': []
            }
            
            conn = await get_database_connection(config=db_config)
            
            try:
                for source_name, config in self.source_configs.items():
                    try:
                        # Check if source already exists
                        existing = await conn.fetchrow(
                            "SELECT id FROM vulnerability_sources WHERE name = $1",
                            source_name
                        )
                        
                        if existing:
                            # Update existing source
                            await conn.execute("""
                                UPDATE vulnerability_sources SET
                                    description = $2,
                                    url = $3,
                                    active = $4,
                                    updated_at = CURRENT_TIMESTAMP
                                WHERE name = $1
                            """, 
                                source_name,
                                f"{config.category} - {config.notes}",
                                config.url,
                                config.status == SourceStatus.WORKING
                            )
                            sync_results['sources_updated'] += 1
                        else:
                            # Insert new source
                            await conn.execute("""
                                INSERT INTO vulnerability_sources (
                                    name, description, url, active
                                ) VALUES ($1, $2, $3, $4)
                            """,
                                source_name,
                                f"{config.category} - {config.notes}",
                                config.url,
                                config.status == SourceStatus.WORKING
                            )
                            sync_results['sources_inserted'] += 1
                        
                        sync_results['sources_processed'] += 1
                        
                    except Exception as e:
                        logger.error(f"Failed to sync source {source_name}: {e}")
                        sync_results['errors'].append(f"Source {source_name}: {str(e)}")
                        sync_results['sources_skipped'] += 1
                
                sync_results['success'] = len(sync_results['errors']) == 0
                logger.info(f"Source sync completed: {sync_results['sources_processed']} processed")
                
            finally:
                await conn.close()
                
            return sync_results
                
        except Exception as e:
            logger.error(f"Database source sync failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'sources_processed': 0,
                'sources_inserted': 0,
                'sources_updated': 0,
                'sources_skipped': 0,
                'errors': [str(e)]
            }

# Export for use by orchestration system
__all__ = ['SourceConfigManager', 'SourceConfig', 'SourceCategory', 'SourceStatus']

# Convenience functions for specific sources
def get_debian_config() -> Dict[str, Any]:
    """Get Debian Security Tracker configuration"""
    manager = SourceConfigManager()
    configs = manager.load_configurations()
    
    # Find debian config
    for name, config in configs.items():
        if 'debian' in name.lower():
            return {
                'name': config.name,
                'url': config.url,
                'category': config.category,
                'priority': config.priority,
                'status': config.status.value,
                'timeout_seconds': config.timeout_seconds,
                'retry_attempts': config.retry_attempts,
                'database': manager.get_database_config()
            }
    
    # Default Debian config if not found
    return {
        'name': 'debian_security_tracker',
        'url': 'https://security-tracker.debian.org/tracker/data/json',
        'category': 'cve_compatible_os',
        'priority': 8,
        'status': 'working',
        'timeout_seconds': 30,
        'retry_attempts': 3,
        'database': manager.get_database_config()
    }

def get_database_config_for_sources(environment: str = None) -> Dict[str, Any]:
    """
    Get database configuration specifically formatted for source fetchers
    
    This function provides database connection details that vulnerability
    sources can use to store their data. Now uses consolidated config only.
    """
    manager = SourceConfigManager()
    return manager.get_database_config(environment)