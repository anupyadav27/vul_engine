# Config package for vulnerability database
from .source_config import SourceConfigManager, SourceCategory

def get_debian_config():
    """Get Debian-specific configuration"""
    config_manager = SourceConfigManager()
    config_manager.load_configurations()
    
    # Get Debian source configuration
    debian_sources = config_manager.get_sources_by_category(SourceCategory.CVE_COMPATIBLE_OS)
    debian_config = None
    
    for source in debian_sources:
        if 'debian' in source.name.lower():
            debian_config = source
            break
    
    if not debian_config:
        # Return default Debian configuration
        return {
            'name': 'debian',
            'category': 'cve_compatible_os',
            'display_name': 'Debian Security Tracker',
            'url': 'https://security-tracker.debian.org/tracker/data/json',
            'status': 'working',
            'priority': 8,
            'enhancement_needed': False,
            'engine_type': 'existing',
            'vulnerability_engine_priority': 'high',
            'fetch_frequency_hours': 12,
            'timeout_seconds': 30,
            'retry_attempts': 3,
            'rate_limit_per_hour': 1000,
            'enable_incremental': True
        }
    
    # Convert SourceConfig to dictionary
    return {
        'name': debian_config.name,
        'category': debian_config.category,
        'display_name': 'Debian Security Tracker',
        'url': debian_config.url,
        'status': debian_config.status.value,
        'priority': debian_config.priority,
        'enhancement_needed': debian_config.enhancement_needed,
        'engine_type': 'existing',
        'vulnerability_engine_priority': debian_config.vulnerability_engine_priority,
        'fetch_frequency_hours': debian_config.fetch_frequency_hours,
        'timeout_seconds': debian_config.timeout_seconds,
        'retry_attempts': debian_config.retry_attempts,
        'rate_limit_per_hour': debian_config.rate_limit_per_hour,
        'enable_incremental': debian_config.enable_incremental
    }