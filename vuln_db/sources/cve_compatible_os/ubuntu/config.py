"""
Ubuntu Security Notices Configuration

OBJECTIVE: Configure fetching parameters and API settings for Ubuntu Security Notices

INTEGRATION: Used by UbuntuFetcher class and orchestration system
LOADED BY: orchestration/source_manager.py from interest_datasource_final.json
"""

UBUNTU_CONFIG = {
    'source_name': 'ubuntu_security_notices',
    'display_name': 'Ubuntu Security Notices',
    'api_url': 'https://ubuntu.com/security/notices',
    'rss_url': 'https://ubuntu.com/security/notices/rss.xml',
    'category': 'cve_compatible_os',
    'priority': 8,
    'status': 'working',
    
    # Fetching configuration
    'fetch_frequency_hours': 24,
    'timeout_seconds': 30,
    'retry_attempts': 3,
    'retry_delay_seconds': 5,
    
    # Rate limiting
    'rate_limit_per_hour': 100,  # Conservative rate limit for scraping
    'concurrent_requests': 2,
    
    # Data processing
    'batch_size': 50,  # Limit to recent 50 notices
    'enable_incremental': True,
    'max_notices_per_fetch': 50,
    
    # Quality settings
    'data_quality_threshold': 7,
    'required_fields': ['cve_id', 'usn_id'],
    
    # Integration settings
    'duplicate_resolution_priority': 8,  # High priority for OS-specific data
    'source_specific_fields': [
        'ubuntu_usn_id',
        'ubuntu_notice_url',
        'affected_packages',
        'ubuntu_releases'
    ],
    
    # Parsing options
    'use_rss_first': True,
    'fallback_to_html': True,
    'extract_package_details': True
}