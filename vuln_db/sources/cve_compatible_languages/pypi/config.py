"""
PyPI Security Advisories Configuration

OBJECTIVE: Configure fetching parameters for PyPI/Python package vulnerabilities

INTEGRATION: Used by PyPIFetcher class and orchestration system
LOADED BY: orchestration/source_manager.py from interest_datasource_final.json
"""

PYPI_CONFIG = {
    'source_name': 'pypi_security_advisories',
    'display_name': 'PyPI Security Advisories',
    'osv_api_url': 'https://api.osv.dev/v1/query',
    'github_api_url': 'https://api.github.com/advisories',
    'category': 'cve_compatible_languages',
    'priority': 6,
    'status': 'working',
    
    # Fetching configuration
    'fetch_frequency_hours': 12,  # More frequent for package updates
    'timeout_seconds': 30,
    'retry_attempts': 3,
    'retry_delay_seconds': 5,
    
    # Rate limiting
    'rate_limit_per_hour': 1000,  # OSV.dev rate limit
    'concurrent_requests': 2,
    
    # Data processing
    'batch_size': 100,
    'max_osv_pages': 10,  # Limit OSV API pagination
    'max_github_pages': 3,  # Limit GitHub API pagination
    'enable_incremental': True,
    
    # Quality settings
    'data_quality_threshold': 6,
    'required_fields': ['id', 'summary'],
    'prefer_osv_over_github': True,
    
    # Integration settings
    'duplicate_resolution_priority': 6,  # Medium-high priority for package data
    'source_specific_fields': [
        'osv_id',
        'github_advisory_id',
        'pypi_packages',
        'severity_osv',
        'cvss_score'
    ],
    
    # API configuration
    'ecosystems': ['PyPI', 'pip'],
    'include_withdrawn': False,
    'combine_sources': True
}