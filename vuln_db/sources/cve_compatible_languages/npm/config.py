"""
npm Security Advisories Configuration

OBJECTIVE: Configure fetching parameters for npm/JavaScript package vulnerabilities

INTEGRATION: Used by NpmFetcher class and orchestration system
LOADED BY: orchestration/source_manager.py from interest_datasource_final.json
"""

NPM_CONFIG = {
    'source_name': 'npm_security_advisories',
    'display_name': 'npm Security Advisories',
    'api_url': 'https://api.github.com/advisories',
    'npm_api_url': 'https://registry.npmjs.org/-/npm/vuln',
    'category': 'cve_compatible_languages',
    'priority': 6,
    'status': 'working',
    
    # Fetching configuration
    'fetch_frequency_hours': 12,  # More frequent for package updates
    'timeout_seconds': 30,
    'retry_attempts': 3,
    'retry_delay_seconds': 5,
    
    # Rate limiting - GitHub API limits
    'rate_limit_per_hour': 5000,  # GitHub API limit
    'concurrent_requests': 2,
    
    # Data processing
    'batch_size': 100,
    'max_pages': 5,  # Limit GitHub API pagination
    'enable_incremental': True,
    
    # Quality settings
    'data_quality_threshold': 6,
    'required_fields': ['ghsa_id', 'summary'],
    'prefer_cve_over_ghsa': True,
    
    # Integration settings
    'duplicate_resolution_priority': 6,  # Medium-high priority for package data
    'source_specific_fields': [
        'github_advisory_id',
        'npm_packages',
        'cvss_score',
        'severity'
    ],
    
    # API configuration
    'github_token': None,  # Optional GitHub token for higher rate limits
    'ecosystems': ['npm'],
    'include_withdrawn': False
}