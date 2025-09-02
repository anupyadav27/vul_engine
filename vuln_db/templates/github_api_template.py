#!/usr/bin/env python3
"""
GitHub API Data Downloader Template

APPLIES TO SOURCES (4 sources):
- GitHub Security Advisories  
- Go Vulnerability Database (golang.org/x/vuln)
- Rust Security Advisory Database
- Python Security Advisory Database

OBJECTIVE:
Downloads vulnerability data from GitHub repositories and GitHub Security Advisories API.
This template handles both public repositories and the GitHub Security Advisory API.

DATA FORMAT: GitHub API JSON responses
COMPLEXITY: Low-Medium  
IMPLEMENTATION APPROACH: GitHub REST API v4 + GraphQL for advisories

TEMPLATE USAGE:
1. Update GITHUB_TOKEN for authenticated access (higher rate limits)
2. Customize repository/API endpoints for target source
3. Implement GitHub-specific data extraction
4. Update field mappings for GitHub data format
"""

import asyncio
import aiohttp
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
import base64

# Add vuln_db root to Python path
current_dir = Path(__file__).resolve().parent
vuln_db_root = current_dir.parent.parent.parent
sys.path.insert(0, str(vuln_db_root))
sys.path.append(str(vuln_db_root / "config"))

from source_config import get_source_config

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class GitHubVulnerabilityDownloader:
    """
    GitHub API vulnerability downloader for security advisories and vulnerability databases
    
    TEMPLATE INSTRUCTIONS:
    1. Set GITHUB_TOKEN environment variable for authentication
    2. Update repository_owner/repository_name for repo-based sources
    3. Use 'github_advisories' for GitHub Security Advisories API
    4. Customize data extraction for GitHub response format
    """
    
    def __init__(self, source_name: str = "github_source", source_type: str = "repository", 
                 repository_owner: str = "", repository_name: str = ""):
        """
        Initialize GitHub downloader
        
        Args:
            source_name: Name of the vulnerability source
            source_type: 'repository' for repo data, 'advisories' for GitHub Security Advisories API
            repository_owner: GitHub username/organization (for repository type)
            repository_name: Repository name (for repository type)
        """
        # UPDATE: Set your source configuration
        self.source_name = source_name.lower().replace(" ", "_")
        self.source_type = source_type  # 'repository' or 'advisories'
        self.repository_owner = repository_owner
        self.repository_name = repository_name
        
        # GitHub API Configuration
        self.github_token = self._get_github_token()
        self.base_url = "https://api.github.com"
        self.graphql_url = "https://api.github.com/graphql"
        
        # Headers for GitHub API
        self.headers = {
            'User-Agent': 'VulnDB/1.0',
            'Accept': 'application/vnd.github.v3+json',
            'X-GitHub-Api-Version': '2022-11-28'
        }
        
        if self.github_token:
            self.headers['Authorization'] = f'token {self.github_token}'
            logger.info("🔑 Using GitHub token for authenticated requests")
        else:
            logger.warning("⚠️ No GitHub token found - using unauthenticated requests (lower rate limits)")
        
        # GitHub-specific configuration
        self.github_config = {
            # Rate limiting (GitHub allows 5000/hour authenticated, 60/hour unauthenticated)
            'delay_between_requests': 0.5 if self.github_token else 2.0,
            'timeout_seconds': 30,
            'retry_attempts': 3,
            'max_pages': 100,  # Maximum pages to fetch
            'per_page': 100,   # Items per page (max 100 for most endpoints)
            
            # Repository file patterns for vulnerability databases
            'vulnerability_file_patterns': [
                '*.json', '*.yaml', '*.yml', '*.toml',
                'advisories/*.json', 'advisories/*.yaml',
                'database/*.json', 'vulns/*.json'
            ],
            
            # GitHub Security Advisories API settings
            'advisory_severity_levels': ['LOW', 'MODERATE', 'HIGH', 'CRITICAL'],
            'advisory_states': ['PUBLISHED', 'WITHDRAWN']
        }
        
        # Session for connection pooling
        self.session = None
        
        # Statistics tracking
        self.stats = {
            'api_requests': 0,
            'total_vulnerabilities': 0,
            'failed_requests': 0,
            'rate_limit_remaining': 0,
            'data_size_mb': 0,
            'processing_time_seconds': 0
        }
    
    def _get_github_token(self) -> Optional[str]:
        """Get GitHub token from environment"""
        import os
        return os.getenv('GITHUB_TOKEN') or os.getenv('GH_TOKEN')
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            headers=self.headers,
            timeout=aiohttp.ClientTimeout(total=self.github_config['timeout_seconds'])
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def download_and_save_data(self, output_dir: str = None) -> str:
        """Download vulnerability data from GitHub"""
        if output_dir is None:
            output_dir = current_dir / "output" / "data_downloads"
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"🚀 Starting GitHub download for {self.source_name}")
        logger.info(f"📂 Source Type: {self.source_type}")
        
        if self.source_type == "repository":
            logger.info(f"📦 Repository: {self.repository_owner}/{self.repository_name}")
        
        start_time = datetime.utcnow()
        
        try:
            # Download based on source type
            if self.source_type == "repository":
                all_vulnerabilities = await self._download_from_repository()
            elif self.source_type == "advisories":
                all_vulnerabilities = await self._download_github_advisories()
            else:
                raise ValueError(f"Unknown source_type: {self.source_type}")
            
            # Process and analyze data
            processed_data = self._process_vulnerability_data(all_vulnerabilities)
            structure_analysis = self._analyze_data_structure(processed_data)
            
            # Update statistics
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            self.stats['processing_time_seconds'] = processing_time
            self.stats['total_vulnerabilities'] = len(processed_data)
            
            # Generate timestamped filename
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"{self.source_name}_data_{timestamp}.json"
            output_file = output_path / filename
            
            # Calculate file size
            file_size_mb = len(json.dumps(processed_data).encode('utf-8')) / (1024 * 1024)
            self.stats['data_size_mb'] = file_size_mb
            
            # Prepare final data with metadata
            final_data = {
                'metadata': {
                    'download_timestamp': datetime.utcnow().isoformat(),
                    'source_name': self.source_name,
                    'source_type': self.source_type,
                    'github_repository': f"{self.repository_owner}/{self.repository_name}" if self.source_type == "repository" else None,
                    'api_method': 'github_rest_api',
                    'total_vulnerabilities': self.stats['total_vulnerabilities'],
                    'api_requests_made': self.stats['api_requests'],
                    'failed_requests': self.stats['failed_requests'],
                    'rate_limit_remaining': self.stats['rate_limit_remaining'],
                    'processing_time_seconds': processing_time,
                    'data_size_mb': file_size_mb,
                    'content_type': 'application/json',
                    'structure_analysis': structure_analysis,
                    'field_mappings': self._generate_field_mappings(),
                    'github_config': self.github_config
                },
                'data': processed_data
            }
            
            # Save to file
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(final_data, f, indent=2, ensure_ascii=False, default=str)
            
            logger.info(f"✅ GitHub download completed successfully")
            logger.info(f"📁 File: {output_file}")
            logger.info(f"🛡️ Vulnerabilities: {self.stats['total_vulnerabilities']:,}")
            logger.info(f"📡 API Requests: {self.stats['api_requests']:,}")
            logger.info(f"⏱️ Processing Time: {processing_time:.1f}s")
            logger.info(f"💾 Size: {file_size_mb:.2f} MB")
            logger.info(f"🔄 Rate Limit Remaining: {self.stats['rate_limit_remaining']:,}")
            
            return str(output_file)
            
        except Exception as e:
            logger.error(f"❌ Failed to download from GitHub: {e}")
            raise
    
    async def _download_from_repository(self) -> List[Dict[str, Any]]:
        """Download vulnerability data from GitHub repository"""
        logger.info(f"📂 Scanning repository {self.repository_owner}/{self.repository_name}")
        
        all_vulnerabilities = []
        
        # Method 1: Look for vulnerability files in repository
        vulnerability_files = await self._find_vulnerability_files()
        
        for file_info in vulnerability_files:
            logger.info(f"📄 Processing file: {file_info['path']}")
            
            # Download file content
            file_content = await self._download_file_content(file_info['path'])
            if file_content:
                # Parse file based on format
                file_vulnerabilities = self._parse_vulnerability_file(file_content, file_info)
                all_vulnerabilities.extend(file_vulnerabilities)
                
                logger.info(f"✓ Extracted {len(file_vulnerabilities)} vulnerabilities from {file_info['path']}")
        
        # Method 2: Check for releases/tags with vulnerability data
        releases = await self._get_repository_releases()
        for release in releases[:10]:  # Limit to recent releases
            release_vulnerabilities = self._extract_vulnerabilities_from_release(release)
            all_vulnerabilities.extend(release_vulnerabilities)
        
        logger.info(f"✓ Total vulnerabilities found in repository: {len(all_vulnerabilities)}")
        return all_vulnerabilities
    
    async def _download_github_advisories(self) -> List[Dict[str, Any]]:
        """Download from GitHub Security Advisories API"""
        logger.info("🔍 Downloading GitHub Security Advisories")
        
        all_advisories = []
        page = 1
        
        while page <= self.github_config['max_pages']:
            logger.info(f"📄 Downloading advisories page {page}...")
            
            # GitHub Security Advisories API endpoint
            url = f"{self.base_url}/advisories"
            params = {
                'per_page': self.github_config['per_page'],
                'page': page,
                'state': 'published',  # Only published advisories
                'sort': 'updated',     # Sort by updated date
                'direction': 'desc'    # Most recent first
            }
            
            # Make API request
            advisories_data = await self._make_github_request(url, params)
            if not advisories_data or not isinstance(advisories_data, list):
                break
            
            if len(advisories_data) == 0:
                logger.info("🏁 No more advisories found")
                break
            
            all_advisories.extend(advisories_data)
            logger.info(f"✓ Downloaded {len(advisories_data)} advisories from page {page}")
            
            # If we got fewer than requested, we're done
            if len(advisories_data) < self.github_config['per_page']:
                logger.info("🏁 Reached end of advisories")
                break
            
            page += 1
            
            # Rate limiting
            await asyncio.sleep(self.github_config['delay_between_requests'])
        
        logger.info(f"✓ Total GitHub advisories downloaded: {len(all_advisories)}")
        return all_advisories
    
    async def _find_vulnerability_files(self) -> List[Dict[str, Any]]:
        """Find vulnerability files in repository"""
        vulnerability_files = []
        
        # Search common vulnerability directories
        search_paths = [
            '',                    # Root directory
            'advisories',         # Common advisory directory
            'database',           # Common database directory
            'vulns',              # Vulnerability directory
            'security',           # Security directory
            'data'                # Data directory
        ]
        
        for search_path in search_paths:
            try:
                # Get directory contents
                url = f"{self.base_url}/repos/{self.repository_owner}/{self.repository_name}/contents/{search_path}"
                contents = await self._make_github_request(url)
                
                if isinstance(contents, list):
                    for item in contents:
                        if item['type'] == 'file':
                            # Check if file matches vulnerability patterns
                            if self._is_vulnerability_file(item['name'], item['path']):
                                vulnerability_files.append({
                                    'name': item['name'],
                                    'path': item['path'],
                                    'size': item['size'],
                                    'download_url': item['download_url']
                                })
                        elif item['type'] == 'dir' and search_path == '':
                            # Add subdirectories to search (limited depth)
                            if item['name'] in ['advisories', 'database', 'vulns', 'security', 'data']:
                                search_paths.append(item['name'])
                
                # Rate limiting
                await asyncio.sleep(self.github_config['delay_between_requests'])
                
            except Exception as e:
                logger.warning(f"Failed to search path {search_path}: {e}")
                continue
        
        logger.info(f"🔍 Found {len(vulnerability_files)} potential vulnerability files")
        return vulnerability_files[:50]  # Limit to 50 files to avoid overwhelming
    
    def _is_vulnerability_file(self, filename: str, filepath: str) -> bool:
        """Check if file is likely to contain vulnerability data"""
        # Check file extensions
        vulnerability_extensions = ['.json', '.yaml', '.yml', '.toml']
        if not any(filename.endswith(ext) for ext in vulnerability_extensions):
            return False
        
        # Check filename patterns
        vulnerability_keywords = [
            'vulnerability', 'vuln', 'cve', 'advisory', 'security', 
            'alert', 'bulletin', 'ghsa', 'osv'
        ]
        
        filename_lower = filename.lower()
        filepath_lower = filepath.lower()
        
        # Must contain vulnerability-related keywords
        return any(keyword in filename_lower or keyword in filepath_lower 
                  for keyword in vulnerability_keywords)
    
    async def _download_file_content(self, file_path: str) -> Optional[str]:
        """Download content of a file from repository"""
        try:
            url = f"{self.base_url}/repos/{self.repository_owner}/{self.repository_name}/contents/{file_path}"
            file_data = await self._make_github_request(url)
            
            if file_data and 'content' in file_data:
                # Decode base64 content
                content = base64.b64decode(file_data['content']).decode('utf-8')
                return content
            
        except Exception as e:
            logger.warning(f"Failed to download file {file_path}: {e}")
        
        return None
    
    def _parse_vulnerability_file(self, content: str, file_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse vulnerability data from file content"""
        vulnerabilities = []
        
        try:
            # Determine file format and parse
            filename = file_info['name'].lower()
            
            if filename.endswith('.json'):
                data = json.loads(content)
                vulnerabilities = self._extract_vulnerabilities_from_json(data, file_info)
            elif filename.endswith(('.yaml', '.yml')):
                import yaml
                data = yaml.safe_load(content)
                vulnerabilities = self._extract_vulnerabilities_from_yaml(data, file_info)
            elif filename.endswith('.toml'):
                import tomli
                data = tomli.loads(content)
                vulnerabilities = self._extract_vulnerabilities_from_toml(data, file_info)
            
        except Exception as e:
            logger.warning(f"Failed to parse file {file_info['name']}: {e}")
        
        return vulnerabilities
    
    def _extract_vulnerabilities_from_json(self, data: Any, file_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract vulnerabilities from JSON data"""
        vulnerabilities = []
        
        # Handle different JSON structures
        if isinstance(data, list):
            # Array of vulnerabilities
            for item in data:
                if isinstance(item, dict):
                    vuln = self._normalize_vulnerability_data(item, file_info)
                    if vuln:
                        vulnerabilities.append(vuln)
        elif isinstance(data, dict):
            # Single vulnerability or nested structure
            if any(key in data for key in ['id', 'cve', 'ghsa_id', 'title', 'summary']):
                # Single vulnerability
                vuln = self._normalize_vulnerability_data(data, file_info)
                if vuln:
                    vulnerabilities.append(vuln)
            else:
                # Nested structure - look for arrays
                for key, value in data.items():
                    if isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict):
                                vuln = self._normalize_vulnerability_data(item, file_info)
                                if vuln:
                                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _extract_vulnerabilities_from_yaml(self, data: Any, file_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract vulnerabilities from YAML data"""
        # YAML parsing similar to JSON
        return self._extract_vulnerabilities_from_json(data, file_info)
    
    def _extract_vulnerabilities_from_toml(self, data: Any, file_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract vulnerabilities from TOML data"""
        # TOML parsing similar to JSON
        return self._extract_vulnerabilities_from_json(data, file_info)
    
    def _normalize_vulnerability_data(self, vuln_data: Dict[str, Any], file_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Normalize vulnerability data from repository files"""
        try:
            # Extract common fields with various possible names
            normalized = {
                'source_file': file_info['path'],
                'file_format': file_info['name'].split('.')[-1],
                'github_repository': f"{self.repository_owner}/{self.repository_name}",
                
                # ID fields
                'source_id': (vuln_data.get('id') or vuln_data.get('ghsa_id') or 
                             vuln_data.get('advisory_id') or vuln_data.get('osv_id')),
                
                # CVE fields
                'cve_identifiers': self._extract_cve_ids_from_data(vuln_data),
                
                # Title/Summary
                'title': (vuln_data.get('title') or vuln_data.get('summary') or 
                         vuln_data.get('description', '')[:100]),
                
                # Description
                'description': (vuln_data.get('description') or vuln_data.get('details') or 
                               vuln_data.get('summary', '')),
                
                # Severity
                'severity': self._extract_severity_from_data(vuln_data),
                
                # Dates
                'published_date': (vuln_data.get('published') or vuln_data.get('published_at') or 
                                  vuln_data.get('date') or vuln_data.get('created')),
                'updated_date': (vuln_data.get('modified') or vuln_data.get('updated_at') or 
                                vuln_data.get('updated')),
                
                # Packages
                'affected_packages': self._extract_packages_from_data(vuln_data),
                
                # References
                'references': self._extract_references_from_data(vuln_data),
                
                # CVSS
                'cvss_score': self._extract_cvss_from_data(vuln_data),
                
                # Source metadata
                'source_name': self.source_name,
                'raw_data': vuln_data
            }
            
            # Only return if we have meaningful data
            if (normalized['source_id'] or normalized['cve_identifiers'] or 
                normalized['title'] or len(normalized['description']) > 10):
                return normalized
            
        except Exception as e:
            logger.warning(f"Failed to normalize vulnerability data: {e}")
        
        return None
    
    async def _get_repository_releases(self) -> List[Dict[str, Any]]:
        """Get repository releases"""
        try:
            url = f"{self.base_url}/repos/{self.repository_owner}/{self.repository_name}/releases"
            params = {'per_page': 10}  # Get recent releases
            
            releases = await self._make_github_request(url, params)
            return releases if isinstance(releases, list) else []
            
        except Exception as e:
            logger.warning(f"Failed to get repository releases: {e}")
            return []
    
    def _extract_vulnerabilities_from_release(self, release: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract vulnerability information from release data"""
        # Look for CVE mentions in release notes
        import re
        
        vulnerabilities = []
        release_text = f"{release.get('name', '')} {release.get('body', '')}"
        
        # Find CVE mentions
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        cve_matches = re.findall(cve_pattern, release_text)
        
        if cve_matches:
            vuln = {
                'source_id': release.get('id'),
                'cve_identifiers': list(set(cve_matches)),
                'title': f"Release {release.get('tag_name', '')}: {release.get('name', '')}",
                'description': release.get('body', '')[:500],  # Limit description
                'published_date': release.get('published_at'),
                'source_name': self.source_name,
                'source_type': 'github_release',
                'release_tag': release.get('tag_name'),
                'raw_data': release
            }
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _make_github_request(self, url: str, params: Dict[str, Any] = None) -> Optional[Any]:
        """Make GitHub API request with rate limiting and error handling"""
        for attempt in range(self.github_config['retry_attempts']):
            try:
                self.stats['api_requests'] += 1
                
                async with self.session.get(url, params=params) as response:
                    # Update rate limit info
                    self.stats['rate_limit_remaining'] = int(response.headers.get('X-RateLimit-Remaining', 0))
                    
                    if response.status == 200:
                        data = await response.json()
                        return data
                    elif response.status == 403:
                        # Rate limited
                        reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
                        current_time = datetime.utcnow().timestamp()
                        wait_time = max(reset_time - current_time, 60)
                        
                        logger.warning(f"⚠️ GitHub rate limited, waiting {wait_time:.0f}s...")
                        await asyncio.sleep(min(wait_time, 300))  # Max 5 minute wait
                        continue
                    elif response.status == 404:
                        logger.warning(f"⚠️ GitHub resource not found: {url}")
                        return None
                    else:
                        logger.warning(f"⚠️ GitHub API returned status {response.status}")
                        self.stats['failed_requests'] += 1
                        return None
                        
            except Exception as e:
                logger.warning(f"❌ GitHub API request failed (attempt {attempt + 1}): {e}")
                if attempt < self.github_config['retry_attempts'] - 1:
                    await asyncio.sleep(2 ** attempt)
                continue
        
        self.stats['failed_requests'] += 1
        return None
    
    def _extract_cve_ids_from_data(self, data: Dict[str, Any]) -> List[str]:
        """Extract CVE IDs from vulnerability data"""
        import re
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        cve_ids = set()
        
        # Common CVE fields
        cve_fields = ['cve', 'cve_id', 'cve_ids', 'identifiers', 'aliases', 'cve_list']
        
        for field in cve_fields:
            if field in data:
                value = data[field]
                if isinstance(value, str):
                    matches = re.findall(cve_pattern, value)
                    cve_ids.update(matches)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str):
                            matches = re.findall(cve_pattern, item)
                            cve_ids.update(matches)
        
        return list(cve_ids)
    
    def _extract_severity_from_data(self, data: Dict[str, Any]) -> str:
        """Extract severity from vulnerability data"""
        severity_fields = ['severity', 'priority', 'cvss_score', 'score']
        
        for field in severity_fields:
            if field in data:
                value = data[field]
                if isinstance(value, str):
                    return value.upper()
                elif isinstance(value, dict):
                    # CVSS object
                    if 'level' in value:
                        return value['level'].upper()
                    elif 'score' in value:
                        score = float(value['score'])
                        if score >= 9.0:
                            return 'CRITICAL'
                        elif score >= 7.0:
                            return 'HIGH'
                        elif score >= 4.0:
                            return 'MEDIUM'
                        else:
                            return 'LOW'
        
        return 'UNKNOWN'
    
    def _extract_packages_from_data(self, data: Dict[str, Any]) -> List[str]:
        """Extract affected packages from vulnerability data"""
        packages = []
        
        package_fields = ['affected', 'packages', 'vulnerable_packages', 'affected_packages']
        
        for field in package_fields:
            if field in data:
                value = data[field]
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, str):
                            packages.append(item)
                        elif isinstance(item, dict):
                            pkg_name = (item.get('package', {}).get('name') or 
                                       item.get('name') or 
                                       item.get('ecosystem', '') + '/' + item.get('name', ''))
                            if pkg_name:
                                packages.append(pkg_name)
        
        return packages[:10]
    
    def _extract_references_from_data(self, data: Dict[str, Any]) -> List[str]:
        """Extract references from vulnerability data"""
        references = []
        
        ref_fields = ['references', 'urls', 'links', 'external_references']
        
        for field in ref_fields:
            if field in data:
                value = data[field]
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, str) and item.startswith('http'):
                            references.append(item)
                        elif isinstance(item, dict):
                            url = item.get('url', item.get('link', ''))
                            if url and url.startswith('http'):
                                references.append(url)
        
        return references[:5]
    
    def _extract_cvss_from_data(self, data: Dict[str, Any]) -> Optional[float]:
        """Extract CVSS score from vulnerability data"""
        cvss_fields = ['cvss_score', 'cvss', 'score']
        
        for field in cvss_fields:
            if field in data:
                value = data[field]
                if isinstance(value, (int, float)):
                    return float(value)
                elif isinstance(value, dict):
                    score = value.get('score', value.get('base_score'))
                    if isinstance(score, (int, float)):
                        return float(score)
        
        return None
    
    def _process_vulnerability_data(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process and clean vulnerability data"""
        # Remove duplicates and clean data
        seen_ids = set()
        processed_vulnerabilities = []
        
        for vuln in vulnerabilities:
            # Create unique identifier
            unique_id = (vuln.get('source_id') or 
                        str(vuln.get('cve_identifiers', [])) or 
                        vuln.get('title', '')[:50])
            
            if unique_id and unique_id not in seen_ids:
                seen_ids.add(unique_id)
                processed_vulnerabilities.append(vuln)
        
        return processed_vulnerabilities
    
    def _analyze_data_structure(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze the structure of vulnerability data"""
        if not data:
            return {'data_type': 'empty_list', 'total_size': 0}
        
        sample_vuln = data[0]
        
        # Count vulnerabilities with different types of data
        vulns_with_cves = sum(1 for vuln in data if vuln.get('cve_identifiers'))
        vulns_with_ghsa = sum(1 for vuln in data if vuln.get('source_id', '').startswith('GHSA'))
        vulns_with_packages = sum(1 for vuln in data if vuln.get('affected_packages'))
        
        analysis = {
            'data_type': 'list_of_github_vulnerabilities',
            'total_vulnerabilities': len(data),
            'vulnerability_structure': list(sample_vuln.keys()),
            'vulnerabilities_with_cves': vulns_with_cves,
            'vulnerabilities_with_ghsa_ids': vulns_with_ghsa,
            'vulnerabilities_with_packages': vulns_with_packages,
            'data_completeness_score': (vulns_with_cves + vulns_with_ghsa) / (len(data) * 2) if data else 0,
            'github_api_success_rate': (self.stats['api_requests'] - self.stats['failed_requests']) / max(self.stats['api_requests'], 1)
        }
        
        return analysis
    
    def _generate_field_mappings(self) -> Dict[str, str]:
        """Generate field mappings for parser"""
        return {
            'source_id': 'identifier',
            'cve_identifiers': 'cve_ids',
            'title': 'title',
            'description': 'description',
            'severity': 'severity',
            'published_date': 'published_date',
            'updated_date': 'last_modified_date',
            'affected_packages': 'affected_packages',
            'references': 'references',
            'cvss_score': 'cvss_score'
        }
    
    async def test_connectivity(self) -> Dict[str, Any]:
        """Test GitHub API connectivity"""
        logger.info(f"🔍 Testing GitHub API connectivity")
        
        try:
            start_time = datetime.utcnow()
            
            # Test basic GitHub API access
            url = f"{self.base_url}/rate_limit"
            rate_limit_data = await self._make_github_request(url)
            
            response_time = (datetime.utcnow() - start_time).total_seconds()
            
            if rate_limit_data:
                core_limit = rate_limit_data.get('resources', {}).get('core', {})
                
                logger.info(f"✅ GitHub API connectivity test passed ({response_time:.2f}s)")
                logger.info(f"🔄 Rate Limit: {core_limit.get('remaining', 0)}/{core_limit.get('limit', 0)}")
                
                # Test specific source access
                if self.source_type == "repository":
                    # Test repository access
                    repo_url = f"{self.base_url}/repos/{self.repository_owner}/{self.repository_name}"
                    repo_data = await self._make_github_request(repo_url)
                    
                    return {
                        'status': 'success',
                        'response_time_seconds': response_time,
                        'authenticated': bool(self.github_token),
                        'rate_limit_remaining': core_limit.get('remaining', 0),
                        'rate_limit_total': core_limit.get('limit', 0),
                        'repository_accessible': bool(repo_data),
                        'repository_size': repo_data.get('size', 0) if repo_data else 0,
                        'timestamp': datetime.utcnow().isoformat()
                    }
                else:
                    # Test Security Advisories API
                    advisories_url = f"{self.base_url}/advisories"
                    test_advisories = await self._make_github_request(advisories_url, {'per_page': 1})
                    
                    return {
                        'status': 'success',
                        'response_time_seconds': response_time,
                        'authenticated': bool(self.github_token),
                        'rate_limit_remaining': core_limit.get('remaining', 0),
                        'rate_limit_total': core_limit.get('limit', 0),
                        'advisories_accessible': bool(test_advisories),
                        'sample_advisories_count': len(test_advisories) if test_advisories else 0,
                        'timestamp': datetime.utcnow().isoformat()
                    }
            else:
                return {
                    'status': 'failed',
                    'error': 'Could not access GitHub API',
                    'timestamp': datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            logger.error(f"❌ GitHub API connectivity test failed: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def display_statistics(self):
        """Display download statistics"""
        logger.info("=" * 70)
        logger.info(f"📊 GitHub Download Statistics ({self.source_name})")
        logger.info("=" * 70)
        logger.info(f"🛡️ Vulnerabilities: {self.stats['total_vulnerabilities']:,}")
        logger.info(f"📡 API Requests: {self.stats['api_requests']:,}")
        logger.info(f"❌ Failed Requests: {self.stats['failed_requests']:,}")
        logger.info(f"⏱️ Processing Time: {self.stats['processing_time_seconds']:.1f}s")
        logger.info(f"💾 Data Size: {self.stats['data_size_mb']:.2f} MB")
        logger.info(f"🔄 Rate Limit Remaining: {self.stats['rate_limit_remaining']:,}")
        
        success_rate = ((self.stats['api_requests'] - self.stats['failed_requests']) / 
                       max(self.stats['api_requests'], 1) * 100)
        logger.info(f"✅ Success Rate: {success_rate:.1f}%")
        
        if self.source_type == "repository":
            logger.info(f"📦 Repository: {self.repository_owner}/{self.repository_name}")
        else:
            logger.info(f"🔒 Source: GitHub Security Advisories API")
        
        logger.info("=" * 70)

async def main():
    """Main execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Download from GitHub vulnerability sources')
    parser.add_argument('--source-name', required=True,
                       help='Name of the vulnerability source')
    parser.add_argument('--source-type', choices=['repository', 'advisories'], required=True,
                       help='Type of GitHub source')
    parser.add_argument('--repository-owner', 
                       help='GitHub repository owner (required for repository type)')
    parser.add_argument('--repository-name',
                       help='GitHub repository name (required for repository type)')
    parser.add_argument('--test-connectivity', action='store_true',
                       help='Test GitHub API connectivity only')
    parser.add_argument('--output-dir', 
                       help='Output directory for downloaded data')
    
    args = parser.parse_args()
    
    if args.source_type == 'repository':
        if not args.repository_owner or not args.repository_name:
            print("❌ --repository-owner and --repository-name required for repository type")
            sys.exit(1)
    
    async with GitHubVulnerabilityDownloader(
        args.source_name, 
        args.source_type,
        args.repository_owner or "",
        args.repository_name or ""
    ) as downloader:
        try:
            if args.test_connectivity:
                results = await downloader.test_connectivity()
                print(f"Connectivity test: {results['status']}")
                if results['status'] == 'success':
                    print(f"Rate limit: {results['rate_limit_remaining']}/{results['rate_limit_total']}")
                return
            
            # Download and save data
            output_file = await downloader.download_and_save_data(args.output_dir)
            
            # Display statistics
            downloader.display_statistics()
            
            print(f"✅ GitHub download completed!")
            print(f"📁 Output file: {output_file}")
            
        except Exception as e:
            print(f"❌ Download failed: {e}")
            sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())