#!/usr/bin/env python3
"""
Debian Input Data Structure Downloader

OBJECTIVE:
Download and analyze Debian Security Tracker data structure.
This script focuses on data acquisition and initial structure analysis only.

WORKFLOW:
1. Fetch complete data from Debian Security Tracker
2. Save as timestamped JSON file
3. Analyze basic data structure and patterns
4. Generate field mappings and validation rules
5. Generate comprehensive reports

DEBIAN-SPECIFIC FEATURES:
- Handles {package: {CVE: data}} structure
- Analyzes Debian release information
- Identifies package-specific fields
- Downloads complete dataset for offline processing
"""

import asyncio
import aiohttp
import json
import re
import logging
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from pathlib import Path
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import statistics

# Add paths for imports
current_dir = Path(__file__).parent
vuln_db_root = current_dir.parent.parent.parent
sys.path.append(str(vuln_db_root))
sys.path.append(str(vuln_db_root / "config"))

# Import with fallback to direct URL if config fails
try:
    # from source_config import get_debian_config
    def get_debian_config():
        return {
            'name': 'debian_security_tracker',
            'url': 'https://security-tracker.debian.org/tracker/data/json',
            'category': 'cve_compatible_os',
            'priority': 8,
            'status': 'working',
            'timeout_seconds': 30,
            'retry_attempts': 3
        }
except ImportError:
    # Fallback configuration if import fails
    def get_debian_config():
        return {
            'name': 'debian_security_tracker',
            'url': 'https://security-tracker.debian.org/tracker/data/json',
            'category': 'cve_compatible_os',
            'priority': 8,
            'status': 'working',
            'timeout_seconds': 30,
            'retry_attempts': 3
        }

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class FieldAnalysis:
    """Analysis results for a single field"""
    field_name: str
    field_path: str  # JSON path like "releases.bookworm.status"
    data_types: Set[str]
    sample_values: List[Any]
    null_count: int
    total_count: int
    unique_values: Set[str]
    value_patterns: List[str]
    is_required: bool
    is_nested: bool
    nested_structure: Optional[Dict] = None

@dataclass
class DebianDataStructureAnalysis:
    """Complete analysis of Debian data structure"""
    source_name: str
    total_records: int
    total_packages: int
    total_cves: int
    analysis_timestamp: str
    fields: Dict[str, FieldAnalysis]
    nested_structures: Dict[str, Dict]
    data_patterns: Dict[str, Any]
    debian_releases: List[str]
    package_patterns: Dict[str, Any]
    recommendations: List[str]
    parser_suggestions: Dict[str, Any]

class DebianDataStructureAnalyzer:
    """Analyzes Debian Security Tracker data and generates optimized parsers"""
    
    def __init__(self):
        self.session = None
        self.debian_config = get_debian_config()
        self.analysis_results = {}
        
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=60),
            headers={
                'User-Agent': 'DebianDataStructureAnalyzer/1.0 (Vulnerability Research)',
                'Accept': 'application/json, application/xml, text/html, */*'
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def download_and_save_debian_data(self, output_dir: str = None) -> str:
        """Download complete Debian data and save as timestamped JSON file"""
        # Hardcode the correct output path as default
        if output_dir is None:
            output_dir = current_dir / "output" / "data_downloads"
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Generate timestamped filename
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"debian_security_tracker_data_{timestamp}.json"
        output_file = output_path / filename
        
        logger.info(f"📥 Downloading complete Debian Security Tracker data...")
        
        try:
            url = self.debian_config.get('url')
            if not url:
                raise Exception("No URL configured for Debian source")
            
            async with self.session.get(url) as response:
                if response.status != 200:
                    raise Exception(f"HTTP {response.status}: {await response.text()}")
                
                content_type = response.headers.get('content-type', '').lower()
                
                if 'application/json' in content_type:
                    data = await response.json()
                else:
                    text_data = await response.text()
                    try:
                        data = json.loads(text_data)
                    except:
                        raise Exception(f"Unable to parse response as JSON")
                
                # Add metadata
                download_metadata = {
                    'download_timestamp': datetime.utcnow().isoformat(),
                    'source_url': url,
                    'total_packages': len(data) if isinstance(data, dict) else 0,
                    'content_type': content_type,
                    'response_status': response.status,
                    'data_size_mb': len(str(data)) / (1024 * 1024)
                }
                
                # Calculate statistics
                total_cves = 0
                if isinstance(data, dict):
                    for package_data in data.values():
                        if isinstance(package_data, dict):
                            total_cves += sum(1 for key in package_data.keys() if key.startswith('CVE-'))
                
                download_metadata['total_cves_found'] = total_cves
                
                # Prepare final data structure
                final_data = {
                    'metadata': download_metadata,
                    'data': data
                }
                
                # Save to file
                with open(output_file, 'w') as f:
                    json.dump(final_data, f, indent=2, default=str)
                
                logger.info(f"✅ Downloaded and saved Debian data: {output_file}")
                logger.info(f"📊 Statistics:")
                logger.info(f"   • Total packages: {download_metadata['total_packages']:,}")
                logger.info(f"   • Total CVEs: {download_metadata['total_cves_found']:,}")
                logger.info(f"   • File size: {download_metadata['data_size_mb']:.2f} MB")
                
                return str(output_file)
                
        except Exception as e:
            logger.error(f"❌ Failed to download Debian data: {e}")
            raise

    async def analyze_debian_data(self, max_packages: int = 100) -> DebianDataStructureAnalysis:
        """
        Comprehensive analysis of Debian Security Tracker data structure
        
        STEPS:
        1. Fetch sample data from Debian Security Tracker
        2. Analyze Debian-specific structure {package: {CVE: data}}
        3. Identify field patterns and data types
        4. Analyze Debian releases and package patterns
        5. Generate Debian-optimized parser recommendations
        """
        logger.info(f"🔍 Starting Debian data structure analysis")
        
        try:
            # Step 1: Fetch sample data
            raw_data, packages_analyzed = await self._fetch_debian_sample_data(max_packages)
            if not raw_data:
                raise Exception("No sample data available for analysis")
            
            logger.info(f"✓ Fetched data from {packages_analyzed} packages with {len(raw_data)} CVE records")
            
            # Step 2: Analyze data structure
            field_analysis = self._analyze_debian_fields(raw_data)
            logger.info(f"✓ Analyzed {len(field_analysis)} unique fields")
            
            # Step 3: Identify Debian-specific patterns
            patterns = self._identify_debian_patterns(raw_data, field_analysis)
            logger.info(f"✓ Identified Debian-specific patterns")
            
            # Step 4: Analyze releases and packages
            debian_releases = self._identify_debian_releases(raw_data)
            package_patterns = self._analyze_package_patterns(raw_data)
            
            # Step 5: Generate recommendations
            recommendations = self._generate_debian_recommendations(field_analysis, patterns, debian_releases)
            parser_suggestions = self._generate_debian_parser_suggestions(field_analysis, patterns, debian_releases)
            
            # Step 6: Create comprehensive analysis
            analysis = DebianDataStructureAnalysis(
                source_name='debian_security_tracker',
                total_records=len(raw_data),
                total_packages=packages_analyzed,
                total_cves=len(set(record.get('cve_id') for record in raw_data)),
                analysis_timestamp=datetime.utcnow().isoformat(),
                fields=field_analysis,
                nested_structures=patterns.get('nested_structures', {}),
                data_patterns=patterns,
                debian_releases=debian_releases,
                package_patterns=package_patterns,
                recommendations=recommendations,
                parser_suggestions=parser_suggestions
            )
            
            logger.info(f"🎉 Debian data structure analysis completed")
            return analysis
            
        except Exception as e:
            logger.error(f"❌ Debian data structure analysis failed: {e}")
            raise
    
    async def analyze_from_saved_file(self, json_file_path: str, max_packages: int = 100) -> DebianDataStructureAnalysis:
        """Analyze Debian data from previously saved JSON file"""
        logger.info(f"📂 Loading Debian data from: {json_file_path}")
        
        try:
            with open(json_file_path, 'r') as f:
                file_data = json.load(f)
            
            # Extract data and metadata
            if 'data' in file_data and 'metadata' in file_data:
                data = file_data['data']
                metadata = file_data['metadata']
                logger.info(f"✓ Loaded saved data from {metadata.get('download_timestamp', 'unknown time')}")
                logger.info(f"✓ Original data size: {metadata.get('data_size_mb', 0):.2f} MB")
                logger.info(f"✓ Total packages in file: {metadata.get('total_packages', 0):,}")
                logger.info(f"✓ Total CVEs in file: {metadata.get('total_cves_found', 0):,}")
            else:
                # Assume it's raw data without metadata wrapper
                data = file_data
                metadata = {'source': 'raw_file'}
                logger.info("✓ Loaded raw data file without metadata")
            
            # Convert to normalized records
            records, packages_analyzed = self._normalize_debian_data(data, max_packages)
            logger.info(f"✓ Normalized {len(records)} CVE records from {packages_analyzed} packages")
            
            # Perform analysis (rest of the analysis pipeline)
            field_analysis = self._analyze_debian_fields(records)
            logger.info(f"✓ Analyzed {len(field_analysis)} unique fields")
            
            patterns = self._identify_debian_patterns(records, field_analysis)
            debian_releases = self._identify_debian_releases(records)
            package_patterns = self._analyze_package_patterns(records)
            recommendations = self._generate_debian_recommendations(field_analysis, patterns, debian_releases)
            parser_suggestions = self._generate_debian_parser_suggestions(field_analysis, patterns, debian_releases)
            
            analysis = DebianDataStructureAnalysis(
                source_name='debian_security_tracker',
                total_records=len(records),
                total_packages=packages_analyzed,
                total_cves=len(set(record.get('cve_id') for record in records)),
                analysis_timestamp=datetime.utcnow().isoformat(),
                fields=field_analysis,
                nested_structures=patterns.get('nested_structures', {}),
                data_patterns=patterns,
                debian_releases=debian_releases,
                package_patterns=package_patterns,
                recommendations=recommendations,
                parser_suggestions=parser_suggestions
            )
            
            logger.info(f"🎉 Analysis completed from saved file")
            return analysis
            
        except Exception as e:
            logger.error(f"❌ Failed to analyze from saved file: {e}")
            raise
    
    async def _fetch_debian_sample_data(self, max_packages: int) -> Tuple[List[Dict[str, Any]], int]:
        """Fetch sample data from Debian Security Tracker"""
        url = self.debian_config.get('url')
        if not url:
            raise Exception("No URL configured for Debian source")
        
        logger.info(f"📥 Fetching sample data from {url}")
        
        try:
            async with self.session.get(url) as response:
                if response.status != 200:
                    raise Exception(f"HTTP {response.status}: {await response.text()}")
                
                content_type = response.headers.get('content-type', '').lower()
                
                if 'application/json' in content_type:
                    data = await response.json()
                else:
                    text_data = await response.text()
                    try:
                        data = json.loads(text_data)
                    except:
                        raise Exception(f"Unable to parse response as JSON: {text_data[:200]}...")
                
                # Convert Debian structure to normalized records
                return self._normalize_debian_data(data, max_packages)
                
        except Exception as e:
            logger.error(f"Error fetching Debian sample data: {e}")
            raise
    
    def _normalize_debian_data(self, data: Dict[str, Any], max_packages: int) -> Tuple[List[Dict[str, Any]], int]:
        """Convert Debian {package: {CVE: data}} structure to normalized records"""
        records = []
        packages_processed = 0
        
        # Process packages up to the limit
        for package_name, package_data in list(data.items())[:max_packages]:
            if not isinstance(package_data, dict):
                continue
                
            packages_processed += 1
            
            # Process CVEs within this package
            for cve_id, cve_data in package_data.items():
                if not cve_id.startswith('CVE-') or not isinstance(cve_data, dict):
                    continue
                
                # Create flattened record with package context
                record = cve_data.copy()
                record['cve_id'] = cve_id
                record['package_name'] = package_name
                
                # Add Debian-specific metadata
                record['_debian_metadata'] = {
                    'source_package': package_name,
                    'total_releases': len(cve_data.get('releases', {})),
                    'has_debianbug': 'debianbug' in cve_data,
                    'scope': cve_data.get('scope', 'unknown')
                }
                
                records.append(record)
        
        logger.info(f"✓ Normalized to {len(records)} CVE records from {packages_processed} packages")
        return records, packages_processed
    
    def _analyze_debian_fields(self, data: List[Dict[str, Any]]) -> Dict[str, FieldAnalysis]:
        """Analyze all fields in Debian data"""
        field_stats = defaultdict(lambda: {
            'types': set(),
            'values': [],
            'nulls': 0,
            'total': 0,
            'unique_values': set(),
            'paths': set()
        })
        
        # Analyze each record
        for record in data:
            self._analyze_record_fields(record, field_stats, "")
        
        # Convert to FieldAnalysis objects
        field_analysis = {}
        for field_name, stats in field_stats.items():
            # Determine if field is required (less than 20% nulls)
            is_required = (stats['nulls'] / max(stats['total'], 1)) < 0.2
            
            # Identify value patterns
            patterns = self._identify_value_patterns(stats['values'])
            
            # Check if field is nested
            is_nested = '.' in field_name or any('.' in path for path in stats['paths'])
            
            field_analysis[field_name] = FieldAnalysis(
                field_name=field_name.split('.')[-1],  # Last part of path
                field_path=field_name,
                data_types=stats['types'],
                sample_values=list(stats['values'])[:10],  # First 10 samples
                null_count=stats['nulls'],
                total_count=stats['total'],
                unique_values=stats['unique_values'],
                value_patterns=patterns,
                is_required=is_required,
                is_nested=is_nested
            )
        
        return field_analysis
    
    def _analyze_record_fields(self, obj: Any, field_stats: Dict, prefix: str):
        """Recursively analyze fields in a record"""
        if isinstance(obj, dict):
            for key, value in obj.items():
                field_path = f"{prefix}.{key}" if prefix else key
                
                if value is None:
                    field_stats[field_path]['nulls'] += 1
                    field_stats[field_path]['total'] += 1
                    field_stats[field_path]['types'].add('null')
                elif isinstance(value, (dict, list)):
                    # Nested structure
                    field_stats[field_path]['total'] += 1
                    field_stats[field_path]['types'].add(type(value).__name__)
                    field_stats[field_path]['paths'].add(field_path)
                    
                    # Recurse into nested structure
                    self._analyze_record_fields(value, field_stats, field_path)
                else:
                    # Leaf value
                    field_stats[field_path]['total'] += 1
                    field_stats[field_path]['types'].add(type(value).__name__)
                    field_stats[field_path]['values'].append(value)
                    field_stats[field_path]['paths'].add(field_path)
                    
                    # Track unique values (limit to reasonable size)
                    if len(field_stats[field_path]['unique_values']) < 100:
                        field_stats[field_path]['unique_values'].add(str(value))
        
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                item_path = f"{prefix}[{i}]" if prefix else f"item_{i}"
                self._analyze_record_fields(item, field_stats, item_path)
    
    def _identify_value_patterns(self, values: List[Any]) -> List[str]:
        """Identify patterns in field values"""
        patterns = []
        string_values = [str(v) for v in values if v is not None]
        
        if not string_values:
            return patterns
        
        # CVE ID pattern
        cve_pattern = r'^CVE-\d{4}-\d{4,}$'
        if any(re.match(cve_pattern, v) for v in string_values):
            patterns.append('cve_id')
        
        # Debian-specific patterns
        debian_release_pattern = r'^(bullseye|bookworm|trixie|sid|forky|experimental)$'
        if any(re.match(debian_release_pattern, v) for v in string_values):
            patterns.append('debian_release')
        
        # Debian package version pattern
        version_pattern = r'^\d+[:\.].*'
        if any(re.match(version_pattern, v) for v in string_values):
            patterns.append('debian_version')
        
        # Debian urgency pattern
        urgency_pattern = r'^(unimportant|low|medium|high|not yet assigned)$'
        if any(re.match(urgency_pattern, v) for v in string_values):
            patterns.append('debian_urgency')
        
        # Debian status pattern
        status_pattern = r'^(resolved|open|undetermined|not-affected|end-of-life)$'
        if any(re.match(status_pattern, v) for v in string_values):
            patterns.append('debian_status')
        
        # Debian bug ID pattern
        bug_pattern = r'^\d{6,}$'
        if any(re.match(bug_pattern, v) for v in string_values):
            patterns.append('debian_bug_id')
        
        # General patterns
        if any(re.match(r'^https?://', v) for v in string_values):
            patterns.append('url')
        
        # Enumerated values (if limited unique values)
        unique_count = len(set(string_values))
        if unique_count <= 10 and len(string_values) > unique_count * 2:
            patterns.append('enumerated')
        
        return patterns
    
    def _identify_debian_patterns(self, data: List[Dict[str, Any]], field_analysis: Dict[str, FieldAnalysis]) -> Dict[str, Any]:
        """Identify Debian-specific patterns"""
        patterns = {
            'nested_structures': {},
            'debian_specific': {},
            'data_quality': {},
            'common_structures': []
        }
        
        # Identify nested structures
        for field_name, analysis in field_analysis.items():
            if analysis.is_nested and 'dict' in analysis.data_types:
                parts = field_name.split('.')
                if len(parts) >= 2:
                    parent = parts[0]
                    child = '.'.join(parts[1:])
                    if parent not in patterns['nested_structures']:
                        patterns['nested_structures'][parent] = []
                    patterns['nested_structures'][parent].append(child)
        
        # Identify Debian-specific structures
        patterns['debian_specific'] = {
            'has_releases_structure': 'releases' in patterns['nested_structures'],
            'has_debianbug_field': any('debianbug' in f.field_path for f in field_analysis.values()),
            'has_scope_field': any('scope' in f.field_path for f in field_analysis.values()),
            'has_repositories': any('repositories' in f.field_path for f in field_analysis.values())
        }
        
        # Common vulnerability patterns
        if any('cve_id' in analysis.value_patterns for analysis in field_analysis.values()):
            patterns['common_structures'].append('vulnerability_data')
        
        if any('debian_release' in analysis.value_patterns for analysis in field_analysis.values()):
            patterns['common_structures'].append('debian_releases')
        
        # Data quality assessment
        total_fields = len(field_analysis)
        required_fields = sum(1 for analysis in field_analysis.values() if analysis.is_required)
        patterns['data_quality'] = {
            'total_fields': total_fields,
            'required_fields': required_fields,
            'optional_fields': total_fields - required_fields,
            'completeness_ratio': required_fields / max(total_fields, 1)
        }
        
        return patterns
    
    def _identify_debian_releases(self, data: List[Dict[str, Any]]) -> List[str]:
        """Identify all Debian releases found in the data"""
        releases = set()
        
        for record in data:
            release_data = record.get('releases', {})
            if isinstance(release_data, dict):
                releases.update(release_data.keys())
        
        # Sort releases by typical Debian order
        release_order = ['experimental', 'sid', 'trixie', 'bookworm', 'bullseye', 'buster', 'stretch']
        sorted_releases = []
        
        for release in release_order:
            if release in releases:
                sorted_releases.append(release)
                releases.remove(release)
        
        # Add any remaining releases
        sorted_releases.extend(sorted(releases))
        
        return sorted_releases
    
    def _analyze_package_patterns(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze package-specific patterns"""
        packages = defaultdict(int)
        package_cve_counts = defaultdict(int)
        
        for record in data:
            package_name = record.get('package_name')
            if package_name:
                packages[package_name] += 1
                package_cve_counts[package_name] += 1
        
        return {
            'total_packages': len(packages),
            'most_vulnerable_packages': dict(Counter(package_cve_counts).most_common(10)),
            'average_cves_per_package': sum(package_cve_counts.values()) / max(len(package_cve_counts), 1),
            'package_distribution': dict(packages)
        }
    
    def _generate_debian_recommendations(self, field_analysis: Dict[str, FieldAnalysis], patterns: Dict[str, Any], debian_releases: List[str]) -> List[str]:
        """Generate Debian-specific recommendations"""
        recommendations = []
        
        # Debian-specific recommendations
        if patterns['debian_specific']['has_releases_structure']:
            recommendations.append(f"Process {len(debian_releases)} Debian releases: {', '.join(debian_releases[:5])}")
        
        if patterns['debian_specific']['has_debianbug_field']:
            recommendations.append("Include Debian bug tracking integration")
        
        if patterns['debian_specific']['has_repositories']:
            recommendations.append("Handle Debian repository information (main, security, updates)")
        
        # Field handling recommendations
        required_fields = [f.field_name for f in field_analysis.values() if f.is_required]
        if len(required_fields) > 15:
            recommendations.append(f"Focus on {len(required_fields)} required fields for Debian parsing")
        
        # Data quality recommendations
        quality = patterns['data_quality']
        if quality['completeness_ratio'] < 0.6:
            recommendations.append("Implement robust null handling for optional Debian fields")
        
        # Debian-specific parsing recommendations
        debian_pattern_fields = [f for f in field_analysis.values() if any(p.startswith('debian_') for p in f.value_patterns)]
        if debian_pattern_fields:
            recommendations.append("Implement Debian-specific field validation and normalization")
        
        return recommendations
    
    def _generate_debian_parser_suggestions(self, field_analysis: Dict[str, FieldAnalysis], patterns: Dict[str, Any], debian_releases: List[str]) -> Dict[str, Any]:
        """Generate Debian-specific parser implementation suggestions"""
        suggestions = {
            'required_fields': [],
            'optional_fields': [],
            'debian_specific_fields': [],
            'field_mappings': {},
            'validation_rules': {},
            'transformation_functions': [],
            'debian_releases': debian_releases
        }
        
        for field_name, analysis in field_analysis.items():
            field_info = {
                'name': analysis.field_name,
                'path': analysis.field_path,
                'types': list(analysis.data_types),
                'patterns': analysis.value_patterns
            }
            
            # Categorize fields
            if analysis.is_required:
                suggestions['required_fields'].append(field_info)
            else:
                suggestions['optional_fields'].append(field_info)
            
            # Identify Debian-specific fields
            if any(p.startswith('debian_') for p in analysis.value_patterns):
                suggestions['debian_specific_fields'].append(field_info)
            
            # Generate field mappings
            suggestions['field_mappings'][analysis.field_path] = self._suggest_debian_field_mapping(analysis)
            
            # Generate validation rules
            if analysis.value_patterns:
                suggestions['validation_rules'][analysis.field_path] = analysis.value_patterns
        
        # Generate Debian-specific transformation functions
        if patterns['debian_specific']['has_releases_structure']:
            suggestions['transformation_functions'].append('process_debian_releases')
            suggestions['transformation_functions'].append('determine_debian_package_status')
        
        if patterns['debian_specific']['has_debianbug_field']:
            suggestions['transformation_functions'].append('normalize_debian_bug_id')
        
        suggestions['transformation_functions'].extend(['normalize_cve_id', 'parse_debian_urgency', 'validate_debian_version'])
        
        return suggestions
    
    def _suggest_debian_field_mapping(self, analysis: FieldAnalysis) -> Dict[str, Any]:
        """Suggest Debian-specific field mapping for parser"""
        mapping = {
            'source_field': analysis.field_path,
            'target_field': analysis.field_name,
            'required': analysis.is_required,
            'data_type': list(analysis.data_types)[0] if len(analysis.data_types) == 1 else 'mixed'
        }
        
        # Add Debian-specific handling based on patterns
        if 'cve_id' in analysis.value_patterns:
            mapping['parser_function'] = 'normalize_cve_id'
            mapping['validation'] = 'validate_cve_format'
        elif 'debian_release' in analysis.value_patterns:
            mapping['parser_function'] = 'normalize_debian_release'
            mapping['validation'] = 'validate_debian_release'
        elif 'debian_urgency' in analysis.value_patterns:
            mapping['parser_function'] = 'normalize_debian_urgency'
            mapping['validation'] = 'validate_debian_urgency'
        elif 'debian_status' in analysis.value_patterns:
            mapping['parser_function'] = 'normalize_debian_status'
            mapping['validation'] = 'validate_debian_status'
        elif 'debian_version' in analysis.value_patterns:
            mapping['parser_function'] = 'parse_debian_version'
            mapping['validation'] = 'validate_debian_version'
        elif 'debian_bug_id' in analysis.value_patterns:
            mapping['parser_function'] = 'normalize_debian_bug_id'
            mapping['validation'] = 'validate_debian_bug_id'
        elif 'url' in analysis.value_patterns:
            mapping['parser_function'] = 'validate_url'
        elif 'enumerated' in analysis.value_patterns:
            mapping['parser_function'] = 'normalize_enum_value'
            mapping['allowed_values'] = list(analysis.unique_values)
        
        return mapping
    
    def save_debian_analysis_report(self, analysis: DebianDataStructureAnalysis, output_dir: str = None) -> str:
        """Save comprehensive Debian analysis report"""
        if output_dir is None:
            output_dir = current_dir / "reports"
        
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Generate report
        report_file = output_path / f"debian_structure_analysis.json"
        
        # Convert analysis to serializable format
        report_data = {
            'source_name': analysis.source_name,
            'total_records': analysis.total_records,
            'total_packages': analysis.total_packages,
            'total_cves': analysis.total_cves,
            'analysis_timestamp': analysis.analysis_timestamp,
            'debian_releases': analysis.debian_releases,
            'summary': {
                'total_fields': len(analysis.fields),
                'required_fields': len([f for f in analysis.fields.values() if f.is_required]),
                'nested_fields': len([f for f in analysis.fields.values() if f.is_nested]),
                'debian_specific_fields': len([f for f in analysis.fields.values() if any(p.startswith('debian_') for p in f.value_patterns)]),
                'data_types_found': list(set().union(*[f.data_types for f in analysis.fields.values()]))
            },
            'fields': {
                name: {
                    'field_name': field.field_name,
                    'field_path': field.field_path,
                    'data_types': list(field.data_types),
                    'sample_values': field.sample_values,
                    'null_percentage': field.null_count / max(field.total_count, 1) * 100,
                    'unique_values_count': len(field.unique_values),
                    'value_patterns': field.value_patterns,
                    'is_required': field.is_required,
                    'is_nested': field.is_nested
                }
                for name, field in analysis.fields.items()
            },
            'nested_structures': analysis.nested_structures,
            'data_patterns': analysis.data_patterns,
            'package_patterns': analysis.package_patterns,
            'recommendations': analysis.recommendations,
            'parser_suggestions': analysis.parser_suggestions
        }
        
        # Save report
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        logger.info(f"📄 Debian analysis report saved: {report_file}")
        
        # Generate human-readable summary
        summary_file = output_path / f"debian_analysis_summary.txt"
        with open(summary_file, 'w') as f:
            f.write(self._generate_debian_summary(analysis, report_data))
        
        logger.info(f"📄 Human-readable summary saved: {summary_file}")
        
        return str(report_file)
    
    def _generate_debian_summary(self, analysis: DebianDataStructureAnalysis, report_data: Dict) -> str:
        """Generate human-readable Debian analysis summary"""
        summary = f"""
# Debian Security Tracker Data Structure Analysis

## Summary
- **Total CVE Records Analyzed**: {analysis.total_records:,}
- **Total Packages Analyzed**: {analysis.total_packages:,}
- **Unique CVEs Found**: {analysis.total_cves:,}
- **Analysis Date**: {analysis.analysis_timestamp}
- **Total Fields Found**: {len(analysis.fields):,}
- **Required Fields**: {report_data['summary']['required_fields']}
- **Debian-Specific Fields**: {report_data['summary']['debian_specific_fields']}

## Debian Releases Found
{', '.join(analysis.debian_releases)}

## Package Analysis
- **Most Vulnerable Packages**: {', '.join(list(analysis.package_patterns['most_vulnerable_packages'].keys())[:5])}
- **Average CVEs per Package**: {analysis.package_patterns['average_cves_per_package']:.1f}

## Required Fields Analysis
"""
        
        required_fields = [f for f in analysis.fields.values() if f.is_required]
        for field in sorted(required_fields, key=lambda x: x.field_path)[:10]:  # Top 10
            summary += f"\n### {field.field_path}\n"
            summary += f"- **Data Types**: {', '.join(field.data_types)}\n"
            summary += f"- **Patterns**: {', '.join(field.value_patterns) if field.value_patterns else 'None'}\n"
            summary += f"- **Sample Values**: {', '.join(str(v) for v in field.sample_values[:3])}...\n"
        
        summary += f"\n## Debian-Specific Recommendations\n"
        for i, rec in enumerate(analysis.recommendations, 1):
            summary += f"{i}. {rec}\n"
        
        summary += f"\n## Parser Implementation\n"
        suggestions = analysis.parser_suggestions
        summary += f"- **Required Transformations**: {', '.join(suggestions['transformation_functions'])}\n"
        summary += f"- **Debian Releases to Handle**: {len(analysis.debian_releases)}\n"
        summary += f"- **Field Mappings**: {len(suggestions['field_mappings'])} mappings generated\n"
        
        return summary

async def main():
    """Main execution function for Debian data structure analysis"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Analyze Debian Security Tracker data structure')
    parser.add_argument('--max-packages', type=int, default=100,
                       help='Maximum packages to analyze (default: 100)')
    parser.add_argument('--output-dir', default=None,
                       help='Directory for output reports (defaults to ./output/data_downloads)')
    parser.add_argument('--download-only', action='store_true',
                       help='Only download and save data as JSON file')
    parser.add_argument('--analyze-file', 
                       help='Analyze data from previously saved JSON file')
    parser.add_argument('--update-parser', action='store_true',
                       help='Auto-update the Debian parser based on analysis')
    
    args = parser.parse_args()
    
    print(f"🚀 Starting Debian Security Tracker data structure analysis")
    
    async with DebianDataStructureAnalyzer() as analyzer:
        try:
            if args.download_only:
                # Download and save data only
                print(f"📥 Downloading Debian data...")
                data_file = await analyzer.download_and_save_debian_data(args.output_dir)
                print(f"✅ Data saved: {data_file}")
                return
            
            elif args.analyze_file:
                # Analyze from saved file
                print(f"📂 Analyzing data from file: {args.analyze_file}")
                analysis = await analyzer.analyze_from_saved_file(args.analyze_file, args.max_packages)
            
            else:
                # Live analysis
                print(f"📊 Will analyze up to {args.max_packages} packages")
                analysis = await analyzer.analyze_debian_data(args.max_packages)
            
            # Save report
            report_path = analyzer.save_debian_analysis_report(analysis, args.output_dir)
            print(f"✅ Analysis completed successfully!")
            print(f"📄 Report saved: {report_path}")
            
            # Print summary
            print(f"\n📋 DEBIAN ANALYSIS SUMMARY:")
            print(f"CVE Records: {analysis.total_records:,}")
            print(f"Packages: {analysis.total_packages:,}")
            print(f"Unique CVEs: {analysis.total_cves:,}")
            print(f"Total Fields: {len(analysis.fields):,}")
            print(f"Required Fields: {len([f for f in analysis.fields.values() if f.is_required])}")
            print(f"Debian Releases: {', '.join(analysis.debian_releases)}")
            
            if analysis.recommendations:
                print(f"\n💡 TOP RECOMMENDATIONS:")
                for i, rec in enumerate(analysis.recommendations[:3], 1):
                    print(f"  {i}. {rec}")
            
            if args.update_parser:
                print(f"\n🔧 Auto-updating Debian parser...")
                # This would call parser update functionality
                print(f"Parser update functionality would be implemented here")
            
        except Exception as e:
            print(f"❌ Analysis failed: {e}")
            sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())