#!/usr/bin/env python3
"""
Debian Security Tracker Parser

Parses Debian Security Tracker JSON format into standardized vulnerability data.
Handles Debian-specific fields, package information, and advisory details.

ENHANCED: Now supports loading from saved JSON files for offline processing.

OBJECTIVE:
Parses Debian Security Tracker JSON format into standardized vulnerability data. 
Handles Debian-specific fields, package information, and advisory details.

IMPLEMENTATION STAGES:
Stage 1: JSON Structure Parsing ✓
Stage 2: Debian-Specific Data Extraction ✓
Stage 3: Data Enrichment ✓
Stage 4: JSON File Loading ✓ (NEW)

RELATIONS TO LOCAL CODES:
- Inherits: sources/base/base_parser.py
- Uses: sources/base/data_normalizer.py for schema conversion
- Integrates: Debian-specific configurations

RELATIONS TO WHOLE VUL_DB:
- Data Flow: Feeds to DataNormalizer → CommonLoader → Database
- Schema: Converts to common vulnerability schema
- Quality: Maintains data quality standards
"""

import re
import json
import logging
import sys
from datetime import datetime
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
from pathlib import Path

# Add vuln_db root to Python path for imports
current_dir = Path(__file__).resolve().parent
vuln_db_root = current_dir.parent.parent.parent
sys.path.insert(0, str(vuln_db_root))

# Try to import base classes, fallback to simple implementations if not available
try:
    from sources.base.base_parser import BaseParser
    from sources.base.exceptions import ParseException
except ImportError:
    # Fallback implementations
    class BaseParser:
        def __init__(self, source_name: str, config: Dict[str, Any]):
            self.source_name = source_name
            self.config = config
    
    class ParseException(Exception):
        pass


class DebianParser(BaseParser):
    """Parser for Debian Security Tracker data"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Debian parser"""
        super().__init__("debian", config)
        self.logger = logging.getLogger("parser.debian")
        
        # Debian-specific parsing configuration
        self.severity_mapping = {
            'unimportant': 'LOW',
            'low': 'LOW', 
            'medium': 'MEDIUM',
            'high': 'HIGH',
            'critical': 'CRITICAL'
        }
        
        # Debian release codenames to versions
        self.release_mapping = {
            'sid': 'unstable',
            'trixie': '13',
            'bookworm': '12',
            'bullseye': '11',
            'buster': '10',
            'stretch': '9'
        }
    
    def load_from_json_file(self, json_file_path: str) -> List[Dict[str, Any]]:
        """
        Load and parse Debian data from saved JSON file
        
        Args:
            json_file_path: Path to the saved Debian JSON file
            
        Returns:
            List of normalized vulnerability records ready for database insertion
        """
        try:
            self.logger.info(f"📂 Loading Debian data from: {json_file_path}")
            
            # Load JSON file
            with open(json_file_path, 'r') as f:
                file_data = json.load(f)
            
            # Extract data and metadata
            if 'data' in file_data and 'metadata' in file_data:
                raw_data = file_data['data']
                metadata = file_data['metadata']
                self.logger.info(f"✓ Loaded saved data from {metadata.get('download_timestamp', 'unknown time')}")
                self.logger.info(f"✓ Original file contains {metadata.get('total_packages', 0):,} packages")
                self.logger.info(f"✓ Original file contains {metadata.get('total_cves_found', 0):,} CVEs")
            else:
                # Assume it's raw data without metadata wrapper
                raw_data = file_data
                self.logger.info("✓ Loaded raw data file without metadata")
            
            # Convert Debian structure to normalized records
            normalized_records = self._convert_debian_structure_to_records(raw_data)
            self.logger.info(f"✓ Converted to {len(normalized_records)} vulnerability records")
            
            # Parse the normalized records
            parsed_vulnerabilities = self.parse_raw_data(normalized_records)
            self.logger.info(f"✅ Successfully parsed {len(parsed_vulnerabilities)} vulnerabilities from JSON file")
            
            # UPDATED: Save parsing report in standardized output structure
            self._save_parsing_report(json_file_path, len(normalized_records), len(parsed_vulnerabilities), metadata)
            
            return parsed_vulnerabilities
            
        except Exception as e:
            self.logger.error(f"❌ Failed to load from JSON file: {e}")
            raise ParseException(f"Failed to load Debian data from JSON file: {e}")
    
    def _save_parsing_report(self, json_file_path: str, total_records: int, parsed_count: int, metadata: dict):
        """Save parsing report in standardized output structure"""
        try:
            # Create output directory
            output_dir = Path(__file__).parent / "output" / "parsing_reports"
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate report
            report = {
                'parsing_timestamp': datetime.utcnow().isoformat(),
                'source_json_file': json_file_path,
                'json_metadata': metadata,
                'parsing_results': {
                    'total_records_in_json': total_records,
                    'successfully_parsed': parsed_count,
                    'parsing_success_rate': (parsed_count / total_records * 100) if total_records > 0 else 0,
                    'failed_records': total_records - parsed_count
                },
                'parser_info': self.get_parser_info()
            }
            
            # Save report
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            report_file = output_dir / f"debian_parsing_report_{timestamp}.json"
            
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            self.logger.info(f"📄 Parsing report saved: {report_file}")
            
        except Exception as e:
            self.logger.warning(f"Failed to save parsing report: {e}")

    def _convert_debian_structure_to_records(self, debian_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Convert Debian {package: {CVE: data}} structure to normalized records
        
        Args:
            debian_data: Raw Debian data in {package: {CVE: vulnerability_data}} format
            
        Returns:
            List of normalized vulnerability records
        """
        records = []
        
        for package_name, package_data in debian_data.items():
            if not isinstance(package_data, dict):
                continue
            
            # Process CVEs within this package
            for cve_id, cve_data in package_data.items():
                if not cve_id.startswith('CVE-') or not isinstance(cve_data, dict):
                    continue
                
                # Create normalized record
                record = {
                    'cve_id': cve_id,
                    'package_name': package_name,
                    'description': cve_data.get('description', ''),
                    'scope': cve_data.get('scope', 'unknown'),
                    'debianbug': cve_data.get('debianbug'),
                    'releases': cve_data.get('releases', {}),
                    'packages': self._extract_packages_from_releases(package_name, cve_data.get('releases', {})),
                    'debian_metadata': {
                        'source_package': package_name,
                        'total_releases': len(cve_data.get('releases', {})),
                        'has_debianbug': 'debianbug' in cve_data,
                        'scope': cve_data.get('scope', 'unknown')
                    },
                    'raw_data': cve_data
                }
                
                records.append(record)
        
        return records
    
    def _extract_packages_from_releases(self, package_name: str, releases: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract package information from Debian releases structure
        
        Args:
            package_name: Main package name
            releases: Releases data from Debian JSON
            
        Returns:
            List of package information dictionaries
        """
        packages = []
        
        for release_name, release_data in releases.items():
            if not isinstance(release_data, dict):
                continue
            
            # Extract package info for this release
            package_info = {
                'package_name': package_name,
                'release': release_name,
                'status': release_data.get('status'),
                'urgency': release_data.get('urgency'),
                'fixed_version': release_data.get('fixed_version'),
                'repositories': release_data.get('repositories', {}),
                'repository': 'main'  # Default repository
            }
            
            packages.append(package_info)
        
        return packages

    def parse_raw_data(self, raw_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse raw Debian vulnerability data into standardized format
        
        Args:
            raw_data: List of raw vulnerability dictionaries from fetcher
            
        Returns:
            List of parsed and normalized vulnerability dictionaries
        """
        try:
            self.logger.info(f"Starting to parse {len(raw_data)} Debian vulnerabilities")
            parsed_vulnerabilities = []
            
            for vuln_data in raw_data:
                try:
                    # Stage 1: JSON Structure Parsing
                    if 'cve_id' in vuln_data:
                        # This is a CVE-based vulnerability
                        parsed_vuln = self._parse_cve_vulnerability(vuln_data)
                    elif 'advisory_id' in vuln_data:
                        # This is a DSA/DLA advisory
                        parsed_vuln = self._parse_advisory_vulnerability(vuln_data)
                    else:
                        self.logger.warning(f"Unknown vulnerability format: {vuln_data}")
                        continue
                    
                    if parsed_vuln:
                        parsed_vulnerabilities.append(parsed_vuln)
                        
                except Exception as e:
                    self.logger.error(f"Error parsing individual vulnerability: {e}")
                    continue
            
            self.logger.info(f"Successfully parsed {len(parsed_vulnerabilities)} Debian vulnerabilities")
            return parsed_vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error parsing Debian vulnerabilities: {e}")
            raise ParseException(f"Failed to parse Debian vulnerabilities: {e}")
    
    def _parse_cve_vulnerability(self, vuln_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse CVE-based vulnerability from Debian Security Tracker"""
        try:
            cve_id = vuln_data.get('cve_id', '')
            if not cve_id or not cve_id.startswith('CVE-'):
                return None
            
            # Stage 1: Basic field extraction
            description = vuln_data.get('description', '')
            packages = vuln_data.get('packages', [])
            debian_metadata = vuln_data.get('debian_metadata', {})
            
            # Stage 2: Debian-Specific Data Extraction
            affected_packages = self._extract_affected_packages(packages)
            severity = self._determine_severity(packages)
            
            # Stage 3: Data Enrichment
            references = self._extract_references(debian_metadata, cve_id)
            
            # Create standardized vulnerability record
            parsed_vulnerability = {
                'cve_id': cve_id,
                'description': description,
                'severity': severity,
                'source': 'debian',
                'source_url': f"https://security-tracker.debian.org/tracker/{cve_id}",
                'affected_packages': affected_packages,
                'references': references,
                'published_date': self._extract_published_date(vuln_data),
                'last_modified_date': vuln_data.get('last_modified'),
                'debian_specific': {
                    'scope': debian_metadata.get('scope'),
                    'debianbug': debian_metadata.get('debianbug'),
                    'source_type': vuln_data.get('source_type', 'main')
                },
                'raw_data': vuln_data.get('raw_data', {})
            }
            
            return parsed_vulnerability
            
        except Exception as e:
            self.logger.error(f"Error parsing CVE vulnerability {vuln_data.get('cve_id')}: {e}")
            return None
    
    def _parse_advisory_vulnerability(self, vuln_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse DSA/DLA advisory vulnerability"""
        try:
            advisory_id = vuln_data.get('advisory_id', '')
            advisory_type = vuln_data.get('advisory_type', '')
            
            if not advisory_id:
                return None
            
            # Extract CVE IDs from advisory
            cves = vuln_data.get('cves', [])
            if isinstance(cves, str):
                cves = [cves]
            
            # Create vulnerability record for advisory
            parsed_vulnerability = {
                'advisory_id': advisory_id,
                'advisory_type': advisory_type,
                'title': vuln_data.get('title', ''),
                'description': vuln_data.get('description', ''),
                'cve_ids': cves,
                'source': 'debian',
                'source_url': f"https://security-tracker.debian.org/tracker/{advisory_id}",
                'affected_packages': self._extract_advisory_packages(vuln_data.get('packages', [])),
                'published_date': self._parse_debian_date(vuln_data.get('date')),
                'severity': self._determine_advisory_severity(advisory_type),
                'debian_specific': {
                    'advisory_type': advisory_type,
                    'source_type': 'advisory'
                },
                'raw_data': vuln_data.get('raw_data', {})
            }
            
            return parsed_vulnerability
            
        except Exception as e:
            self.logger.error(f"Error parsing advisory {vuln_data.get('advisory_id')}: {e}")
            return None
    
    def _extract_affected_packages(self, packages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract and normalize affected package information"""
        affected_packages = []
        
        for package in packages:
            try:
                # Skip if package data is invalid or missing required fields
                if not isinstance(package, dict):
                    continue
                    
                package_name = package.get('package_name', '')
                if not package_name or package_name == 'repositories':
                    # Skip invalid or metadata entries
                    continue
                
                # Safely get status and urgency with None checks
                status = package.get('status')
                urgency = package.get('urgency')
                
                package_info = {
                    'name': package_name,
                    'ecosystem': 'debian',
                    'debian_release': package.get('release', ''),
                    'debian_release_version': self.release_mapping.get(package.get('release', ''), ''),
                    'status': status if status is not None else '',
                    'urgency': urgency if urgency is not None else '',
                    'fixed_version': package.get('fixed_version'),
                    'repository': package.get('repository', 'main')
                }
                
                # Determine if package is vulnerable (with None check)
                if status is not None:
                    package_info['vulnerable'] = status.lower() in ['open', 'undetermined', 'todo']
                else:
                    package_info['vulnerable'] = False
                
                affected_packages.append(package_info)
                
            except Exception as e:
                self.logger.warning(f"Error processing package {package}: {e}")
                continue
        
        return affected_packages
    
    def _extract_advisory_packages(self, packages: List[str]) -> List[Dict[str, Any]]:
        """Extract package information from advisory packages list"""
        affected_packages = []
        
        for package_name in packages:
            if isinstance(package_name, str):
                package_info = {
                    'name': package_name,
                    'ecosystem': 'debian',
                    'vulnerable': True  # Assume vulnerable if in advisory
                }
                affected_packages.append(package_info)
        
        return affected_packages
    
    def _determine_severity(self, packages: List[Dict[str, Any]]) -> str:
        """Determine overall severity from package urgency levels"""
        urgencies = []
        
        for package in packages:
            urgency = package.get('urgency')
            if urgency is not None and urgency.lower() in self.severity_mapping:
                urgencies.append(self.severity_mapping[urgency.lower()])
        
        if not urgencies:
            return 'UNKNOWN'
        
        # Return highest severity found
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
        for severity in severity_order:
            if severity in urgencies:
                return severity
        
        return 'UNKNOWN'
    
    def _determine_advisory_severity(self, advisory_type: str) -> str:
        """Determine severity based on advisory type"""
        if advisory_type.upper() == 'DSA':
            return 'HIGH'  # DSAs are generally high severity
        elif advisory_type.upper() == 'DLA':
            return 'MEDIUM'  # DLAs are generally medium severity
        return 'UNKNOWN'
    
    def _extract_references(self, debian_metadata: Dict[str, Any], cve_id: str) -> List[Dict[str, str]]:
        """Extract reference URLs and information"""
        references = []
        
        # Add Debian Security Tracker reference
        references.append({
            'url': f"https://security-tracker.debian.org/tracker/{cve_id}",
            'type': 'vendor',
            'source': 'debian_security_tracker'
        })
        
        # Add Debian bug reference if available
        debianbug = debian_metadata.get('debianbug')
        if debianbug:
            references.append({
                'url': f"https://bugs.debian.org/{debianbug}",
                'type': 'issue-tracking',
                'source': 'debian_bts'
            })
        
        return references
    
    def _extract_published_date(self, vuln_data: Dict[str, Any]) -> Optional[str]:
        """Extract published date from vulnerability data"""
        # Debian Security Tracker doesn't provide explicit published dates
        # Use last_modified or current time
        last_modified = vuln_data.get('last_modified')
        if last_modified:
            return last_modified
        
        return datetime.utcnow().isoformat()
    
    def _parse_debian_date(self, date_str: Optional[str]) -> Optional[str]:
        """Parse Debian date format to ISO format"""
        if not date_str:
            return None
        
        try:
            # Debian uses YYYY-MM-DD format
            parsed_date = datetime.strptime(date_str, '%Y-%m-%d')
            return parsed_date.isoformat()
        except (ValueError, TypeError):
            self.logger.warning(f"Could not parse Debian date: {date_str}")
            return None
    
    def _validate_cve_id(self, cve_id: str) -> bool:
        """Validate CVE ID format"""
        cve_pattern = r'^CVE-\d{4}-\d{4,}$'
        return bool(re.match(cve_pattern, cve_id))
    
    def get_parser_info(self) -> Dict[str, Any]:
        """Return information about this parser"""
        return {
            'name': 'Debian Security Tracker Parser',
            'version': '1.0.0',
            'supported_formats': ['debian_json', 'dsa', 'dla'],
            'output_schema': 'common_vulnerability_schema',
            'features': [
                'CVE parsing',
                'DSA/DLA advisory parsing', 
                'Package information extraction',
                'Debian release mapping',
                'Severity determination'
            ]
        }


def main():
    """Main execution function to run the Debian parser on downloaded data"""
    import argparse
    import glob
    
    parser = argparse.ArgumentParser(description='Parse Debian Security Tracker data from downloaded JSON files')
    parser.add_argument('--input-file', help='Specific JSON file to parse')
    parser.add_argument('--latest', action='store_true', help='Parse the latest downloaded file (default)')
    parser.add_argument('--output-dir', help='Output directory for parsed data')
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    
    try:
        # Initialize parser with default config
        config = {
            'name': 'debian_security_tracker',
            'url': 'https://security-tracker.debian.org/tracker/data/json',
            'timeout_seconds': 30
        }
        
        debian_parser = DebianParser(config)
        
        # Determine input file
        if args.input_file:
            input_file = args.input_file
        else:
            # Find the latest downloaded file
            data_downloads_dir = current_dir / "output" / "data_downloads"
            if not data_downloads_dir.exists():
                logger.error(f"Data downloads directory not found: {data_downloads_dir}")
                return
            
            # Find the most recent JSON file
            json_files = glob.glob(str(data_downloads_dir / "debian_security_tracker_data_*.json"))
            if not json_files:
                logger.error("No Debian data files found in downloads directory")
                return
            
            # Sort by modification time and get the latest
            latest_file = max(json_files, key=lambda x: Path(x).stat().st_mtime)
            input_file = latest_file
            logger.info(f"Using latest downloaded file: {input_file}")
        
        # Parse the data
        logger.info(f"🚀 Starting Debian data parsing from: {input_file}")
        parsed_vulnerabilities = debian_parser.load_from_json_file(input_file)
        
        # Save parsed data to output directory
        if args.output_dir:
            output_dir = Path(args.output_dir)
        else:
            output_dir = current_dir / "output" / "parsed_data"
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate output filename
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_file = output_dir / f"debian_parsed_vulnerabilities_{timestamp}.json"
        
        # Save parsed data
        output_data = {
            'parsing_timestamp': datetime.utcnow().isoformat(),
            'source_file': input_file,
            'total_vulnerabilities': len(parsed_vulnerabilities),
            'vulnerabilities': parsed_vulnerabilities
        }
        
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2, default=str)
        
        logger.info(f"✅ Parsing completed successfully!")
        logger.info(f"📊 Total vulnerabilities parsed: {len(parsed_vulnerabilities):,}")
        logger.info(f"💾 Parsed data saved to: {output_file}")
        
        # Print summary
        if parsed_vulnerabilities:
            cve_count = sum(1 for v in parsed_vulnerabilities if v.get('cve_id'))
            advisory_count = sum(1 for v in parsed_vulnerabilities if v.get('advisory_id'))
            logger.info(f"📋 Summary:")
            logger.info(f"   • CVE vulnerabilities: {cve_count:,}")
            logger.info(f"   • Advisory vulnerabilities: {advisory_count:,}")
            logger.info(f"   • Total records: {len(parsed_vulnerabilities):,}")
        
    except Exception as e:
        logger.error(f"❌ Parsing failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()