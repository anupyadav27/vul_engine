#!/usr/bin/env python3
"""
NVD Data Parser - Step 2 (Simplified)

APPROACH:
1. Parse NVD batch files starting from batch 15+ (2002+ CVEs)
2. Extract core CVE data: ID, description, dates, CVSS scores, CWE, CPE, references
3. Robust error handling to process all files successfully
4. Skip problematic pre-2002 legacy data

INPUT SOURCES:
- NVD batch files (nvdcve-batch-015.json to nvdcve-batch-154.json)
- Focus on modern CVEs with complete data

OUTPUTS:
- Standardized CVE objects with core vulnerability data
- CVSS scoring data (v2, v3.0, v3.1, v4.0)
- CPE configuration data
- CWE weakness mappings
- Parsing statistics and validation reports
"""

import sys
import asyncio
import logging
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

# Add vuln_db root to Python path
current_dir = Path(__file__).resolve().parent
vuln_db_root = current_dir.parent.parent.parent
sys.path.insert(0, str(vuln_db_root))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class CVSSScore:
    """CVSS score information"""
    version: str
    vector_string: str
    base_score: float
    base_severity: str
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None

@dataclass
class CPEMatch:
    """CPE (Common Platform Enumeration) match data"""
    cpe23_uri: str
    vulnerable: bool
    version_start_including: Optional[str] = None
    version_start_excluding: Optional[str] = None
    version_end_including: Optional[str] = None
    version_end_excluding: Optional[str] = None

@dataclass
class StandardizedCVE:
    """Standardized CVE object for database insertion"""
    cve_id: str
    description: str
    published_date: datetime
    last_modified_date: datetime
    source: str = "nvd"
    source_url: str = ""
    
    # Severity and scoring
    cvss_v2: Optional[CVSSScore] = None
    cvss_v3_0: Optional[CVSSScore] = None
    cvss_v3_1: Optional[CVSSScore] = None
    cvss_v4_0: Optional[CVSSScore] = None
    severity: str = "UNKNOWN"
    
    # Technical details
    cwe_ids: List[str] = None
    cpe_matches: List[CPEMatch] = None
    references: List[str] = None
    
    # Raw data preservation
    nvd_raw_data: Dict = None
    
    def __post_init__(self):
        if self.cwe_ids is None:
            self.cwe_ids = []
        if self.cpe_matches is None:
            self.cpe_matches = []
        if self.references is None:
            self.references = []

class NVDDataParser:
    """Simplified NVD data parser focused on core CVE data"""
    
    def __init__(self):
        self.input_dir = current_dir / "output" / "data_downloads"
        self.output_dir = current_dir / "output" / "parsed_data"
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Statistics tracking
        self.stats = {
            'files_processed': 0,
            'total_cves_parsed': 0,
            'parsing_errors': 0,
            'cvss_version_counts': {'v2': 0, 'v3.0': 0, 'v3.1': 0, 'v4.0': 0},
            'severity_counts': {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0, 'UNKNOWN': 0},
            'pre_2002_cves_skipped': 0,
            'rejected_cves': 0,
            'cves_with_configurations': 0,
            'cves_with_cisa_alerts': 0
        }
        
        # Track per-file parsed outputs
        self.parsed_files_manifest: List[Dict[str, Any]] = []
    
    async def parse_all_nvd_data(self) -> Dict[str, Any]:
        """Main method to parse all downloaded NVD batch data"""
        logger.info("🚀 Starting simplified NVD batch data parsing...")
        start_time = datetime.now(timezone.utc)
        
        try:
            # Parse all batch files starting from batch 15+ (2002+ CVEs)
            await self.parse_all_batch_files()
            
            # Generate parsing report and manifest
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            
            results = {
                'success': True,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration,
                'total_cves_parsed': self.stats['total_cves_parsed'],
                'parsing_statistics': self.stats,
                'manifest_file': str(self.output_dir / "nvd_parsed_manifest.json"),
                'parsed_files_count': len(self.parsed_files_manifest)
            }
            
            await self.save_manifest()
            await self.save_parsing_report(results)
            self.log_parsing_summary(results)
            
            return results
            
        except Exception as e:
            logger.error(f"❌ Error during NVD data parsing: {e}")
            return {
                'success': False,
                'error': str(e),
                'total_cves_parsed': 0,
                'parsing_statistics': self.stats
            }
    
    async def parse_all_batch_files(self) -> None:
        """Find and parse all NVD batch files starting from batch 15+, writing per-file outputs"""
        
        # Find all batch files
        batch_files = list(self.input_dir.glob("nvdcve-batch-*.json"))
        
        if not batch_files:
            logger.warning("⚠️ No NVD batch files found for parsing")
            return
        
        # Sort files numerically by batch number
        batch_files.sort(key=lambda x: int(x.stem.split('-')[-1]))
        
        # Filter to start from batch 15+ (where 2002+ CVEs begin)
        filtered_batch_files = [f for f in batch_files if int(f.stem.split('-')[-1]) >= 15]
        
        logger.info(f"📁 Found {len(batch_files)} total NVD batch files")
        logger.info(f"📁 Processing {len(filtered_batch_files)} batch files (batch 15+) to focus on 2002+ CVEs")
        logger.info(f"   Expected CVEs to process: {len(filtered_batch_files) * 2000:,}")
        
        for file_path in filtered_batch_files:
            batch_num = int(file_path.stem.split('-')[-1])
            try:
                logger.info(f"   📄 Parsing batch {batch_num:03d}: {file_path.name}")
                
                # Parse the batch file with robust error handling
                cves = await self.parse_batch_file(file_path)
                
                # Persist per-file parsed output
                saved_path, count = await self.save_parsed_batch(file_path, cves)
                self.parsed_files_manifest.append({
                    'batch': batch_num,
                    'source_file': str(file_path),
                    'parsed_file': saved_path,
                    'cve_count': count
                })
                
                self.stats['files_processed'] += 1
                logger.info(f"     ✅ Parsed {count:,} CVEs from batch {batch_num:03d}")
                
                # Log progress every 20 files
                if batch_num % 20 == 0:
                    logger.info(f"📊 Progress: {self.stats['total_cves_parsed']:,} total CVEs parsed so far")
                
            except Exception as e:
                logger.error(f"     ❌ Error parsing {file_path.name}: {e}")
                self.stats['parsing_errors'] += 1
                # Continue processing other files instead of failing completely
    
    async def parse_batch_file(self, file_path: Path) -> List[StandardizedCVE]:
        """Parse a single NVD batch file with robust error handling"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Validate batch file structure
            if 'vulnerabilities' not in data:
                logger.error(f"Invalid batch file structure in {file_path.name}")
                return []
            
            vulnerabilities = data['vulnerabilities']
            return await self.parse_vulnerabilities(vulnerabilities)
                
        except Exception as e:
            logger.error(f"❌ Error reading {file_path}: {e}")
            return []
    
    async def parse_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[StandardizedCVE]:
        """Parse vulnerability data from a batch with robust error handling"""
        cves = []
        
        for vuln_data in vulnerabilities:
            try:
                cve_data = vuln_data.get('cve', {})
                cve_id = cve_data.get('id', '')
                
                if not cve_id:
                    continue
                
                # Extract CVE year for filtering
                cve_year = self.extract_cve_year(cve_id)
                
                # Skip CVEs before 2002 (legacy data with issues)
                if cve_year and cve_year < 2002:
                    self.stats['pre_2002_cves_skipped'] += 1
                    continue
                
                # Skip rejected CVEs
                vuln_status = cve_data.get('vulnStatus', '')
                if vuln_status == 'Rejected':
                    self.stats['rejected_cves'] += 1
                    continue
                
                # Extract description with robust handling
                description = self.extract_description(cve_data)
                
                # Skip only if description is completely empty or too short
                if not description or len(description.strip()) < 20:
                    continue
                
                # Parse dates with error handling
                try:
                    published_date = self.parse_datetime(cve_data.get('published', ''))
                    last_modified_date = self.parse_datetime(cve_data.get('lastModified', ''))
                except Exception:
                    # Use current time as fallback for date parsing errors
                    published_date = datetime.now(timezone.utc)
                    last_modified_date = datetime.now(timezone.utc)
                
                # Create standardized CVE object
                standardized_cve = StandardizedCVE(
                    cve_id=cve_id,
                    description=description,
                    published_date=published_date,
                    last_modified_date=last_modified_date,
                    source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    nvd_raw_data=vuln_data
                )
                
                # Extract data with error handling
                try:
                    # Extract CVSS scores (all versions including v4.0)
                    self.extract_cvss_scores(standardized_cve, cve_data)
                    
                    # Extract CWE information
                    standardized_cve.cwe_ids = self.extract_cwe_ids(cve_data)
                    
                    # Extract CPE matches
                    standardized_cve.cpe_matches = self.extract_cpe_matches(cve_data)
                    
                    # Extract references
                    standardized_cve.references = self.extract_references(cve_data)
                    
                    # Determine overall severity
                    standardized_cve.severity = self.determine_severity(standardized_cve)
                    
                except Exception as e:
                    # Continue with partial data rather than skipping entirely
                    logger.debug(f"Data extraction warning for {cve_id}: {e}")
                    standardized_cve.severity = 'UNKNOWN'
                
                # Track additional statistics
                if standardized_cve.cpe_matches:
                    self.stats['cves_with_configurations'] += 1
                
                if 'cisaExploitAdd' in cve_data:
                    self.stats['cves_with_cisa_alerts'] += 1
                
                cves.append(standardized_cve)
                self.update_statistics(standardized_cve)
                
            except Exception as e:
                logger.debug(f"Skipping CVE due to parsing error: {e}")
                # Continue processing other CVEs rather than failing completely
        
        return cves
    
    def extract_cve_year(self, cve_id: str) -> Optional[int]:
        """Extract year from CVE ID (e.g., CVE-1999-0001 -> 1999)"""
        try:
            parts = cve_id.split('-')
            if len(parts) >= 2:
                return int(parts[1])
        except (ValueError, IndexError):
            pass
        return None

    def extract_description(self, cve_data: Dict) -> str:
        """Extract description from CVE data with robust handling"""
        descriptions = cve_data.get('descriptions', [])
        
        # Prefer English description
        for desc in descriptions:
            if desc.get('lang') == 'en':
                value = desc.get('value', '').strip()
                if value:
                    return value
        
        # Fallback to first available description
        for desc in descriptions:
            value = desc.get('value', '').strip()
            if value:
                return value
        
        return ""
    
    def extract_cvss_scores(self, cve: StandardizedCVE, cve_data: Dict):
        """Extract all CVSS scores from CVE data"""
        metrics = cve_data.get('metrics', {})
        
        # CVSS v4.0 (newest)
        if 'cvssMetricV40' in metrics and metrics['cvssMetricV40']:
            try:
                metric = metrics['cvssMetricV40'][0]
                cvss_data = metric.get('cvssData', {})
                cve.cvss_v4_0 = CVSSScore(
                    version='4.0',
                    vector_string=cvss_data.get('vectorString', ''),
                    base_score=float(cvss_data.get('baseScore', 0.0)),
                    base_severity=cvss_data.get('baseSeverity', 'UNKNOWN')
                )
            except (IndexError, ValueError, TypeError):
                pass
        
        # CVSS v3.1
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            try:
                metric = metrics['cvssMetricV31'][0]
                cvss_data = metric.get('cvssData', {})
                cve.cvss_v3_1 = CVSSScore(
                    version='3.1',
                    vector_string=cvss_data.get('vectorString', ''),
                    base_score=float(cvss_data.get('baseScore', 0.0)),
                    base_severity=cvss_data.get('baseSeverity', 'UNKNOWN'),
                    exploitability_score=metric.get('exploitabilityScore'),
                    impact_score=metric.get('impactScore')
                )
            except (IndexError, ValueError, TypeError):
                pass
        
        # CVSS v3.0
        if 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            try:
                metric = metrics['cvssMetricV30'][0]
                cvss_data = metric.get('cvssData', {})
                cve.cvss_v3_0 = CVSSScore(
                    version='3.0',
                    vector_string=cvss_data.get('vectorString', ''),
                    base_score=float(cvss_data.get('baseScore', 0.0)),
                    base_severity=cvss_data.get('baseSeverity', 'UNKNOWN'),
                    exploitability_score=metric.get('exploitabilityScore'),
                    impact_score=metric.get('impactScore')
                )
            except (IndexError, ValueError, TypeError):
                pass
        
        # CVSS v2
        if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            try:
                metric = metrics['cvssMetricV2'][0]
                cvss_data = metric.get('cvssData', {})
                score = float(cvss_data.get('baseScore', 0.0))
                cve.cvss_v2 = CVSSScore(
                    version='2.0',
                    vector_string=cvss_data.get('vectorString', ''),
                    base_score=score,
                    base_severity=self.cvss_v2_score_to_severity(score),
                    exploitability_score=metric.get('exploitabilityScore'),
                    impact_score=metric.get('impactScore')
                )
            except (IndexError, ValueError, TypeError):
                pass
    
    def cvss_v2_score_to_severity(self, score: float) -> str:
        """Convert CVSS v2 score to severity level"""
        if score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        elif score > 0.0:
            return 'LOW'
        else:
            return 'UNKNOWN'
    
    def extract_cwe_ids(self, cve_data: Dict) -> List[str]:
        """Extract CWE IDs from CVE data"""
        cwe_ids = []
        try:
            weaknesses = cve_data.get('weaknesses', [])
            for weakness in weaknesses:
                for desc in weakness.get('description', []):
                    cwe_id = desc.get('value', '')
                    if cwe_id.startswith('CWE-'):
                        cwe_ids.append(cwe_id)
        except Exception:
            pass
        return list(set(cwe_ids))  # Remove duplicates
    
    def extract_cpe_matches(self, cve_data: Dict) -> List[CPEMatch]:
        """Extract CPE matches from CVE data"""
        cpe_matches = []
        try:
            configurations = cve_data.get('configurations', [])
            for config in configurations:
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        match = CPEMatch(
                            cpe23_uri=cpe_match.get('criteria', ''),
                            vulnerable=cpe_match.get('vulnerable', False),
                            version_start_including=cpe_match.get('versionStartIncluding'),
                            version_start_excluding=cpe_match.get('versionStartExcluding'),
                            version_end_including=cpe_match.get('versionEndIncluding'),
                            version_end_excluding=cpe_match.get('versionEndExcluding')
                        )
                        cpe_matches.append(match)
        except Exception:
            pass
        return cpe_matches
    
    def extract_references(self, cve_data: Dict) -> List[str]:
        """Extract references from CVE data"""
        references = []
        try:
            for ref in cve_data.get('references', []):
                url = ref.get('url', '')
                if url:
                    references.append(url)
        except Exception:
            pass
        return references
    
    def determine_severity(self, cve: StandardizedCVE) -> str:
        """Determine overall severity from available CVSS scores"""
        # Prefer CVSS v4.0, then v3.1, then v3.0, then v2
        if cve.cvss_v4_0 and cve.cvss_v4_0.base_severity:
            return cve.cvss_v4_0.base_severity.upper()
        elif cve.cvss_v3_1 and cve.cvss_v3_1.base_severity:
            return cve.cvss_v3_1.base_severity.upper()
        elif cve.cvss_v3_0 and cve.cvss_v3_0.base_severity:
            return cve.cvss_v3_0.base_severity.upper()
        elif cve.cvss_v2 and cve.cvss_v2.base_severity:
            return cve.cvss_v2.base_severity.upper()
        else:
            return 'UNKNOWN'
    
    def parse_datetime(self, date_string: str) -> datetime:
        """Parse datetime string from NVD data with robust error handling"""
        if not date_string:
            return datetime.now(timezone.utc)
        
        # Handle different datetime formats
        formats = [
            '%Y-%m-%dT%H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%dT%H:%M:%SZ'
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(date_string.replace('Z', ''), fmt.replace('Z', ''))
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        
        # Fallback
        return datetime.now(timezone.utc)
    
    def update_statistics(self, cve: StandardizedCVE):
        """Update parsing statistics"""
        self.stats['total_cves_parsed'] += 1
        
        # CVSS version counts
        if cve.cvss_v2:
            self.stats['cvss_version_counts']['v2'] += 1
        if cve.cvss_v3_0:
            self.stats['cvss_version_counts']['v3.0'] += 1
        if cve.cvss_v3_1:
            self.stats['cvss_version_counts']['v3.1'] += 1
        if cve.cvss_v4_0:
            self.stats['cvss_version_counts']['v4.0'] += 1
        
        # Severity counts
        severity = cve.severity if cve.severity in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN'] else 'UNKNOWN'
        self.stats['severity_counts'][severity] += 1
    
    async def save_parsed_batch(self, source_file: Path, cves: List[StandardizedCVE]) -> (str, int):
        """Save parsed CVEs for a single batch to its own file and return (path, count)"""
        # Convert to serializable format
        serializable_cves = []
        for cve in cves:
            cve_dict = {
                'cve_id': cve.cve_id,
                'description': cve.description,
                'published_date': cve.published_date.isoformat(),
                'last_modified_date': cve.last_modified_date.isoformat(),
                'source': cve.source,
                'source_url': cve.source_url,
                'severity': cve.severity,
                'cwe_ids': cve.cwe_ids,
                'references': cve.references,
                'cvss_scores': {},
                'cpe_matches': [],
                'nvd_raw_data': cve.nvd_raw_data
            }
            # Add CVSS scores
            for version, score_obj in [
                ('v2', cve.cvss_v2), ('v3.0', cve.cvss_v3_0), 
                ('v3.1', cve.cvss_v3_1), ('v4.0', cve.cvss_v4_0)
            ]:
                if score_obj:
                    cve_dict['cvss_scores'][version] = {
                        'version': score_obj.version,
                        'vector_string': score_obj.vector_string,
                        'base_score': score_obj.base_score,
                        'base_severity': score_obj.base_severity,
                        'exploitability_score': score_obj.exploitability_score,
                        'impact_score': score_obj.impact_score
                    }
            # Add CPE matches
            for cpe_match in cve.cpe_matches:
                cve_dict['cpe_matches'].append({
                    'cpe23_uri': cpe_match.cpe23_uri,
                    'vulnerable': cpe_match.vulnerable,
                    'version_start_including': cpe_match.version_start_including,
                    'version_start_excluding': cpe_match.version_start_excluding,
                    'version_end_including': cpe_match.version_end_including,
                    'version_end_excluding': cpe_match.version_end_excluding
                })
            serializable_cves.append(cve_dict)
        
        # Write per-file output
        batch_num = int(Path(source_file).stem.split('-')[-1])
        output_file = self.output_dir / f"nvd_standardized_cves_batch_{batch_num:03d}.json"
        with open(output_file, 'w') as f:
            json.dump({
                'metadata': {
                    'total_cves': len(serializable_cves),
                    'processing_timestamp': datetime.now(timezone.utc).isoformat(),
                    'source': 'nvd_batch_files',
                    'parser_version': '2.1_simplified',
                    'source_file': str(source_file.name),
                    'batch_number': batch_num
                },
                'cves': serializable_cves
            }, f, indent=2)
        
        return str(output_file), len(serializable_cves)
    
    async def save_manifest(self):
        """Write a small manifest listing all per-file parsed outputs"""
        manifest_path = self.output_dir / "nvd_parsed_manifest.json"
        manifest = {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'parser_version': '2.1_simplified',
            'files': self.parsed_files_manifest,
            'totals': {
                'files': len(self.parsed_files_manifest),
                'cves': self.stats['total_cves_parsed']
            }
        }
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)
    
    async def save_parsing_report(self, results: Dict[str, Any]):
        """Save parsing report with statistics"""
        report_file = self.output_dir / "nvd_parsing_report.json"
        with open(report_file, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"📊 Saved parsing report to {report_file}")
    
    def log_parsing_summary(self, results: Dict[str, Any]):
        """Log comprehensive parsing summary"""
        logger.info("=" * 60)
        logger.info("📊 NVD BATCH DATA PARSING SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Success: {results['success']}")
        logger.info(f"Duration: {results['duration_seconds']:.2f} seconds")
        logger.info(f"Batch Files Processed: {self.stats['files_processed']}")
        logger.info(f"Total CVEs Parsed: {results['total_cves_parsed']:,}")
        logger.info(f"Parsed Files Created: {results['parsed_files_count']}")
        
        logger.info(f"\nCVEs Skipped:")
        logger.info(f"  Pre-2002 CVEs: {self.stats.get('pre_2002_cves_skipped', 0):,}")
        logger.info(f"  Rejected CVEs: {self.stats['rejected_cves']:,}")
        logger.info(f"  Parsing Errors: {self.stats['parsing_errors']}")
        
        logger.info(f"\nCVSS Version Distribution:")
        for version, count in self.stats['cvss_version_counts'].items():
            logger.info(f"  CVSS {version}: {count:,} CVEs")
        
        logger.info(f"\nSeverity Distribution:")
        for severity, count in self.stats['severity_counts'].items():
            logger.info(f"  {severity}: {count:,} CVEs")
        
        logger.info(f"\nAdditional Statistics:")
        logger.info(f"  CVEs with Configurations: {self.stats['cves_with_configurations']:,}")
        logger.info(f"  CVEs with CISA Alerts: {self.stats['cves_with_cisa_alerts']:,}")
        
        if results['total_cves_parsed'] > 0:
            avg_per_second = results['total_cves_parsed'] / results['duration_seconds']
            logger.info(f"  Processing Rate: {avg_per_second:.1f} CVEs/second")
        
        logger.info("=" * 60)

async def main():
    """Main execution function"""
    try:
        parser = NVDDataParser()
        result = await parser.parse_all_nvd_data()
        
        if result['success']:
            print("✅ Simplified NVD batch data parsing completed successfully!")
            print(f"Parsed {result['total_cves_parsed']:,} CVEs from {result['parsing_statistics']['files_processed']} batch files")
            print(f"Created {result['parsed_files_count']} per-batch parsed files. Manifest: {result['manifest_file']}")
        else:
            print(f"❌ NVD data parsing failed: {result.get('error', 'Unknown error')}")
            sys.exit(1)
    except Exception as e:
        print(f"❌ NVD data parsing failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())