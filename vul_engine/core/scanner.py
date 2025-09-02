"""
Vulnerability Scanner - Core scanning logic
Matches discovered packages against vulnerability database
"""

import asyncpg
import logging
from typing import Dict, List, Optional, Set
from datetime import datetime
import re
import json

from .config import settings

logger = logging.getLogger(__name__)

class VulnerabilityScanner:
    """Core vulnerability scanning and matching logic"""
    
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.cve_cache = {}
        self.cache_timestamp = None
    
    async def scan_packages(self, packages: List[Dict]) -> List[Dict]:
        """
        Scan packages for vulnerabilities
        
        Args:
            packages: List of discovered packages
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        logger.info(f"Scanning {len(packages)} packages for vulnerabilities")
        
        for package in packages:
            package_vulns = await self._check_package_vulnerabilities(package)
            vulnerabilities.extend(package_vulns)
        
        # Filter by severity threshold
        filtered_vulns = self._filter_by_severity(vulnerabilities)
        
        logger.info(f"Found {len(filtered_vulns)} vulnerabilities above threshold")
        return filtered_vulns
    
    async def _check_package_vulnerabilities(self, package: Dict) -> List[Dict]:
        """Check a single package for vulnerabilities"""
        try:
            package_name = package.get('name', '').lower()
            package_version = package.get('version', '')
            package_type = package.get('type', '')
            
            if not package_name or not package_version:
                return []
            
            # Query vulnerability database
            vulnerabilities = await self._query_vulnerability_db(
                package_name, package_version, package_type
            )
            
            # Add package context to vulnerabilities
            for vuln in vulnerabilities:
                vuln.update({
                    'package_name': package_name,
                    'package_version': package_version,
                    'package_type': package_type,
                    'package_manager': package.get('manager', '')
                })
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error checking package {package.get('name')}: {e}")
            return []
    
    async def _query_vulnerability_db(self, package_name: str, version: str, package_type: str) -> List[Dict]:
        """Query the vulnerability database for package vulnerabilities"""
        try:
            async with self.db_manager.pool.acquire() as conn:
                # Query using the actual NVD schema: cves + cpes tables
                rows = await conn.fetch("""
                    SELECT DISTINCT 
                        cve.cve_id,
                        cve.description,
                        cve.cvss_v3_severity as severity,
                        cve.cvss_v3_score as score,
                        cve.published_date,
                        cve.last_modified_date,
                        cpe.product,
                        cpe.vendor,
                        cpe.version
                    FROM cves cve
                    JOIN cpes cpe ON cve.cve_id = cpe.cve_id
                    WHERE LOWER(cpe.product) = $1
                       OR LOWER(cpe.product) LIKE $2
                       OR LOWER(cpe.vendor) = $1
                    ORDER BY cve.cvss_v3_score DESC NULLS LAST
                    LIMIT 100
                """, package_name, f"%{package_name}%")
                
                vulnerabilities = []
                for row in rows:
                    # Create vulnerability record
                    vuln = {
                        'cve_id': row['cve_id'],
                        'description': row['description'],
                        'severity': row['severity'] or 'MEDIUM',  # Default if null
                        'score': float(row['score']) if row['score'] else 0.0,
                        'published_date': row['published_date'].isoformat() if row['published_date'] else None,
                        'remediation': self._generate_remediation(package_name, version, row['cve_id'])
                    }
                    vulnerabilities.append(vuln)
                
                return vulnerabilities
                
        except Exception as e:
            logger.error(f"Database query error for {package_name}: {e}")
            return []
    
    def _is_version_affected(self, package_version: str, cve_data: Dict) -> bool:
        """
        Check if package version is affected by vulnerability
        
        Args:
            package_version: Version of the package
            cve_data: CVE data from database
            
        Returns:
            bool: True if version is affected
        """
        try:
            # Clean version string
            clean_version = self._clean_version(package_version)
            
            version_start = cve_data.get('version_start')
            version_end = cve_data.get('version_end')
            start_including = cve_data.get('version_start_including', True)
            end_including = cve_data.get('version_end_including', False)
            
            # If no version range specified, assume affected
            if not version_start and not version_end:
                return True
            
            # Compare versions
            if version_start:
                start_clean = self._clean_version(version_start)
                if start_including:
                    if self._compare_versions(clean_version, start_clean) < 0:
                        return False
                else:
                    if self._compare_versions(clean_version, start_clean) <= 0:
                        return False
            
            if version_end:
                end_clean = self._clean_version(version_end)
                if end_including:
                    if self._compare_versions(clean_version, end_clean) > 0:
                        return False
                else:
                    if self._compare_versions(clean_version, end_clean) >= 0:
                        return False
            
            return True
            
        except Exception as e:
            logger.debug(f"Version comparison error: {e}")
            return True  # Default to affected if can't determine
    
    def _clean_version(self, version: str) -> str:
        """Clean version string for comparison"""
        if not version:
            return "0.0.0"
        
        # Remove common prefixes and suffixes
        version = re.sub(r'^[vV]', '', version)
        version = re.sub(r'[-+].*$', '', version)  # Remove build metadata
        
        # Ensure we have at least major.minor.patch
        parts = version.split('.')
        while len(parts) < 3:
            parts.append('0')
        
        return '.'.join(parts[:3])
    
    def _compare_versions(self, version1: str, version2: str) -> int:
        """
        Compare two version strings
        
        Returns:
            -1 if version1 < version2
             0 if version1 == version2
             1 if version1 > version2
        """
        try:
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]
            
            # Pad shorter version with zeros
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            for i in range(max_len):
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1
            
            return 0
            
        except (ValueError, AttributeError):
            # Fallback to string comparison
            return -1 if version1 < version2 else (1 if version1 > version2 else 0)
    
    def _filter_by_severity(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Filter vulnerabilities by severity threshold"""
        severity_order = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1,
            'NONE': 0
        }
        
        threshold = severity_order.get(settings.SEVERITY_THRESHOLD, 2)
        
        filtered = []
        for vuln in vulnerabilities:
            vuln_severity = severity_order.get(vuln.get('severity', 'NONE'), 0)
            if vuln_severity >= threshold:
                filtered.append(vuln)
        
        return filtered
    
    def _generate_remediation(self, package_name: str, current_version: str, cve_id: str) -> str:
        """Generate remediation advice for vulnerability"""
        remediation = f"Update {package_name} from version {current_version} to the latest secure version."
        
        # Add CVE-specific advice
        if "CRITICAL" in cve_id or "RCE" in cve_id:
            remediation += " This is a critical vulnerability that should be patched immediately."
        
        remediation += f" For more details, see: https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
        
        return remediation
    
    async def process_scan_results(self, scan_data: Dict) -> Dict:
        """
        Process complete scan results from agent
        
        Args:
            scan_data: Raw scan data from agent
            
        Returns:
            Dict: Processed results with vulnerabilities
        """
        try:
            # Register/update agent
            agent_info = {
                'agent_id': scan_data['agent_id'],
                'hostname': scan_data.get('system_info', {}).get('hostname', ''),
                'platform': scan_data.get('system_info', {}).get('platform', ''),
                'architecture': scan_data.get('system_info', {}).get('architecture', '')
            }
            
            await self.db_manager.register_agent(agent_info)
            
            # Store scan results
            scan_id = await self.db_manager.store_scan_results(scan_data)
            if not scan_id:
                raise Exception("Failed to store scan results")
            
            # Scan packages for vulnerabilities
            packages = scan_data.get('packages', [])
            vulnerabilities = await self.scan_packages(packages)
            
            # Store vulnerabilities
            if vulnerabilities:
                await self.db_manager.store_vulnerabilities(scan_id, vulnerabilities)
            
            # Prepare response
            result = {
                'scan_id': scan_id,
                'agent_id': scan_data['agent_id'],
                'timestamp': datetime.utcnow().isoformat(),
                'packages_scanned': len(packages),
                'vulnerabilities_found': len(vulnerabilities),
                'vulnerability_count': len(vulnerabilities),
                'vulnerabilities': vulnerabilities[:10],  # Return first 10 for quick view
                'severity_summary': self._get_severity_summary(vulnerabilities),
                'recommendations': self._generate_recommendations(vulnerabilities)
            }
            
            logger.info(f"Scan processed: {len(vulnerabilities)} vulnerabilities found")
            return result
            
        except Exception as e:
            logger.error(f"Error processing scan results: {e}")
            raise
    
    def _get_severity_summary(self, vulnerabilities: List[Dict]) -> Dict:
        """Get summary of vulnerabilities by severity"""
        summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            if severity in summary:
                summary[severity] += 1
        
        return summary
    
    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        severity_counts = self._get_severity_summary(vulnerabilities)
        
        if severity_counts['CRITICAL'] > 0:
            recommendations.append(f"Immediately patch {severity_counts['CRITICAL']} critical vulnerabilities")
        
        if severity_counts['HIGH'] > 0:
            recommendations.append(f"Schedule patching for {severity_counts['HIGH']} high severity vulnerabilities")
        
        if severity_counts['MEDIUM'] > 5:
            recommendations.append("Consider automated updating for medium severity issues")
        
        # Package-specific recommendations
        package_counts = {}
        for vuln in vulnerabilities:
            pkg = vuln.get('package_name')
            if pkg:
                package_counts[pkg] = package_counts.get(pkg, 0) + 1
        
        top_packages = sorted(package_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        for pkg, count in top_packages:
            if count > 1:
                recommendations.append(f"Priority update needed for {pkg} ({count} vulnerabilities)")
        
        return recommendations