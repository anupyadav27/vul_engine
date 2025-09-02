"""
Data Normalizer for Multi-Source Vulnerability System

Universal data normalizer that converts any source format into the common database schema.
Handles field mapping, data type conversion, and ensures consistency across all 49 sources.

OBJECTIVE:
Universal data normalizer that converts any source format into the common database schema. 
Handles field mapping, data type conversion, and ensures consistency across all 49 sources.

IMPLEMENTATION STAGES:
Stage 1: Schema Mapping Framework ✓
Stage 2: CVE Data Standardization ✓
Stage 3: Advanced Normalization ✓

RELATIONS TO LOCAL CODES:
- Uses: Database schema from db_schema/vulnerability_schema.py
- Extends: NVD normalization patterns
- Integrates: Source tracking metadata

RELATIONS TO WHOLE VUL_DB:
- Critical Path: ALL sources use this for schema compliance
- Database: Ensures data fits enhanced vulnerability schema
- Quality: Final validation before database insertion
"""

import logging
import re
from datetime import datetime
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

from .exceptions import ParseException


class DataNormalizer:
    """Universal data normalizer for all vulnerability sources"""
    
    def __init__(self, source_name: str):
        """Initialize data normalizer for specific source"""
        self.source_name = source_name
        self.logger = logging.getLogger(f"normalizer.{source_name}")
        
        # Common field mappings
        self.severity_mapping = {
            'CRITICAL': 'CRITICAL',
            'HIGH': 'HIGH',
            'MEDIUM': 'MEDIUM',
            'MODERATE': 'MEDIUM',
            'LOW': 'LOW',
            'MINIMAL': 'LOW',
            'NONE': 'NONE',
            'UNKNOWN': 'UNKNOWN',
            'UNSPECIFIED': 'UNKNOWN'
        }
        
        # CVE ID validation pattern
        self.cve_pattern = re.compile(r'^CVE-\d{4}-\d{4,}$')
    
    def normalize_vulnerability(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize parsed vulnerability data to common schema
        
        Args:
            parsed_data: Parsed vulnerability data from source parser
            
        Returns:
            Normalized vulnerability data ready for database insertion
        """
        try:
            # Stage 1: Schema Mapping Framework
            normalized = {
                'cve_id': self._normalize_cve_id(parsed_data),
                'description': self._normalize_description(parsed_data),
                'severity': self._normalize_severity(parsed_data),
                'cvss_score': self._normalize_cvss_score(parsed_data),
                'source': self.source_name,
                'source_url': parsed_data.get('source_url'),
                'published_date': self._normalize_date(parsed_data.get('published_date')),
                'last_modified_date': self._normalize_date(parsed_data.get('last_modified_date')),
                'references': self._normalize_references(parsed_data),
                'affected_packages': self._normalize_packages(parsed_data),
                'source_metadata': self._extract_source_metadata(parsed_data)
            }
            
            # Stage 2: CVE Data Standardization
            if 'advisory_id' in parsed_data:
                normalized['advisory_id'] = parsed_data['advisory_id']
                normalized['advisory_type'] = parsed_data.get('advisory_type')
            
            # Stage 3: Advanced Normalization
            normalized['cwe_id'] = self._normalize_cwe_id(parsed_data)
            normalized['attack_vector'] = self._normalize_attack_vector(parsed_data)
            
            # Add source tracking
            normalized['source_tracking'] = {
                'source_name': self.source_name,
                'fetch_timestamp': datetime.utcnow().isoformat(),
                'data_quality_score': self._calculate_quality_score(normalized)
            }
            
            return normalized
            
        except Exception as e:
            self.logger.error(f"Error normalizing vulnerability data: {e}")
            raise ParseException(f"Normalization failed: {e}")
    
    def _normalize_cve_id(self, data: Dict[str, Any]) -> Optional[str]:
        """Normalize CVE ID format"""
        cve_id = data.get('cve_id')
        if not cve_id:
            return None
        
        cve_id = str(cve_id).upper().strip()
        if self.cve_pattern.match(cve_id):
            return cve_id
        
        self.logger.warning(f"Invalid CVE ID format: {cve_id}")
        return None
    
    def _normalize_description(self, data: Dict[str, Any]) -> str:
        """Normalize vulnerability description"""
        description = data.get('description', '')
        if not description:
            return ''
        
        # Clean and truncate description
        description = str(description).strip()
        
        # Remove excessive whitespace
        description = ' '.join(description.split())
        
        # Truncate if too long (database limit)
        if len(description) > 4000:
            description = description[:3997] + '...'
        
        return description
    
    def _normalize_severity(self, data: Dict[str, Any]) -> str:
        """Normalize severity level"""
        severity = data.get('severity', 'UNKNOWN')
        if not severity:
            return 'UNKNOWN'
        
        severity = str(severity).upper().strip()
        return self.severity_mapping.get(severity, 'UNKNOWN')
    
    def _normalize_cvss_score(self, data: Dict[str, Any]) -> Optional[float]:
        """Normalize CVSS score"""
        score_fields = ['cvss_score', 'base_score', 'score']
        
        for field in score_fields:
            score = data.get(field)
            if score is not None:
                try:
                    score_float = float(score)
                    if 0.0 <= score_float <= 10.0:
                        return round(score_float, 1)
                except (ValueError, TypeError):
                    continue
        
        return None
    
    def _normalize_date(self, date_str: Optional[str]) -> Optional[str]:
        """Normalize date to ISO format"""
        if not date_str:
            return None
        
        try:
            # If already in ISO format, validate and return
            if 'T' in str(date_str) and ('Z' in str(date_str) or '+' in str(date_str)):
                datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                return date_str
            
            # Try to parse various formats
            date_formats = [
                '%Y-%m-%d',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%dT%H:%M:%S.%fZ'
            ]
            
            for date_format in date_formats:
                try:
                    parsed_date = datetime.strptime(str(date_str), date_format)
                    return parsed_date.isoformat()
                except ValueError:
                    continue
            
            return None
            
        except Exception as e:
            self.logger.warning(f"Could not normalize date {date_str}: {e}")
            return None
    
    def _normalize_references(self, data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Normalize reference URLs"""
        references = data.get('references', [])
        if not references:
            return []
        
        normalized_refs = []
        for ref in references:
            if isinstance(ref, dict):
                url = ref.get('url')
                if url and self._is_valid_url(url):
                    normalized_refs.append({
                        'url': url,
                        'type': ref.get('type', 'external'),
                        'source': ref.get('source', self.source_name)
                    })
            elif isinstance(ref, str) and self._is_valid_url(ref):
                normalized_refs.append({
                    'url': ref,
                    'type': 'external',
                    'source': self.source_name
                })
        
        return normalized_refs
    
    def _normalize_packages(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Normalize affected package information"""
        packages = data.get('affected_packages', [])
        if not packages:
            return []
        
        normalized_packages = []
        for package in packages:
            if not isinstance(package, dict):
                continue
            
            normalized_package = {
                'name': str(package.get('name', '')).strip(),
                'ecosystem': str(package.get('ecosystem', '')).strip(),
                'vulnerable': bool(package.get('vulnerable', True))
            }
            
            # Add optional fields if present
            optional_fields = ['version', 'fixed_version', 'version_range']
            for field in optional_fields:
                if field in package and package[field] is not None:
                    normalized_package[field] = str(package[field]).strip()
            
            if normalized_package['name']:
                normalized_packages.append(normalized_package)
        
        return normalized_packages
    
    def _normalize_cwe_id(self, data: Dict[str, Any]) -> Optional[str]:
        """Normalize CWE ID"""
        cwe_id = data.get('cwe_id')
        if not cwe_id:
            return None
        
        cwe_id = str(cwe_id).upper().strip()
        if cwe_id.startswith('CWE-') and cwe_id[4:].isdigit():
            return cwe_id
        
        return None
    
    def _normalize_attack_vector(self, data: Dict[str, Any]) -> Optional[str]:
        """Normalize attack vector"""
        attack_vector = data.get('attack_vector')
        if not attack_vector:
            return None
        
        vector_mapping = {
            'NETWORK': 'NETWORK',
            'LOCAL': 'LOCAL',
            'PHYSICAL': 'PHYSICAL',
            'ADJACENT_NETWORK': 'ADJACENT_NETWORK'
        }
        
        attack_vector = str(attack_vector).upper().strip()
        return vector_mapping.get(attack_vector)
    
    def _extract_source_metadata(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract source-specific metadata"""
        metadata = {}
        
        # Extract source-specific fields
        source_specific_keys = [
            'debian_specific', 'npm_specific', 'aws_specific',
            'source_type', 'advisory_type', 'urgency'
        ]
        
        for key in source_specific_keys:
            if key in data:
                metadata[key] = data[key]
        
        return metadata
    
    def _is_valid_url(self, url: str) -> bool:
        """Validate URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def _calculate_quality_score(self, normalized_data: Dict[str, Any]) -> int:
        """Calculate data quality score (1-10)"""
        score = 0
        
        # Required fields
        if normalized_data.get('cve_id'):
            score += 3
        if normalized_data.get('description'):
            score += 2
        if normalized_data.get('severity') != 'UNKNOWN':
            score += 2
        
        # Optional but valuable fields
        if normalized_data.get('cvss_score'):
            score += 1
        if normalized_data.get('references'):
            score += 1
        if normalized_data.get('affected_packages'):
            score += 1
        
        return min(score, 10)
    
    def validate_normalized_data(self, normalized_data: Dict[str, Any]) -> bool:
        """Validate normalized data meets schema requirements"""
        required_fields = ['source']
        
        for field in required_fields:
            if field not in normalized_data:
                self.logger.error(f"Missing required field: {field}")
                return False
        
        # Either CVE ID or advisory ID should be present
        if not any(field in normalized_data for field in ['cve_id', 'advisory_id']):
            self.logger.error("Missing CVE ID or advisory ID")
            return False
        
        return True