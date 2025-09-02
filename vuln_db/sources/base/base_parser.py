"""
Base Parser for Multi-Source Vulnerability System

Abstract base class that all vulnerability source parsers inherit from.
Provides common parsing functionality and enforces consistent interface.

OBJECTIVE:
Common parsing infrastructure that standardizes vulnerability data extraction from diverse 
source formats (JSON, XML, HTML, RSS). Ensures consistent data structure before normalization.

IMPLEMENTATION STAGES:
Stage 1: Format Detection & Basic Parsing ✓
Stage 2: Advanced Parsing Features ✓  
Stage 3: Data Validation & Enrichment ✓

RELATIONS TO LOCAL CODES:
- Extends: NVD JSON parsing patterns from existing NVD parser
- Uses: Common schema definitions from db_schema/vulnerability_schema.py
- Integrates: Error handling from sources/base/exceptions.py

RELATIONS TO WHOLE VUL_DB:
- Foundation: ALL 49 source parsers inherit from this
- Data Flow: Feeds normalized data to DataNormalizer
- Quality: Ensures data quality before database insertion
"""

import abc
import json
import logging
import re
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
import feedparser

from .exceptions import ParseException


class BaseParser(abc.ABC):
    """Abstract base class for all vulnerability source parsers"""
    
    def __init__(self, source_name: str, config: Dict[str, Any]):
        """
        Initialize parser with source configuration
        
        Args:
            source_name: Name of the vulnerability source
            config: Configuration dict from interest_datasource_final.json
        """
        self.source_name = source_name
        self.config = config
        self.logger = logging.getLogger(f"parser.{source_name}")
        
        # Common parsing configuration
        self.date_formats = [
            '%Y-%m-%d',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%d/%m/%Y',
            '%m/%d/%Y',
            '%B %d, %Y',
            '%d %B %Y'
        ]
        
        # Common CVE pattern
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}')
    
    @abc.abstractmethod
    def parse_raw_data(self, raw_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse raw vulnerability data into standardized format
        
        Args:
            raw_data: List of raw vulnerability data from fetcher
            
        Returns:
            List of parsed vulnerability dictionaries
        """
        pass
    
    def detect_format(self, data: Union[str, bytes, Dict, List]) -> str:
        """
        Detect the format of input data
        
        Args:
            data: Raw data to analyze
            
        Returns:
            Detected format: 'json', 'xml', 'html', 'rss', 'text'
        """
        if isinstance(data, (dict, list)):
            return 'json'
        
        if isinstance(data, bytes):
            data = data.decode('utf-8', errors='ignore')
        
        if not isinstance(data, str):
            return 'unknown'
        
        data_stripped = data.strip()
        
        # Check for XML/RSS
        if data_stripped.startswith('<?xml') or data_stripped.startswith('<rss') or data_stripped.startswith('<feed'):
            if 'rss' in data_stripped[:200].lower() or 'feed' in data_stripped[:200].lower():
                return 'rss'
            return 'xml'
        
        # Check for HTML
        if data_stripped.startswith('<!DOCTYPE html') or data_stripped.startswith('<html'):
            return 'html'
        
        # Check for JSON
        try:
            json.loads(data)
            return 'json'
        except (json.JSONDecodeError, TypeError):
            pass
        
        return 'text'
    
    def parse_json(self, data: Union[str, Dict, List]) -> Union[Dict, List]:
        """Parse JSON data with error handling"""
        try:
            if isinstance(data, str):
                return json.loads(data)
            return data
        except json.JSONDecodeError as e:
            raise ParseException(f"Invalid JSON data: {e}")
    
    def parse_xml(self, data: str) -> ET.Element:
        """Parse XML data with error handling"""
        try:
            return ET.fromstring(data)
        except ET.ParseError as e:
            raise ParseException(f"Invalid XML data: {e}")
    
    def parse_html(self, data: str) -> BeautifulSoup:
        """Parse HTML data with BeautifulSoup"""
        try:
            return BeautifulSoup(data, 'html.parser')
        except Exception as e:
            raise ParseException(f"Error parsing HTML: {e}")
    
    def parse_rss(self, data: str) -> Dict[str, Any]:
        """Parse RSS/Atom feed data"""
        try:
            return feedparser.parse(data)
        except Exception as e:
            raise ParseException(f"Error parsing RSS feed: {e}")
    
    def extract_cve_ids(self, text: str) -> List[str]:
        """Extract CVE IDs from text"""
        if not text:
            return []
        
        matches = self.cve_pattern.findall(text)
        return list(set(matches))  # Remove duplicates
    
    def parse_date(self, date_str: Optional[str]) -> Optional[str]:
        """
        Parse date string into ISO format
        
        Args:
            date_str: Date string in various formats
            
        Returns:
            ISO formatted date string or None
        """
        if not date_str:
            return None
        
        # Clean the date string
        date_str = str(date_str).strip()
        
        for date_format in self.date_formats:
            try:
                parsed_date = datetime.strptime(date_str, date_format)
                return parsed_date.isoformat()
            except ValueError:
                continue
        
        # Try parsing with dateutil as fallback
        try:
            from dateutil import parser as dateutil_parser
            parsed_date = dateutil_parser.parse(date_str)
            return parsed_date.isoformat()
        except (ImportError, ValueError):
            pass
        
        self.logger.warning(f"Could not parse date: {date_str}")
        return None
    
    def clean_text(self, text: Optional[str]) -> str:
        """Clean and normalize text content"""
        if not text:
            return ""
        
        # Convert to string if not already
        text = str(text)
        
        # Remove HTML tags if present
        if '<' in text and '>' in text:
            soup = BeautifulSoup(text, 'html.parser')
            text = soup.get_text()
        
        # Clean whitespace
        text = ' '.join(text.split())
        
        return text.strip()
    
    def extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text"""
        url_pattern = re.compile(
            r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?'
        )
        
        matches = url_pattern.findall(text)
        return [url for url in matches if self.is_valid_url(url)]
    
    def is_valid_url(self, url: str) -> bool:
        """Validate URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def normalize_severity(self, severity: Optional[str]) -> str:
        """Normalize severity levels to standard values"""
        if not severity:
            return 'UNKNOWN'
        
        severity = str(severity).upper().strip()
        
        # Map various severity formats to standard levels
        severity_mapping = {
            'CRITICAL': 'CRITICAL',
            'HIGH': 'HIGH',
            'MEDIUM': 'MEDIUM',
            'MODERATE': 'MEDIUM',
            'LOW': 'LOW',
            'MINIMAL': 'LOW',
            'NONE': 'NONE',
            'UNKNOWN': 'UNKNOWN',
            'UNSPECIFIED': 'UNKNOWN',
            # CVSS score ranges
            '9.0-10.0': 'CRITICAL',
            '7.0-8.9': 'HIGH',
            '4.0-6.9': 'MEDIUM',
            '0.1-3.9': 'LOW',
            '0.0': 'NONE'
        }
        
        return severity_mapping.get(severity, 'UNKNOWN')
    
    def extract_cvss_score(self, data: Dict[str, Any]) -> Optional[float]:
        """Extract CVSS score from various fields"""
        cvss_fields = [
            'cvss_score', 'cvss3_score', 'cvss2_score',
            'score', 'base_score', 'cvss_base_score',
            'cvss', 'cvssScore', 'baseScore'
        ]
        
        for field in cvss_fields:
            score = data.get(field)
            if score is not None:
                try:
                    score_float = float(score)
                    if 0.0 <= score_float <= 10.0:
                        return score_float
                except (ValueError, TypeError):
                    continue
        
        return None
    
    def validate_vulnerability_data(self, vuln_data: Dict[str, Any]) -> bool:
        """
        Validate that vulnerability data contains required fields
        
        Args:
            vuln_data: Vulnerability data dictionary
            
        Returns:
            True if valid, False otherwise
        """
        required_fields = ['source']
        
        # Either CVE ID or advisory ID should be present
        if not any(field in vuln_data for field in ['cve_id', 'advisory_id']):
            self.logger.warning("Vulnerability missing CVE ID or advisory ID")
            return False
        
        for field in required_fields:
            if field not in vuln_data:
                self.logger.warning(f"Vulnerability missing required field: {field}")
                return False
        
        return True
    
    def extract_references(self, data: Dict[str, Any], base_url: str = None) -> List[Dict[str, str]]:
        """Extract reference URLs from vulnerability data"""
        references = []
        
        # Common reference fields
        ref_fields = [
            'references', 'refs', 'links', 'urls',
            'external_references', 'advisory_links'
        ]
        
        for field in ref_fields:
            if field in data:
                ref_data = data[field]
                if isinstance(ref_data, list):
                    for ref in ref_data:
                        if isinstance(ref, dict):
                            url = ref.get('url') or ref.get('href') or ref.get('link')
                            if url and self.is_valid_url(url):
                                references.append({
                                    'url': url,
                                    'type': ref.get('type', 'external'),
                                    'source': self.source_name
                                })
                        elif isinstance(ref, str) and self.is_valid_url(ref):
                            references.append({
                                'url': ref,
                                'type': 'external',
                                'source': self.source_name
                            })
        
        # Add source URL if available
        if base_url and self.is_valid_url(base_url):
            references.append({
                'url': base_url,
                'type': 'vendor',
                'source': self.source_name
            })
        
        return references
    
    def get_parser_stats(self) -> Dict[str, Any]:
        """Return parsing statistics"""
        return {
            'source_name': self.source_name,
            'supported_formats': ['json', 'xml', 'html', 'rss'],
            'date_formats_supported': len(self.date_formats),
            'validation_enabled': True
        }