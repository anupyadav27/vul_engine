#!/usr/bin/env python3
"""
Simple and Efficient CVE ID-Based Incremental Detector

INSIGHT FROM USER:
Instead of complex cryptographic fingerprinting, we can use the natural 
chronological ordering of CVE IDs to detect incremental changes:

CVE-2025-0001 < CVE-2025-0002 < CVE-2025-9999

This approach is:
1. SIMPLE: Just string comparison
2. EFFICIENT: O(1) per CVE instead of hashing
3. ACCURATE: CVE IDs are naturally incremental
4. UNIVERSAL: Works for ALL vulnerability sources

LOGIC:
1. Get latest CVE ID from database: "CVE-2025-1234"
2. Compare with fresh data CVE IDs
3. Any CVE > "CVE-2025-1234" is genuinely NEW
4. Can also detect CVE updates by comparing metadata
"""

import logging
import json
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from datetime import datetime
import re

logger = logging.getLogger(__name__)

class ChangeType(Enum):
    """Types of changes for vulnerability detection"""
    NEW = "new"                    # Genuinely new CVE
    UPDATED = "updated"           # Existing CVE with changes
    UNCHANGED = "unchanged"       # No changes detected

@dataclass
class CVEComparisonResult:
    """Result of CVE-based incremental comparison"""
    cve_id: str
    change_type: ChangeType
    is_newer: bool                # True if CVE ID is chronologically newer
    has_content_changes: bool     # True if content differs
    confidence_score: float       # 1.0 for new CVEs, varies for updates
    source_name: str
    detected_at: datetime

class SimpleIncrementalDetector:
    """
    Simple CVE ID-based incremental change detector
    
    Uses the natural chronological ordering of CVE IDs (CVE-YYYY-NNNN)
    to efficiently detect new vulnerabilities without complex hashing.
    """
    
    def __init__(self, source_name: str = "unknown"):
        self.source_name = source_name
        self.cve_pattern = re.compile(r'^CVE-(\d{4})-(\d+)$')
    
    def parse_cve_id(self, cve_id: str) -> Tuple[int, int]:
        """Parse CVE ID into (year, number) for comparison"""
        match = self.cve_pattern.match(cve_id)
        if match:
            year = int(match.group(1))
            number = int(match.group(2))
            return (year, number)
        return (0, 0)  # Invalid CVE ID
    
    def is_cve_newer(self, cve_id: str, reference_cve_id: str) -> bool:
        """Check if cve_id is chronologically newer than reference_cve_id"""
        cve_year, cve_num = self.parse_cve_id(cve_id)
        ref_year, ref_num = self.parse_cve_id(reference_cve_id)
        
        # Invalid CVE IDs are not newer
        if cve_year == 0 or ref_year == 0:
            return False
        
        # Compare year first, then number
        if cve_year > ref_year:
            return True
        elif cve_year == ref_year:
            return cve_num > ref_num
        else:
            return False
    
    def get_latest_cve_id(self, cve_list: List[str]) -> Optional[str]:
        """Get the chronologically latest CVE ID from a list"""
        valid_cves = [cve for cve in cve_list if self.cve_pattern.match(cve)]
        if not valid_cves:
            return None
        
        # Sort CVEs chronologically and return the latest
        valid_cves.sort(key=lambda cve: self.parse_cve_id(cve))
        return valid_cves[-1]
    
    def find_incremental_changes(self, 
                                fresh_vulnerabilities: List[Dict], 
                                last_processed_cve_id: Optional[str] = None) -> List[CVEComparisonResult]:
        """
        Find incremental changes using CVE ID-based detection
        
        Args:
            fresh_vulnerabilities: List of vulnerability dictionaries with 'cve_id' field
            last_processed_cve_id: Latest CVE ID we've already processed (None for full scan)
        
        Returns:
            List of comparison results showing new/updated CVEs
        """
        results = []
        
        logger.info(f"🔍 Starting incremental detection for {self.source_name}")
        logger.info(f"📊 Fresh data contains {len(fresh_vulnerabilities):,} vulnerabilities")
        logger.info(f"🎯 Last processed CVE: {last_processed_cve_id or 'None (full scan)'}")
        
        new_count = 0
        
        for vuln in fresh_vulnerabilities:
            cve_id = vuln.get('cve_id')
            if not cve_id or not self.cve_pattern.match(cve_id):
                continue  # Skip invalid CVE IDs
            
            # Determine if this is a new CVE
            is_new = False
            if last_processed_cve_id is None:
                # Full scan mode - treat all as "new" for processing
                is_new = True
            else:
                # Incremental mode - only newer CVEs are truly new
                is_new = self.is_cve_newer(cve_id, last_processed_cve_id)
            
            if is_new:
                results.append(CVEComparisonResult(
                    cve_id=cve_id,
                    change_type=ChangeType.NEW,
                    is_newer=True,
                    has_content_changes=False,  # New CVEs don't have "changes"
                    confidence_score=1.0,
                    source_name=self.source_name,
                    detected_at=datetime.utcnow()
                ))
                new_count += 1
        
        # Sort results by CVE ID to process in chronological order
        results.sort(key=lambda r: self.parse_cve_id(r.cve_id))
        
        logger.info(f"✅ Incremental detection completed:")
        logger.info(f"   • New CVEs found: {new_count:,}")
        logger.info(f"   • CVE ID range: {results[0].cve_id if results else 'None'} to {results[-1].cve_id if results else 'None'}")
        
        return results
    
    def find_cve_updates(self, 
                        fresh_vulnerabilities: List[Dict],
                        existing_vulnerabilities: List[Dict]) -> List[CVEComparisonResult]:
        """
        Find content updates in existing CVEs
        
        This is useful for detecting when existing CVEs get updated descriptions,
        fix status, or other metadata changes.
        """
        results = []
        
        # Create lookup for existing CVEs
        existing_lookup = {vuln['cve_id']: vuln for vuln in existing_vulnerabilities if vuln.get('cve_id')}
        
        logger.info(f"🔄 Checking for CVE content updates...")
        logger.info(f"   • Fresh CVEs: {len(fresh_vulnerabilities):,}")
        logger.info(f"   • Existing CVEs: {len(existing_lookup):,}")
        
        updated_count = 0
        
        for fresh_vuln in fresh_vulnerabilities:
            cve_id = fresh_vuln.get('cve_id')
            if not cve_id or cve_id not in existing_lookup:
                continue  # Skip new CVEs or invalid IDs
            
            existing_vuln = existing_lookup[cve_id]
            
            # Simple content comparison (can be enhanced based on source format)
            fresh_desc = fresh_vuln.get('description', '')
            existing_desc = existing_vuln.get('description', '')
            
            # Check for meaningful content changes
            has_changes = False
            confidence = 0.0
            
            if fresh_desc != existing_desc:
                has_changes = True
                confidence += 0.5
            
            # Check source-specific fields (adapt based on vulnerability source)
            fresh_metadata = json.dumps(fresh_vuln, sort_keys=True)
            existing_metadata = json.dumps(existing_vuln, sort_keys=True)
            
            if fresh_metadata != existing_metadata:
                has_changes = True
                confidence += 0.3
            
            if has_changes and confidence > 0.3:  # Threshold for meaningful updates
                results.append(CVEComparisonResult(
                    cve_id=cve_id,
                    change_type=ChangeType.UPDATED,
                    is_newer=False,
                    has_content_changes=True,
                    confidence_score=min(confidence, 1.0),
                    source_name=self.source_name,
                    detected_at=datetime.utcnow()
                ))
                updated_count += 1
        
        logger.info(f"✅ Content update detection completed:")
        logger.info(f"   • Updated CVEs found: {updated_count:,}")
        
        return results
    
    def get_incremental_summary(self, results: List[CVEComparisonResult]) -> Dict:
        """Generate summary statistics for incremental detection"""
        if not results:
            return {
                'total_changes': 0,
                'new_cves': 0,
                'updated_cves': 0,
                'latest_cve_processed': None,
                'earliest_cve_processed': None,
                'detection_timestamp': datetime.utcnow().isoformat()
            }
        
        new_cves = [r for r in results if r.change_type == ChangeType.NEW]
        updated_cves = [r for r in results if r.change_type == ChangeType.UPDATED]
        
        # Get chronological range
        all_cve_ids = [r.cve_id for r in results]
        all_cve_ids.sort(key=lambda cve: self.parse_cve_id(cve))
        
        return {
            'total_changes': len(results),
            'new_cves': len(new_cves),
            'updated_cves': len(updated_cves),
            'latest_cve_processed': all_cve_ids[-1] if all_cve_ids else None,
            'earliest_cve_processed': all_cve_ids[0] if all_cve_ids else None,
            'detection_timestamp': datetime.utcnow().isoformat(),
            'source_name': self.source_name
        }

# Backward compatibility with existing code
VulnerabilityComparator = SimpleIncrementalDetector
ComparisonResult = CVEComparisonResult