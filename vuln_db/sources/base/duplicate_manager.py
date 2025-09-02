"""
Duplicate Manager for Multi-Source Vulnerability System

Cross-source duplicate resolution system that handles conflicts when the same CVE appears 
from multiple sources. Implements priority-based resolution and data merging strategies.

OBJECTIVE:
Cross-source duplicate resolution system that handles conflicts when the same CVE appears from 
multiple sources. Implements priority-based resolution and data merging strategies.

IMPLEMENTATION STAGES:
Stage 1: Duplicate Detection ✓
Stage 2: Resolution Strategies ✓
Stage 3: Advanced Conflict Management ✓

RELATIONS TO LOCAL CODES:
- Uses: Source configurations from config/source_config.py
- Integrates: Database operations from common_loader.py
- Extends: Conflict resolution from existing systems

RELATIONS TO WHOLE VUL_DB:
- Quality: Ensures data integrity across all sources
- Intelligence: Merges best data from multiple sources
- Traceability: Maintains resolution history
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Set
from collections import defaultdict

from .exceptions import ParseException


class DuplicateManager:
    """Cross-source duplicate resolution system"""
    
    def __init__(self):
        """Initialize duplicate manager"""
        self.logger = logging.getLogger("duplicate_manager")
        
        # Source priority matrix (higher = better quality/authority)
        # Stage 1: Duplicate Detection - priority-based resolution
        self.source_priorities = {
            'nvd': 10,              # NVD is authoritative
            'debian': 8,            # OS vendors have high authority
            'ubuntu': 8,
            'redhat': 8,
            'npm': 7,               # Package ecosystems
            'pypi': 7,
            'maven': 7,
            'golang': 7,
            'github': 6,            # Third-party aggregators
            'aws': 5,               # Cloud vendor advisories
            'gcp': 5,
            'azure': 5,
            'postgresql': 4,        # Database vendors
            'mysql': 4,
            'apache': 3,            # Middleware vendors
            'nginx': 3
        }
        
        # Conflict resolution statistics
        self.resolution_stats = {
            'duplicates_found': 0,
            'conflicts_resolved': 0,
            'data_merged': 0,
            'priority_resolutions': 0
        }
    
    def detect_duplicates(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Detect duplicate vulnerabilities across sources
        
        Args:
            vulnerabilities: List of vulnerability data from multiple sources
            
        Returns:
            Dictionary mapping CVE IDs to lists of duplicate entries
        """
        try:
            self.logger.info(f"Detecting duplicates in {len(vulnerabilities)} vulnerabilities")
            
            # Stage 1: Duplicate Detection
            cve_groups = defaultdict(list)
            advisory_groups = defaultdict(list)
            
            # Group by CVE ID
            for vuln in vulnerabilities:
                cve_id = vuln.get('cve_id')
                advisory_id = vuln.get('advisory_id')
                
                if cve_id:
                    cve_groups[cve_id].append(vuln)
                elif advisory_id:
                    advisory_groups[advisory_id].append(vuln)
            
            # Find actual duplicates (more than one entry per ID)
            duplicates = {}
            for cve_id, entries in cve_groups.items():
                if len(entries) > 1:
                    duplicates[cve_id] = entries
                    self.resolution_stats['duplicates_found'] += len(entries) - 1
            
            for advisory_id, entries in advisory_groups.items():
                if len(entries) > 1:
                    duplicates[advisory_id] = entries
                    self.resolution_stats['duplicates_found'] += len(entries) - 1
            
            self.logger.info(f"Found {len(duplicates)} IDs with duplicates")
            return duplicates
            
        except Exception as e:
            self.logger.error(f"Error detecting duplicates: {e}")
            raise ParseException(f"Duplicate detection failed: {e}")
    
    def resolve_duplicates(self, duplicates: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """
        Resolve duplicate vulnerabilities using priority and merging strategies
        
        Args:
            duplicates: Dictionary of duplicate vulnerability groups
            
        Returns:
            List of resolved vulnerability records
        """
        try:
            self.logger.info(f"Resolving {len(duplicates)} duplicate groups")
            resolved_vulnerabilities = []
            
            for vuln_id, duplicate_entries in duplicates.items():
                try:
                    # Stage 2: Resolution Strategies
                    resolved_vuln = self._resolve_duplicate_group(vuln_id, duplicate_entries)
                    if resolved_vuln:
                        resolved_vulnerabilities.append(resolved_vuln)
                        self.resolution_stats['conflicts_resolved'] += 1
                        
                except Exception as e:
                    self.logger.error(f"Error resolving duplicates for {vuln_id}: {e}")
                    # Fall back to highest priority source
                    fallback_vuln = self._select_by_priority(duplicate_entries)
                    if fallback_vuln:
                        resolved_vulnerabilities.append(fallback_vuln)
            
            self.logger.info(f"Successfully resolved {len(resolved_vulnerabilities)} duplicate groups")
            return resolved_vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error resolving duplicates: {e}")
            raise ParseException(f"Duplicate resolution failed: {e}")
    
    def _resolve_duplicate_group(self, vuln_id: str, entries: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Resolve a single group of duplicate entries"""
        if not entries:
            return None
        
        if len(entries) == 1:
            return entries[0]
        
        # Stage 2: Resolution Strategies
        # 1. Select base entry by priority
        base_entry = self._select_by_priority(entries)
        if not base_entry:
            return entries[0]  # Fallback
        
        # 2. Merge data from other sources
        merged_entry = self._merge_vulnerability_data(base_entry, entries)
        
        # Stage 3: Advanced Conflict Management
        # 3. Add resolution metadata
        merged_entry['duplicate_resolution'] = {
            'resolved_at': datetime.utcnow().isoformat(),
            'source_count': len(entries),
            'sources_merged': [entry.get('source') for entry in entries],
            'primary_source': base_entry.get('source'),
            'resolution_strategy': 'priority_with_merge'
        }
        
        return merged_entry
    
    def _select_by_priority(self, entries: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Select entry with highest source priority"""
        if not entries:
            return None
        
        # Sort by priority (highest first)
        sorted_entries = sorted(
            entries,
            key=lambda x: self.source_priorities.get(x.get('source', ''), 0),
            reverse=True
        )
        
        self.resolution_stats['priority_resolutions'] += 1
        return sorted_entries[0]
    
    def _merge_vulnerability_data(self, base_entry: Dict[str, Any], all_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge data from multiple sources into base entry"""
        merged = base_entry.copy()
        
        try:
            # Stage 3: Advanced Conflict Management
            # Merge references from all sources
            all_references = merged.get('references', [])
            for entry in all_entries:
                if entry != base_entry:
                    entry_refs = entry.get('references', [])
                    for ref in entry_refs:
                        if ref not in all_references:
                            all_references.append(ref)
            
            merged['references'] = all_references
            
            # Merge affected packages
            all_packages = merged.get('affected_packages', [])
            for entry in all_entries:
                if entry != base_entry:
                    entry_packages = entry.get('affected_packages', [])
                    for package in entry_packages:
                        # Check if package already exists
                        existing = False
                        for existing_package in all_packages:
                            if (existing_package.get('name') == package.get('name') and
                                existing_package.get('ecosystem') == package.get('ecosystem')):
                                existing = True
                                break
                        
                        if not existing:
                            all_packages.append(package)
            
            merged['affected_packages'] = all_packages
            
            # Use best available CVSS score (highest if multiple)
            best_score = merged.get('cvss_score')
            for entry in all_entries:
                entry_score = entry.get('cvss_score')
                if entry_score and (not best_score or entry_score > best_score):
                    best_score = entry_score
            
            if best_score:
                merged['cvss_score'] = best_score
            
            # Use most recent date
            latest_date = merged.get('last_modified_date')
            for entry in all_entries:
                entry_date = entry.get('last_modified_date')
                if entry_date and (not latest_date or entry_date > latest_date):
                    latest_date = entry_date
            
            if latest_date:
                merged['last_modified_date'] = latest_date
            
            # Merge source metadata
            merged_metadata = merged.get('source_metadata', {})
            for entry in all_entries:
                if entry != base_entry:
                    entry_metadata = entry.get('source_metadata', {})
                    for key, value in entry_metadata.items():
                        if key not in merged_metadata:
                            merged_metadata[key] = value
            
            merged['source_metadata'] = merged_metadata
            
            self.resolution_stats['data_merged'] += 1
            
            return merged
            
        except Exception as e:
            self.logger.error(f"Error merging vulnerability data: {e}")
            return base_entry
    
    def get_resolution_stats(self) -> Dict[str, int]:
        """Return duplicate resolution statistics"""
        return self.resolution_stats.copy()
    
    def reset_stats(self):
        """Reset resolution statistics"""
        self.resolution_stats = {
            'duplicates_found': 0,
            'conflicts_resolved': 0,
            'data_merged': 0,
            'priority_resolutions': 0
        }
    
    def update_source_priority(self, source_name: str, priority: int):
        """Update priority for a specific source"""
        if 0 <= priority <= 10:
            self.source_priorities[source_name] = priority
            self.logger.info(f"Updated {source_name} priority to {priority}")
        else:
            raise ValueError("Priority must be between 0 and 10")
    
    def get_source_priorities(self) -> Dict[str, int]:
        """Return current source priority matrix"""
        return self.source_priorities.copy()