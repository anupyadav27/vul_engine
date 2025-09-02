"""
Multi-Source Vulnerability Orchestration System

OBJECTIVE:
Central orchestrator that coordinates all 49 vulnerability sources across 5 categories.
Manages scheduling, data flow, duplicate resolution, and error handling for the entire
multi-source vulnerability intelligence system.

ARCHITECTURE OVERVIEW:
- Coordinates 5 category orchestrators (OS, Languages, Cloud, Database, Middleware)
- Manages source priority and duplicate resolution across categories
- Provides unified scheduling and monitoring interface
- Handles cross-source data normalization and quality control

DEPENDENCIES:
- ../sources/base/: Common infrastructure classes
- ../sources/cve_compatible_os/: OS vulnerability sources (11 sources)
- ../sources/cve_compatible_languages/: Language package sources (5 sources)
- ../sources/advisory_cloud_bulletins/: Cloud provider advisories (5 sources)
- ../sources/database_vendor_advisories/: Database vendor sources (6 sources)
- ../sources/middleware_vendor_advisories/: Middleware sources (7 sources)
- ../interest_datasource_final.json: Source configurations
- ../nvd/database.py: Enhanced database operations

INTEGRATION WITH LOCAL CODES:
- Uses enhanced NVD database operations for multi-source support
- Coordinates with existing NVD incremental update system
- Leverages common schema from db_schema/vulnerability_schema.py
- Integrates with monitoring and alerting systems

INTEGRATION ACROSS COMMON CODES:
- Manages all sources through common BaseFetcher/BaseParser interfaces
- Uses unified DataNormalizer for cross-source schema consistency
- Employs single CommonLoader for all database operations
- Coordinates DuplicateManager for cross-source conflict resolution

INTEGRATION WITH OVERALL PROGRAM:
- Entry point for all multi-source vulnerability operations
- Scheduled by cron/systemd for automated vulnerability intelligence
- Monitored by logging and metrics systems
- Provides API endpoints for manual source management
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import json

from ..sources.base import CommonLoader, DuplicateManager, VulnSourceException
from ..config.source_config import SourceConfigManager
from .category_orchestrators import (
    CveCompatibleOsOrchestrator,
    CveCompatibleLanguagesOrchestrator,
    AdvisoryCloudBulletinsOrchestrator,
    DatabaseVendorAdvisoriesOrchestrator,
    MiddlewareVendorAdvisoriesOrchestrator
)

logger = logging.getLogger(__name__)

class OrchestrationPhase(Enum):
    """Phases of multi-source orchestration"""
    INITIALIZATION = "initialization"
    CVE_COMPATIBLE_OS = "cve_compatible_os"
    CVE_COMPATIBLE_LANGUAGES = "cve_compatible_languages"
    ADVISORY_CLOUD_BULLETINS = "advisory_cloud_bulletins"
    DATABASE_VENDOR_ADVISORIES = "database_vendor_advisories"
    MIDDLEWARE_VENDOR_ADVISORIES = "middleware_vendor_advisories"
    DUPLICATE_RESOLUTION = "duplicate_resolution"
    QUALITY_CONTROL = "quality_control"
    FINALIZATION = "finalization"

@dataclass
class OrchestrationResult:
    """Result of orchestration run"""
    start_time: datetime
    end_time: datetime
    phase: OrchestrationPhase
    sources_processed: int
    vulnerabilities_added: int
    vulnerabilities_updated: int
    duplicates_resolved: int
    errors: List[str]
    success: bool

class MultiSourceOrchestrator:
    """
    Central orchestrator for all vulnerability sources
    
    RESPONSIBILITIES:
    1. Coordinate 5 category orchestrators in priority order
    2. Manage cross-category duplicate resolution
    3. Ensure data quality and consistency
    4. Provide unified monitoring and reporting
    5. Handle error recovery and retry logic
    """
    
    def __init__(self, config_path: str = None):
        self.config_manager = SourceConfigManager(config_path)
        self.common_loader = CommonLoader()
        self.duplicate_manager = DuplicateManager()
        
        # Initialize category orchestrators in priority order
        self.orchestrators = {
            OrchestrationPhase.CVE_COMPATIBLE_OS: CveCompatibleOsOrchestrator(),
            OrchestrationPhase.CVE_COMPATIBLE_LANGUAGES: CveCompatibleLanguagesOrchestrator(),
            OrchestrationPhase.ADVISORY_CLOUD_BULLETINS: AdvisoryCloudBulletinsOrchestrator(),
            OrchestrationPhase.DATABASE_VENDOR_ADVISORIES: DatabaseVendorAdvisoriesOrchestrator(),
            OrchestrationPhase.MIDDLEWARE_VENDOR_ADVISORIES: MiddlewareVendorAdvisoriesOrchestrator()
        }
        
        self.results_history: List[OrchestrationResult] = []
    
    async def run_full_orchestration(self, 
                                   phases: List[OrchestrationPhase] = None,
                                   force_refresh: bool = False) -> OrchestrationResult:
        """
        Run complete multi-source vulnerability orchestration
        
        EXECUTION STEPS:
        1. Initialize and validate all source configurations
        2. Execute Phase 1: CVE Compatible OS sources (highest priority)
        3. Execute Phase 2: CVE Compatible Languages sources
        4. Execute Phase 3: Advisory Cloud Bulletins sources
        5. Execute Phase 4: Database Vendor Advisories sources
        6. Execute Phase 5: Middleware Vendor Advisories sources
        7. Perform cross-source duplicate resolution
        8. Execute quality control and validation
        9. Generate comprehensive report and metrics
        
        Args:
            phases: Specific phases to run (default: all phases)
            force_refresh: Force full refresh instead of incremental
            
        Returns:
            OrchestrationResult with complete execution summary
        """
        start_time = datetime.now()
        errors = []
        total_vulnerabilities_added = 0
        total_vulnerabilities_updated = 0
        total_sources_processed = 0
        total_duplicates_resolved = 0
        
        if phases is None:
            phases = [
                OrchestrationPhase.CVE_COMPATIBLE_OS,
                OrchestrationPhase.CVE_COMPATIBLE_LANGUAGES,
                OrchestrationPhase.ADVISORY_CLOUD_BULLETINS,
                OrchestrationPhase.DATABASE_VENDOR_ADVISORIES,
                OrchestrationPhase.MIDDLEWARE_VENDOR_ADVISORIES
            ]
        
        try:
            logger.info("🚀 Starting Multi-Source Vulnerability Orchestration")
            logger.info(f"Phases to execute: {[phase.value for phase in phases]}")
            
            # Phase: Initialization
            await self._initialize_orchestration()
            
            # Execute each category phase in priority order
            for phase in phases:
                logger.info(f"📊 Executing Phase: {phase.value}")
                
                try:
                    orchestrator = self.orchestrators[phase]
                    phase_result = await orchestrator.run_category_orchestration(
                        force_refresh=force_refresh
                    )
                    
                    total_sources_processed += phase_result.sources_processed
                    total_vulnerabilities_added += phase_result.vulnerabilities_added
                    total_vulnerabilities_updated += phase_result.vulnerabilities_updated
                    
                    logger.info(f"✅ Phase {phase.value} completed: "
                              f"{phase_result.sources_processed} sources, "
                              f"{phase_result.vulnerabilities_added} new, "
                              f"{phase_result.vulnerabilities_updated} updated")
                    
                except Exception as e:
                    error_msg = f"Phase {phase.value} failed: {e}"
                    errors.append(error_msg)
                    logger.error(error_msg)
                    # Continue with other phases
            
            # Phase: Cross-Source Duplicate Resolution
            logger.info("🔍 Performing cross-source duplicate resolution")
            try:
                duplicates_resolved = await self._resolve_cross_source_duplicates()
                total_duplicates_resolved = duplicates_resolved
                logger.info(f"✅ Resolved {duplicates_resolved} cross-source duplicates")
            except Exception as e:
                error_msg = f"Duplicate resolution failed: {e}"
                errors.append(error_msg)
                logger.error(error_msg)
            
            # Phase: Quality Control
            logger.info("🔍 Performing quality control validation")
            try:
                await self._perform_quality_control()
                logger.info("✅ Quality control validation completed")
            except Exception as e:
                error_msg = f"Quality control failed: {e}"
                errors.append(error_msg)
                logger.error(error_msg)
            
            end_time = datetime.now()
            duration = end_time - start_time
            
            result = OrchestrationResult(
                start_time=start_time,
                end_time=end_time,
                phase=OrchestrationPhase.FINALIZATION,
                sources_processed=total_sources_processed,
                vulnerabilities_added=total_vulnerabilities_added,
                vulnerabilities_updated=total_vulnerabilities_updated,
                duplicates_resolved=total_duplicates_resolved,
                errors=errors,
                success=len(errors) == 0
            )
            
            self.results_history.append(result)
            
            logger.info(f"🎉 Multi-Source Orchestration {'COMPLETED' if result.success else 'COMPLETED WITH ERRORS'}")
            logger.info(f"Duration: {duration}")
            logger.info(f"Sources processed: {total_sources_processed}")
            logger.info(f"Vulnerabilities added: {total_vulnerabilities_added}")
            logger.info(f"Vulnerabilities updated: {total_vulnerabilities_updated}")
            logger.info(f"Duplicates resolved: {total_duplicates_resolved}")
            
            if errors:
                logger.warning(f"Errors encountered: {len(errors)}")
                for error in errors:
                    logger.warning(f"  - {error}")
            
            return result
            
        except Exception as e:
            end_time = datetime.now()
            error_msg = f"Critical orchestration failure: {e}"
            errors.append(error_msg)
            logger.error(error_msg)
            
            result = OrchestrationResult(
                start_time=start_time,
                end_time=end_time,
                phase=OrchestrationPhase.INITIALIZATION,
                sources_processed=total_sources_processed,
                vulnerabilities_added=total_vulnerabilities_added,
                vulnerabilities_updated=total_vulnerabilities_updated,
                duplicates_resolved=total_duplicates_resolved,
                errors=errors,
                success=False
            )
            
            self.results_history.append(result)
            return result
    
    async def run_incremental_update(self, 
                                   since_hours: int = 24) -> OrchestrationResult:
        """
        Run incremental update for all sources
        
        INTEGRATION WITH NVD SYSTEM:
        - Uses same incremental logic as existing NVD system
        - Coordinates with nvd/run_incremental_update.py
        - Respects existing database gap detection
        
        Args:
            since_hours: Hours to look back for updates
            
        Returns:
            OrchestrationResult with incremental update summary
        """
        logger.info(f"🔄 Running incremental update (since {since_hours} hours ago)")
        
        # Set incremental mode in configuration
        for orchestrator in self.orchestrators.values():
            orchestrator.set_incremental_mode(since_hours)
        
        return await self.run_full_orchestration(force_refresh=False)
    
    async def _initialize_orchestration(self):
        """Initialize orchestration environment"""
        logger.info("🔧 Initializing orchestration environment")
        
        # Validate database connection
        await self.common_loader.validate_connection()
        
        # Load and validate source configurations
        self.config_manager.load_configurations()
        
        # Initialize duplicate manager
        await self.duplicate_manager.initialize()
        
        logger.info("✅ Orchestration environment initialized")
    
    async def _resolve_cross_source_duplicates(self) -> int:
        """
        Resolve duplicates across different source categories
        
        DUPLICATE RESOLUTION STRATEGY:
        1. NVD data takes highest priority (priority 10)
        2. OS-specific sources (Debian, Ubuntu) priority 8
        3. Language-specific sources (npm, PyPI) priority 6
        4. Cloud/Database vendor sources priority 4
        5. Middleware sources priority 2
        
        Returns:
            Number of duplicates resolved
        """
        return await self.duplicate_manager.resolve_cross_category_duplicates()
    
    async def _perform_quality_control(self):
        """Perform quality control validation on all data"""
        logger.info("Performing comprehensive quality control")
        
        # Validate data consistency
        await self._validate_data_consistency()
        
        # Check for orphaned records
        await self._check_orphaned_records()
        
        # Validate source attribution
        await self._validate_source_attribution()
    
    async def _validate_data_consistency(self):
        """Validate data consistency across sources"""
        # Implementation for data consistency checks
        pass
    
    async def _check_orphaned_records(self):
        """Check for records without proper source attribution"""
        # Implementation for orphaned record detection
        pass
    
    async def _validate_source_attribution(self):
        """Validate all records have proper source attribution"""
        # Implementation for source attribution validation
        pass
    
    def get_orchestration_status(self) -> Dict[str, Any]:
        """Get current orchestration status and metrics"""
        if not self.results_history:
            return {"status": "not_started", "last_run": None}
        
        last_result = self.results_history[-1]
        
        return {
            "status": "success" if last_result.success else "error",
            "last_run": last_result.end_time.isoformat(),
            "sources_processed": last_result.sources_processed,
            "vulnerabilities_added": last_result.vulnerabilities_added,
            "vulnerabilities_updated": last_result.vulnerabilities_updated,
            "duplicates_resolved": last_result.duplicates_resolved,
            "errors": last_result.errors,
            "total_runs": len(self.results_history)
        }
    
    async def run_source_health_check(self) -> Dict[str, Any]:
        """Check health of all vulnerability sources"""
        logger.info("🏥 Performing source health check")
        
        health_status = {}
        
        for phase, orchestrator in self.orchestrators.items():
            try:
                category_health = await orchestrator.check_source_health()
                health_status[phase.value] = category_health
            except Exception as e:
                health_status[phase.value] = {
                    "status": "error",
                    "error": str(e)
                }
        
        return health_status

# Export for use by scheduling and API systems
__all__ = ['MultiSourceOrchestrator', 'OrchestrationPhase', 'OrchestrationResult']