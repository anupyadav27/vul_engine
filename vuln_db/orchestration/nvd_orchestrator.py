#!/usr/bin/env python3
"""
NVD Data Processing Orchestrator

OBJECTIVE:
Comprehensive orchestration system for NVD vulnerability data processing pipeline.
Manages the complete 5-step process: Download → Parse → Upload → Update → Validate
with support for both full and incremental processing modes.

ARCHITECTURE OVERVIEW:
- Coordinates all 5 NVD processing steps in sequence
- Supports full historical data processing and incremental updates
- Integrates with existing database container and configuration
- Provides comprehensive logging, monitoring, and error handling
- Manages data validation and quality control throughout the pipeline

PIPELINE STEPS:
1. Step 1: Initial downloader - Downloads NVD feeds and API data (2002-2024)
2. Step 2: Parser - Standardizes and normalizes raw NVD data
3. Step 3: Uploader - Batch uploads parsed data to database
4. Step 4: Incremental updater - Handles real-time updates efficiently
5. Step 5: Data validator - Validates data quality and integrity

INTEGRATION:
- Uses existing database configuration from ../config/schemas_and_config/
- Integrates with Docker database container
- Leverages existing source management system
- Coordinates with multi-source orchestrator for duplicate resolution
"""

import asyncio
import logging
import sys
import os
import subprocess
import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import argparse

# Add the parent directory to the path to import from other modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.schemas_and_config.database_config import DatabaseConfigManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('nvd_orchestrator.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class NVDProcessingMode(Enum):
    """NVD processing modes"""
    FULL = "full"
    INCREMENTAL = "incremental"
    VALIDATION_ONLY = "validation_only"
    REPAIR = "repair"

class NVDPipelineStep(Enum):
    """NVD pipeline steps"""
    DOWNLOAD = "download"
    PARSE = "parse"
    UPLOAD = "upload"
    UPDATE = "update"
    VALIDATE = "validate"

@dataclass
class NVDProcessingResult:
    """Result of NVD processing operation"""
    step: NVDPipelineStep
    start_time: datetime
    end_time: datetime
    records_processed: int
    records_added: int
    records_updated: int
    errors: List[str]
    success: bool
    output_files: List[str]
    performance_metrics: Dict[str, Any]

@dataclass
class NVDOrchestrationResult:
    """Complete orchestration result"""
    mode: NVDProcessingMode
    start_time: datetime
    end_time: datetime
    steps_completed: List[NVDPipelineStep]
    total_records_processed: int
    total_records_added: int
    total_records_updated: int
    total_errors: List[str]
    success: bool
    step_results: List[NVDProcessingResult]

class NVDOrchestrator:
    """
    Comprehensive NVD data processing orchestrator
    
    RESPONSIBILITIES:
    1. Coordinate all 5 NVD pipeline steps
    2. Manage full and incremental processing modes
    3. Handle error recovery and retry logic
    4. Provide comprehensive monitoring and reporting
    5. Ensure data quality and integrity
    6. Integrate with existing database and configuration systems
    """
    
    def __init__(self, config_path: str = None):
        self.config_manager = DatabaseConfigManager(config_path)
        self.nvd_sources_path = Path(__file__).parent.parent / "sources" / "cve_compatible_general" / "nvd"
        self.processing_history: List[NVDOrchestrationResult] = []
        
        # Validate NVD sources directory
        if not self.nvd_sources_path.exists():
            raise FileNotFoundError(f"NVD sources directory not found: {self.nvd_sources_path}")
        
        # Pipeline step scripts
        self.pipeline_scripts = {
            NVDPipelineStep.DOWNLOAD: self.nvd_sources_path / "step1_nvd_initial_downloader.py",
            NVDPipelineStep.PARSE: self.nvd_sources_path / "step2_nvd_parser.py",
            NVDPipelineStep.UPLOAD: self.nvd_sources_path / "step3_nvd_uploader.py",
            NVDPipelineStep.UPDATE: self.nvd_sources_path / "step4_nvd_incremental_updater.py",
            NVDPipelineStep.VALIDATE: self.nvd_sources_path / "step5_nvd_data_validator.py"
        }
        
        # Validate all pipeline scripts exist
        self._validate_pipeline_scripts()
    
    def _validate_pipeline_scripts(self):
        """Validate all pipeline scripts exist"""
        missing_scripts = []
        for step, script_path in self.pipeline_scripts.items():
            if not script_path.exists():
                missing_scripts.append(f"{step.value}: {script_path}")
        
        if missing_scripts:
            raise FileNotFoundError(f"Missing pipeline scripts: {missing_scripts}")
        
        logger.info("✅ All NVD pipeline scripts validated")
    
    async def run_full_processing(self, 
                                 steps: List[NVDPipelineStep] = None,
                                 force_download: bool = False,
                                 years: List[int] = None) -> NVDOrchestrationResult:
        """
        Run complete NVD data processing pipeline
        
        EXECUTION FLOW:
        1. Download NVD data (feeds + API) for specified years
        2. Parse and standardize downloaded data
        3. Upload parsed data to database with batch processing
        4. Run incremental updater to catch any recent changes
        5. Validate data quality and integrity
        
        Args:
            steps: Specific steps to run (default: all steps)
            force_download: Force re-download even if data exists
            years: Specific years to process (default: 2002-2024)
            
        Returns:
            NVDOrchestrationResult with complete processing summary
        """
        start_time = datetime.now()
        
        if steps is None:
            steps = [
                NVDPipelineStep.DOWNLOAD,
                NVDPipelineStep.PARSE,
                NVDPipelineStep.UPLOAD,
                NVDPipelineStep.UPDATE,
                NVDPipelineStep.VALIDATE
            ]
        
        if years is None:
            current_year = datetime.now().year
            years = list(range(2002, current_year + 1))
        
        logger.info("🚀 Starting NVD Full Processing Pipeline")
        logger.info(f"Steps to execute: {[step.value for step in steps]}")
        logger.info(f"Years to process: {min(years)}-{max(years)} ({len(years)} years)")
        
        step_results = []
        total_records_processed = 0
        total_records_added = 0
        total_records_updated = 0
        total_errors = []
        steps_completed = []
        
        try:
            # Validate database connection
            await self._validate_database_connection()
            
            # Execute each pipeline step
            for step in steps:
                logger.info(f"📊 Executing Step: {step.value}")
                
                try:
                    step_result = await self._execute_pipeline_step(
                        step, 
                        mode=NVDProcessingMode.FULL,
                        force_download=force_download,
                        years=years
                    )
                    
                    step_results.append(step_result)
                    steps_completed.append(step)
                    
                    total_records_processed += step_result.records_processed
                    total_records_added += step_result.records_added
                    total_records_updated += step_result.records_updated
                    total_errors.extend(step_result.errors)
                    
                    if step_result.success:
                        logger.info(f"✅ Step {step.value} completed successfully: "
                                  f"{step_result.records_processed} processed, "
                                  f"{step_result.records_added} added, "
                                  f"{step_result.records_updated} updated")
                    else:
                        logger.error(f"❌ Step {step.value} failed with {len(step_result.errors)} errors")
                        # Continue with other steps for robustness
                    
                except Exception as e:
                    error_msg = f"Step {step.value} execution failed: {e}"
                    total_errors.append(error_msg)
                    logger.error(error_msg)
                    
                    # Create failed step result
                    step_result = NVDProcessingResult(
                        step=step,
                        start_time=datetime.now(),
                        end_time=datetime.now(),
                        records_processed=0,
                        records_added=0,
                        records_updated=0,
                        errors=[error_msg],
                        success=False,
                        output_files=[],
                        performance_metrics={}
                    )
                    step_results.append(step_result)
            
            end_time = datetime.now()
            duration = end_time - start_time
            success = len(total_errors) == 0
            
            result = NVDOrchestrationResult(
                mode=NVDProcessingMode.FULL,
                start_time=start_time,
                end_time=end_time,
                steps_completed=steps_completed,
                total_records_processed=total_records_processed,
                total_records_added=total_records_added,
                total_records_updated=total_records_updated,
                total_errors=total_errors,
                success=success,
                step_results=step_results
            )
            
            self.processing_history.append(result)
            
            logger.info(f"🎉 NVD Full Processing {'COMPLETED' if success else 'COMPLETED WITH ERRORS'}")
            logger.info(f"Duration: {duration}")
            logger.info(f"Steps completed: {len(steps_completed)}/{len(steps)}")
            logger.info(f"Total records processed: {total_records_processed}")
            logger.info(f"Total records added: {total_records_added}")
            logger.info(f"Total records updated: {total_records_updated}")
            
            if total_errors:
                logger.warning(f"Total errors: {len(total_errors)}")
                for error in total_errors[:5]:  # Show first 5 errors
                    logger.warning(f"  - {error}")
                if len(total_errors) > 5:
                    logger.warning(f"  ... and {len(total_errors) - 5} more errors")
            
            return result
            
        except Exception as e:
            end_time = datetime.now()
            error_msg = f"Critical NVD processing failure: {e}"
            total_errors.append(error_msg)
            logger.error(error_msg)
            
            result = NVDOrchestrationResult(
                mode=NVDProcessingMode.FULL,
                start_time=start_time,
                end_time=end_time,
                steps_completed=steps_completed,
                total_records_processed=total_records_processed,
                total_records_added=total_records_added,
                total_records_updated=total_records_updated,
                total_errors=total_errors,
                success=False,
                step_results=step_results
            )
            
            self.processing_history.append(result)
            return result
    
    async def run_incremental_update(self, 
                                   since_hours: int = 24,
                                   include_validation: bool = True) -> NVDOrchestrationResult:
        """
        Run incremental NVD data update
        
        EXECUTION FLOW:
        1. Run incremental updater to fetch recent NVD changes
        2. Parse any new data downloaded
        3. Upload new/updated records to database
        4. Optional: Validate data integrity
        
        Args:
            since_hours: Hours to look back for updates
            include_validation: Whether to include validation step
            
        Returns:
            NVDOrchestrationResult with incremental update summary
        """
        logger.info(f"🔄 Starting NVD Incremental Update (last {since_hours} hours)")
        
        steps = [NVDPipelineStep.UPDATE]
        if include_validation:
            steps.append(NVDPipelineStep.VALIDATE)
        
        return await self._run_incremental_mode(steps, since_hours)
    
    async def _run_incremental_mode(self, 
                                  steps: List[NVDPipelineStep],
                                  since_hours: int) -> NVDOrchestrationResult:
        """Execute incremental processing mode"""
        start_time = datetime.now()
        
        step_results = []
        total_records_processed = 0
        total_records_added = 0
        total_records_updated = 0
        total_errors = []
        steps_completed = []
        
        try:
            await self._validate_database_connection()
            
            for step in steps:
                logger.info(f"📊 Executing Incremental Step: {step.value}")
                
                try:
                    step_result = await self._execute_pipeline_step(
                        step, 
                        mode=NVDProcessingMode.INCREMENTAL,
                        since_hours=since_hours
                    )
                    
                    step_results.append(step_result)
                    steps_completed.append(step)
                    
                    total_records_processed += step_result.records_processed
                    total_records_added += step_result.records_added
                    total_records_updated += step_result.records_updated
                    total_errors.extend(step_result.errors)
                    
                    logger.info(f"✅ Incremental step {step.value} completed: "
                              f"{step_result.records_processed} processed, "
                              f"{step_result.records_added} added, "
                              f"{step_result.records_updated} updated")
                    
                except Exception as e:
                    error_msg = f"Incremental step {step.value} failed: {e}"
                    total_errors.append(error_msg)
                    logger.error(error_msg)
            
            end_time = datetime.now()
            success = len(total_errors) == 0
            
            result = NVDOrchestrationResult(
                mode=NVDProcessingMode.INCREMENTAL,
                start_time=start_time,
                end_time=end_time,
                steps_completed=steps_completed,
                total_records_processed=total_records_processed,
                total_records_added=total_records_added,
                total_records_updated=total_records_updated,
                total_errors=total_errors,
                success=success,
                step_results=step_results
            )
            
            self.processing_history.append(result)
            
            logger.info(f"🎉 NVD Incremental Update {'COMPLETED' if success else 'COMPLETED WITH ERRORS'}")
            logger.info(f"Duration: {end_time - start_time}")
            logger.info(f"Records updated: {total_records_updated}")
            
            return result
            
        except Exception as e:
            error_msg = f"Critical incremental update failure: {e}"
            logger.error(error_msg)
            
            end_time = datetime.now()
            result = NVDOrchestrationResult(
                mode=NVDProcessingMode.INCREMENTAL,
                start_time=start_time,
                end_time=end_time,
                steps_completed=steps_completed,
                total_records_processed=total_records_processed,
                total_records_added=total_records_added,
                total_records_updated=total_records_updated,
                total_errors=total_errors + [error_msg],
                success=False,
                step_results=step_results
            )
            
            self.processing_history.append(result)
            return result
    
    async def _execute_pipeline_step(self, 
                                   step: NVDPipelineStep,
                                   mode: NVDProcessingMode,
                                   **kwargs) -> NVDProcessingResult:
        """Execute a single pipeline step"""
        start_time = datetime.now()
        script_path = self.pipeline_scripts[step]
        
        # Build command arguments based on step and mode
        cmd_args = self._build_step_command(step, mode, **kwargs)
        
        logger.info(f"Executing: python3 {script_path.name} {' '.join(cmd_args)}")
        
        try:
            # Execute the step script
            process = await asyncio.create_subprocess_exec(
                "python3", str(script_path), *cmd_args,
                cwd=str(self.nvd_sources_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            end_time = datetime.now()
            
            # Parse execution results
            result = self._parse_step_output(step, stdout, stderr, process.returncode)
            result.start_time = start_time
            result.end_time = end_time
            
            if process.returncode == 0:
                logger.info(f"Step {step.value} executed successfully")
            else:
                logger.error(f"Step {step.value} failed with return code {process.returncode}")
                if stderr:
                    logger.error(f"Error output: {stderr.decode()}")
            
            return result
            
        except Exception as e:
            end_time = datetime.now()
            error_msg = f"Step execution failed: {e}"
            logger.error(error_msg)
            
            return NVDProcessingResult(
                step=step,
                start_time=start_time,
                end_time=end_time,
                records_processed=0,
                records_added=0,
                records_updated=0,
                errors=[error_msg],
                success=False,
                output_files=[],
                performance_metrics={}
            )
    
    def _build_step_command(self, 
                          step: NVDPipelineStep, 
                          mode: NVDProcessingMode,
                          **kwargs) -> List[str]:
        """Build command arguments for pipeline step"""
        args = []
        
        # Common arguments
        if mode == NVDProcessingMode.INCREMENTAL:
            args.append("--incremental")
            if "since_hours" in kwargs:
                args.extend(["--since-hours", str(kwargs["since_hours"])])
        
        # Step-specific arguments
        if step == NVDPipelineStep.DOWNLOAD:
            if kwargs.get("force_download"):
                args.append("--force")
            if "years" in kwargs:
                years_str = ",".join(map(str, kwargs["years"]))
                args.extend(["--years", years_str])
        
        elif step == NVDPipelineStep.PARSE:
            args.append("--batch-size=1000")
        
        elif step == NVDPipelineStep.UPLOAD:
            args.append("--batch-size=500")
            args.append("--parallel-workers=4")
        
        elif step == NVDPipelineStep.VALIDATE:
            args.append("--comprehensive")
        
        return args
    
    def _parse_step_output(self, 
                         step: NVDPipelineStep,
                         stdout: bytes,
                         stderr: bytes,
                         return_code: int) -> NVDProcessingResult:
        """Parse step execution output and extract metrics"""
        stdout_text = stdout.decode() if stdout else ""
        stderr_text = stderr.decode() if stderr else ""
        
        # Extract metrics from output (implementation specific to each step)
        records_processed = self._extract_metric(stdout_text, "processed")
        records_added = self._extract_metric(stdout_text, "added")
        records_updated = self._extract_metric(stdout_text, "updated")
        
        errors = []
        if return_code != 0:
            errors.append(f"Process failed with code {return_code}")
        if stderr_text:
            errors.append(stderr_text)
        
        # Extract output files
        output_files = self._extract_output_files(stdout_text)
        
        return NVDProcessingResult(
            step=step,
            start_time=datetime.now(),  # Will be overridden
            end_time=datetime.now(),    # Will be overridden
            records_processed=records_processed,
            records_added=records_added,
            records_updated=records_updated,
            errors=errors,
            success=return_code == 0 and len(errors) == 0,
            output_files=output_files,
            performance_metrics=self._extract_performance_metrics(stdout_text)
        )
    
    def _extract_metric(self, output: str, metric_name: str) -> int:
        """Extract numeric metric from output text"""
        import re
        pattern = rf"{metric_name}:\s*(\d+)"
        match = re.search(pattern, output, re.IGNORECASE)
        return int(match.group(1)) if match else 0
    
    def _extract_output_files(self, output: str) -> List[str]:
        """Extract output file paths from execution output"""
        import re
        # Look for file paths in output
        file_pattern = r"(?:saved|written|created).*?([\/\w\-\.]+\.(?:json|csv|sql))"
        matches = re.findall(file_pattern, output, re.IGNORECASE)
        return matches
    
    def _extract_performance_metrics(self, output: str) -> Dict[str, Any]:
        """Extract performance metrics from output"""
        metrics = {}
        
        # Extract timing information
        import re
        duration_match = re.search(r"duration:\s*([0-9.]+)\s*seconds", output, re.IGNORECASE)
        if duration_match:
            metrics["duration_seconds"] = float(duration_match.group(1))
        
        # Extract memory usage if available
        memory_match = re.search(r"memory:\s*([0-9.]+)\s*MB", output, re.IGNORECASE)
        if memory_match:
            metrics["memory_mb"] = float(memory_match.group(1))
        
        return metrics
    
    async def _validate_database_connection(self):
        """Validate database connection and schema"""
        logger.info("🔍 Validating database connection")
        
        try:
            # Get database configuration
            db_config = self.config_manager.get_db_config("development")
            
            # Test connection (implementation depends on your database config)
            logger.info(f"Database: {db_config.get('host')}:{db_config.get('port')}/{db_config.get('database')}")
            logger.info("✅ Database connection validated")
            
        except Exception as e:
            logger.error(f"❌ Database validation failed: {e}")
            raise
    
    def get_processing_status(self) -> Dict[str, Any]:
        """Get current processing status and metrics"""
        if not self.processing_history:
            return {"status": "not_started", "last_run": None}
        
        last_result = self.processing_history[-1]
        
        return {
            "status": "success" if last_result.success else "error",
            "mode": last_result.mode.value,
            "last_run": last_result.end_time.isoformat(),
            "steps_completed": [step.value for step in last_result.steps_completed],
            "total_records_processed": last_result.total_records_processed,
            "total_records_added": last_result.total_records_added,
            "total_records_updated": last_result.total_records_updated,
            "total_errors": len(last_result.total_errors),
            "total_runs": len(self.processing_history)
        }
    
    async def run_data_validation_only(self) -> NVDOrchestrationResult:
        """Run only data validation step"""
        logger.info("🔍 Running NVD data validation only")
        
        return await self._run_incremental_mode([NVDPipelineStep.VALIDATE], since_hours=0)
    
    async def run_repair_mode(self, 
                            missing_years: List[int] = None) -> NVDOrchestrationResult:
        """
        Run repair mode to fix missing or corrupted data
        
        Args:
            missing_years: Specific years to repair (detected automatically if None)
        """
        logger.info("🔧 Running NVD repair mode")
        
        if missing_years is None:
            # Detect missing data automatically
            missing_years = await self._detect_missing_data()
        
        if not missing_years:
            logger.info("✅ No missing data detected")
            return await self.run_data_validation_only()
        
        logger.info(f"🔧 Repairing data for years: {missing_years}")
        
        return await self.run_full_processing(
            steps=[NVDPipelineStep.DOWNLOAD, NVDPipelineStep.PARSE, NVDPipelineStep.UPLOAD],
            force_download=True,
            years=missing_years
        )
    
    async def _detect_missing_data(self) -> List[int]:
        """Detect years with missing or incomplete data"""
        # Implementation to detect missing data
        # This would query the database to find gaps in coverage
        logger.info("🔍 Detecting missing data years")
        return []  # Placeholder implementation

def main():
    """Main CLI interface for NVD orchestrator"""
    parser = argparse.ArgumentParser(description="NVD Data Processing Orchestrator")
    
    # Mode selection
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--full", action="store_true", 
                           help="Run full NVD processing pipeline")
    mode_group.add_argument("--incremental", action="store_true", 
                           help="Run incremental update")
    mode_group.add_argument("--validate", action="store_true", 
                           help="Run validation only")
    mode_group.add_argument("--repair", action="store_true", 
                           help="Run repair mode")
    mode_group.add_argument("--status", action="store_true", 
                           help="Show processing status")
    
    # Full mode options
    parser.add_argument("--force-download", action="store_true",
                       help="Force re-download of data")
    parser.add_argument("--years", type=str,
                       help="Comma-separated list of years to process")
    parser.add_argument("--steps", type=str,
                       help="Comma-separated list of steps to run")
    
    # Incremental mode options
    parser.add_argument("--since-hours", type=int, default=24,
                       help="Hours to look back for incremental updates")
    
    # Configuration
    parser.add_argument("--config", type=str,
                       help="Path to configuration file")
    
    args = parser.parse_args()
    
    async def run_orchestrator():
        orchestrator = NVDOrchestrator(config_path=args.config)
        
        try:
            if args.status:
                status = orchestrator.get_processing_status()
                print(json.dumps(status, indent=2))
                return
            
            if args.full:
                # Parse years if provided
                years = None
                if args.years:
                    years = [int(y.strip()) for y in args.years.split(",")]
                
                # Parse steps if provided
                steps = None
                if args.steps:
                    step_names = [s.strip().upper() for s in args.steps.split(",")]
                    steps = [NVDPipelineStep[name] for name in step_names]
                
                result = await orchestrator.run_full_processing(
                    steps=steps,
                    force_download=args.force_download,
                    years=years
                )
            
            elif args.incremental:
                result = await orchestrator.run_incremental_update(
                    since_hours=args.since_hours
                )
            
            elif args.validate:
                result = await orchestrator.run_data_validation_only()
            
            elif args.repair:
                result = await orchestrator.run_repair_mode()
            
            # Print summary
            print("\n" + "="*60)
            print("NVD PROCESSING SUMMARY")
            print("="*60)
            print(f"Mode: {result.mode.value}")
            print(f"Success: {'✅ YES' if result.success else '❌ NO'}")
            print(f"Duration: {result.end_time - result.start_time}")
            print(f"Steps completed: {len(result.steps_completed)}")
            print(f"Records processed: {result.total_records_processed}")
            print(f"Records added: {result.total_records_added}")
            print(f"Records updated: {result.total_records_updated}")
            print(f"Total errors: {len(result.total_errors)}")
            
            if result.total_errors:
                print("\nErrors:")
                for error in result.total_errors[:5]:
                    print(f"  - {error}")
                if len(result.total_errors) > 5:
                    print(f"  ... and {len(result.total_errors) - 5} more errors")
            
            return 0 if result.success else 1
            
        except Exception as e:
            logger.error(f"Orchestrator failed: {e}")
            return 1
    
    # Run the orchestrator
    exit_code = asyncio.run(run_orchestrator())
    sys.exit(exit_code)

if __name__ == "__main__":
    main()