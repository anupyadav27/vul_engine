"""
Multi-Source Vulnerability Scheduler

OBJECTIVE:
Automated scheduling system for all 49 vulnerability sources.
Coordinates with existing NVD scheduling and provides unified
automation for incremental updates, full refreshes, and health checks.

INTEGRATION WITH LOCAL CODES:
- Coordinates with existing nvd/run_incremental_update.py
- Uses enhanced database operations from nvd/database.py
- Leverages existing logging and monitoring infrastructure

INTEGRATION ACROSS COMMON CODES:
- Uses MultiSourceOrchestrator for all source coordination
- Employs SourceConfigManager for runtime configuration
- Integrates with common logging and error handling

INTEGRATION WITH OVERALL PROGRAM:
- Entry point for automated vulnerability intelligence collection
- Scheduled via cron/systemd for production deployment
- Provides manual trigger capabilities for emergency updates
- Monitors and reports on overall system health
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
import json
import argparse
import sys
from dataclasses import dataclass

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from orchestration.source_manager import MultiSourceOrchestrator, OrchestrationPhase
from config.source_config import SourceConfigManager, SourceCategory

logger = logging.getLogger(__name__)

@dataclass
class ScheduledJob:
    """Configuration for a scheduled job"""
    name: str
    description: str
    frequency_hours: int
    phases: List[OrchestrationPhase]
    enabled: bool = True
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None

class VulnerabilityScheduler:
    """
    Automated scheduler for multi-source vulnerability intelligence
    
    SCHEDULING STRATEGY:
    1. High-priority incremental updates every 6 hours
    2. Full category refreshes every 24 hours (staggered)
    3. Complete system refresh weekly
    4. Health checks every 2 hours
    5. Emergency manual triggers available
    
    COORDINATION WITH EXISTING NVD:
    - Runs after NVD incremental updates complete
    - Uses same database connection and schema
    - Coordinates timing to avoid conflicts
    """
    
    def __init__(self, config_path: str = None):
        self.config_manager = SourceConfigManager(config_path)
        self.orchestrator = MultiSourceOrchestrator(config_path)
        
        # Define scheduled jobs
        self.scheduled_jobs = {
            'incremental_high_priority': ScheduledJob(
                name='incremental_high_priority',
                description='Incremental updates for high-priority sources (OS & Languages)',
                frequency_hours=6,
                phases=[
                    OrchestrationPhase.CVE_COMPATIBLE_OS,
                    OrchestrationPhase.CVE_COMPATIBLE_LANGUAGES
                ]
            ),
            'incremental_medium_priority': ScheduledJob(
                name='incremental_medium_priority', 
                description='Incremental updates for medium-priority sources (Cloud & DB)',
                frequency_hours=12,
                phases=[
                    OrchestrationPhase.ADVISORY_CLOUD_BULLETINS,
                    OrchestrationPhase.DATABASE_VENDOR_ADVISORIES
                ]
            ),
            'incremental_low_priority': ScheduledJob(
                name='incremental_low_priority',
                description='Incremental updates for low-priority sources (Middleware)',
                frequency_hours=24,
                phases=[
                    OrchestrationPhase.MIDDLEWARE_VENDOR_ADVISORIES
                ]
            ),
            'full_refresh': ScheduledJob(
                name='full_refresh',
                description='Complete refresh of all sources',
                frequency_hours=168,  # Weekly
                phases=[
                    OrchestrationPhase.CVE_COMPATIBLE_OS,
                    OrchestrationPhase.CVE_COMPATIBLE_LANGUAGES,
                    OrchestrationPhase.ADVISORY_CLOUD_BULLETINS,
                    OrchestrationPhase.DATABASE_VENDOR_ADVISORIES,
                    OrchestrationPhase.MIDDLEWARE_VENDOR_ADVISORIES
                ]
            ),
            'health_check': ScheduledJob(
                name='health_check',
                description='Health check for all sources',
                frequency_hours=2,
                phases=[]  # Special case - runs health check instead
            )
        }
        
        self._calculate_next_runs()
    
    async def run_scheduler_daemon(self):
        """
        Run continuous scheduler daemon
        
        DAEMON PROCESS:
        1. Check for jobs due to run every 5 minutes
        2. Execute scheduled jobs in priority order
        3. Update next run times
        4. Log execution results
        5. Handle errors and retries
        """
        logger.info("🕒 Starting Vulnerability Scheduler Daemon")
        
        while True:
            try:
                await self._check_and_run_jobs()
                
                # Sleep for 5 minutes before next check
                await asyncio.sleep(300)  # 5 minutes
                
            except KeyboardInterrupt:
                logger.info("Scheduler daemon interrupted by user")
                break
            except Exception as e:
                logger.error(f"Scheduler daemon error: {e}")
                # Sleep longer on error to avoid tight error loops
                await asyncio.sleep(600)  # 10 minutes
        
        logger.info("Vulnerability Scheduler Daemon stopped")
    
    async def _check_and_run_jobs(self):
        """Check for due jobs and execute them"""
        current_time = datetime.now()
        
        for job_name, job in self.scheduled_jobs.items():
            if not job.enabled:
                continue
            
            if job.next_run and current_time >= job.next_run:
                logger.info(f"🚀 Executing scheduled job: {job.name}")
                
                try:
                    if job_name == 'health_check':
                        await self._run_health_check_job(job)
                    else:
                        await self._run_orchestration_job(job)
                    
                    # Update timing
                    job.last_run = current_time
                    job.next_run = current_time + timedelta(hours=job.frequency_hours)
                    
                    logger.info(f"✅ Job {job.name} completed. Next run: {job.next_run}")
                    
                except Exception as e:
                    logger.error(f"❌ Job {job.name} failed: {e}")
                    # Schedule retry in 30 minutes
                    job.next_run = current_time + timedelta(minutes=30)
    
    async def _run_orchestration_job(self, job: ScheduledJob):
        """Run orchestration job with specified phases"""
        force_refresh = job.name == 'full_refresh'
        
        result = await self.orchestrator.run_full_orchestration(
            phases=job.phases,
            force_refresh=force_refresh
        )
        
        # Log results
        logger.info(f"Job {job.name} processed {result.sources_processed} sources")
        logger.info(f"Added: {result.vulnerabilities_added}, Updated: {result.vulnerabilities_updated}")
        
        if result.errors:
            logger.warning(f"Job {job.name} completed with {len(result.errors)} errors")
    
    async def _run_health_check_job(self, job: ScheduledJob):
        """Run health check job"""
        health_status = await self.orchestrator.run_source_health_check()
        
        # Analyze health status
        total_sources = 0
        healthy_sources = 0
        
        for category, status in health_status.items():
            if isinstance(status, dict) and 'sources' in status:
                category_sources = status['sources']
                total_sources += len(category_sources)
                healthy_sources += sum(1 for s in category_sources.values() if s.get('status') == 'healthy')
        
        health_percentage = (healthy_sources / total_sources * 100) if total_sources > 0 else 0
        
        logger.info(f"Health check: {healthy_sources}/{total_sources} sources healthy ({health_percentage:.1f}%)")
        
        if health_percentage < 80:
            logger.warning(f"Low source health detected: {health_percentage:.1f}%")
    
    def _calculate_next_runs(self):
        """Calculate initial next run times for all jobs"""
        current_time = datetime.now()
        
        # Stagger job start times to avoid conflicts
        stagger_offsets = {
            'health_check': 0,           # Start immediately
            'incremental_high_priority': 15,  # 15 minutes after health check
            'incremental_medium_priority': 30, # 30 minutes after
            'incremental_low_priority': 45,    # 45 minutes after
            'full_refresh': 60               # 1 hour after (for initial setup)
        }
        
        for job_name, job in self.scheduled_jobs.items():
            offset_minutes = stagger_offsets.get(job_name, 0)
            job.next_run = current_time + timedelta(minutes=offset_minutes)
            logger.info(f"Job {job.name} scheduled for: {job.next_run}")
    
    async def run_manual_job(self, job_name: str) -> bool:
        """
        Run a specific job manually
        
        Args:
            job_name: Name of job to run
            
        Returns:
            True if successful, False otherwise
        """
        if job_name not in self.scheduled_jobs:
            logger.error(f"Unknown job: {job_name}")
            return False
        
        job = self.scheduled_jobs[job_name]
        logger.info(f"🔧 Running manual job: {job.name}")
        
        try:
            if job_name == 'health_check':
                await self._run_health_check_job(job)
            else:
                await self._run_orchestration_job(job)
            
            logger.info(f"✅ Manual job {job.name} completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Manual job {job.name} failed: {e}")
            return False
    
    async def run_emergency_update(self, categories: List[str] = None) -> bool:
        """
        Run emergency update for specific categories or all sources
        
        Args:
            categories: List of category names to update (default: all)
            
        Returns:
            True if successful, False otherwise
        """
        logger.warning("🚨 Running EMERGENCY vulnerability update")
        
        try:
            if categories:
                # Map category names to phases
                category_mapping = {
                    'os': OrchestrationPhase.CVE_COMPATIBLE_OS,
                    'languages': OrchestrationPhase.CVE_COMPATIBLE_LANGUAGES,
                    'cloud': OrchestrationPhase.ADVISORY_CLOUD_BULLETINS,
                    'database': OrchestrationPhase.DATABASE_VENDOR_ADVISORIES,
                    'middleware': OrchestrationPhase.MIDDLEWARE_VENDOR_ADVISORIES
                }
                
                phases = [category_mapping[cat] for cat in categories if cat in category_mapping]
            else:
                phases = None  # All phases
            
            result = await self.orchestrator.run_full_orchestration(
                phases=phases,
                force_refresh=True
            )
            
            logger.warning(f"🚨 Emergency update completed: "
                         f"{result.sources_processed} sources, "
                         f"{result.vulnerabilities_added} new vulnerabilities")
            
            return result.success
            
        except Exception as e:
            logger.error(f"❌ Emergency update failed: {e}")
            return False
    
    def get_scheduler_status(self) -> Dict[str, Any]:
        """Get current scheduler status"""
        current_time = datetime.now()
        
        job_status = {}
        for job_name, job in self.scheduled_jobs.items():
            time_until_next = None
            if job.next_run:
                time_until_next = (job.next_run - current_time).total_seconds()
            
            job_status[job_name] = {
                'enabled': job.enabled,
                'description': job.description,
                'frequency_hours': job.frequency_hours,
                'last_run': job.last_run.isoformat() if job.last_run else None,
                'next_run': job.next_run.isoformat() if job.next_run else None,
                'time_until_next_seconds': time_until_next
            }
        
        return {
            'current_time': current_time.isoformat(),
            'jobs': job_status,
            'orchestrator_status': self.orchestrator.get_orchestration_status()
        }
    
    def enable_job(self, job_name: str) -> bool:
        """Enable a scheduled job"""
        if job_name in self.scheduled_jobs:
            self.scheduled_jobs[job_name].enabled = True
            logger.info(f"Enabled job: {job_name}")
            return True
        return False
    
    def disable_job(self, job_name: str) -> bool:
        """Disable a scheduled job"""
        if job_name in self.scheduled_jobs:
            self.scheduled_jobs[job_name].enabled = False
            logger.info(f"Disabled job: {job_name}")
            return True
        return False

async def main():
    """
    Command-line interface for vulnerability scheduler
    
    USAGE EXAMPLES:
    python scheduler.py daemon                    # Run continuous daemon
    python scheduler.py manual health_check       # Run health check manually
    python scheduler.py emergency                 # Emergency update all sources
    python scheduler.py emergency --categories os,languages  # Emergency update specific categories
    python scheduler.py status                    # Show scheduler status
    """
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    parser = argparse.ArgumentParser(description='Multi-Source Vulnerability Scheduler')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Daemon command
    daemon_parser = subparsers.add_parser('daemon', help='Run scheduler daemon')
    
    # Manual command
    manual_parser = subparsers.add_parser('manual', help='Run job manually')
    manual_parser.add_argument('job_name', help='Name of job to run')
    
    # Emergency command
    emergency_parser = subparsers.add_parser('emergency', help='Run emergency update')
    emergency_parser.add_argument('--categories', help='Comma-separated list of categories (os,languages,cloud,database,middleware)')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Show scheduler status')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize scheduler
    scheduler = VulnerabilityScheduler()
    
    try:
        if args.command == 'daemon':
            await scheduler.run_scheduler_daemon()
        
        elif args.command == 'manual':
            success = await scheduler.run_manual_job(args.job_name)
            sys.exit(0 if success else 1)
        
        elif args.command == 'emergency':
            categories = None
            if args.categories:
                categories = [cat.strip() for cat in args.categories.split(',')]
            
            success = await scheduler.run_emergency_update(categories)
            sys.exit(0 if success else 1)
        
        elif args.command == 'status':
            status = scheduler.get_scheduler_status()
            print(json.dumps(status, indent=2, default=str))
    
    except KeyboardInterrupt:
        logger.info("Operation interrupted by user")
    except Exception as e:
        logger.error(f"Command failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    asyncio.run(main())

# Export for use by other systems
__all__ = ['VulnerabilityScheduler', 'ScheduledJob']