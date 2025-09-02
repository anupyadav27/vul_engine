"""
Category Orchestrators for Multi-Source Vulnerability System

OBJECTIVE:
Specialized orchestrators for each category of vulnerability sources.
Each orchestrator manages sources within its category, handles category-specific
processing logic, and coordinates with the main orchestrator.

CATEGORIES:
1. CVE Compatible OS Sources (11 sources)
2. CVE Compatible Languages Sources (5 sources) 
3. Advisory Cloud Bulletins (5 sources)
4. Database Vendor Advisories (6 sources)
5. Middleware Vendor Advisories (7 sources)
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from abc import ABC, abstractmethod

from ..sources.base import BaseFetcher, BaseParser, CommonLoader, VulnSourceException

logger = logging.getLogger(__name__)

class BaseCategoryOrchestrator(ABC):
    """Base class for category-specific orchestrators"""
    
    def __init__(self, category_name: str):
        self.category_name = category_name
        self.sources: Dict[str, BaseFetcher] = {}
        self.parsers: Dict[str, BaseParser] = {}
        self.common_loader = CommonLoader()
        
    @abstractmethod
    async def initialize_sources(self) -> bool:
        """Initialize all sources in this category"""
        pass
        
    @abstractmethod
    async def process_category(self, source_filter: Optional[List[str]] = None) -> Dict[str, Any]:
        """Process sources in this category (optionally filtered)"""
        pass
        
    async def process_source(self, source_name: str) -> Dict[str, Any]:
        """Process a single source"""
        try:
            if source_name not in self.sources:
                logger.error(f"Source {source_name} not found in {self.category_name}")
                return {"success": False, "error": "Source not found"}
                
            fetcher = self.sources[source_name]
            parser = self.parsers.get(source_name)
            
            # Fetch data
            raw_data = await fetcher.fetch_vulnerabilities()
            if not raw_data:
                return {"success": True, "vulnerabilities": 0, "message": "No new data"}
                
            # Parse data if parser exists
            if parser:
                parsed_data = await parser.parse_vulnerabilities(raw_data)
            else:
                parsed_data = raw_data
                
            # Load to database
            result = await self.common_loader.load_vulnerabilities(parsed_data, source_name)
            
            return {
                "success": True,
                "vulnerabilities": len(parsed_data),
                "added": result.get("added", 0),
                "updated": result.get("updated", 0)
            }
            
        except Exception as e:
            logger.error(f"Error processing source {source_name}: {e}")
            return {"success": False, "error": str(e)}

    async def process_single_source(self, source_name: str, test_mode: bool = False) -> Dict[str, Any]:
        """
        Process a single source for testing purposes
        
        Args:
            source_name: Name of the source to process
            test_mode: If True, limits data processing for testing
        """
        if source_name not in self.sources:
            available_sources = list(self.sources.keys())
            return {
                "success": False, 
                "error": f"Source '{source_name}' not found. Available sources: {available_sources}"
            }
        
        logger.info(f"🧪 Processing single source: {source_name} (test_mode={test_mode})")
        
        try:
            fetcher = self.sources[source_name]
            parser = self.parsers.get(source_name)
            
            # In test mode, limit the amount of data processed
            if test_mode and hasattr(fetcher, 'set_test_mode'):
                fetcher.set_test_mode(limit=10)  # Only process 10 records for testing
            
            # Fetch data
            raw_data = await fetcher.fetch_vulnerabilities()
            if not raw_data:
                return {"success": True, "vulnerabilities": 0, "message": "No new data"}
            
            # Limit data in test mode
            if test_mode and len(raw_data) > 10:
                raw_data = raw_data[:10]
                logger.info(f"  🧪 Test mode: Limited to {len(raw_data)} records")
                
            # Parse data if parser exists
            if parser:
                parsed_data = await parser.parse_vulnerabilities(raw_data)
            else:
                parsed_data = raw_data
                
            # Load to database
            result = await self.common_loader.load_vulnerabilities(parsed_data, source_name)
            
            return {
                "success": True,
                "source": source_name,
                "test_mode": test_mode,
                "vulnerabilities": len(parsed_data),
                "added": result.get("added", 0),
                "updated": result.get("updated", 0),
                "message": f"Successfully processed {source_name}"
            }
            
        except Exception as e:
            logger.error(f"Error processing source {source_name}: {e}")
            return {"success": False, "source": source_name, "error": str(e)}
    
    async def test_source_connection(self, source_name: str) -> Dict[str, Any]:
        """
        Test connection to a source without processing data
        """
        if source_name not in self.sources:
            return {"success": False, "error": f"Source '{source_name}' not found"}
        
        try:
            fetcher = self.sources[source_name]
            
            # Test connection
            if hasattr(fetcher, 'test_connection'):
                connection_result = await fetcher.test_connection()
            else:
                # Fallback: try to fetch 1 record
                test_data = await fetcher.fetch_vulnerabilities(limit=1)
                connection_result = test_data is not None
            
            return {
                "success": connection_result,
                "source": source_name,
                "message": f"Connection test {'passed' if connection_result else 'failed'}"
            }
            
        except Exception as e:
            return {"success": False, "source": source_name, "error": str(e)}
    
    def list_available_sources(self) -> Dict[str, Any]:
        """List all available sources in this category"""
        return {
            "category": self.category_name,
            "available_sources": list(self.sources.keys()),
            "initialized_sources": len(self.sources),
            "sources_with_parsers": list(self.parsers.keys())
        }

class CveCompatibleOsOrchestrator(BaseCategoryOrchestrator):
    """Orchestrator for CVE Compatible OS sources"""
    
    def __init__(self):
        super().__init__("CVE Compatible OS")
        self.source_processors = {}  # Store specialized processors for each source
        
    async def initialize_sources(self) -> bool:
        """Initialize OS vulnerability sources"""
        try:
            # Import Debian components
            from ..sources.cve_compatible_os.debian.fetcher import DebianFetcher
            from ..sources.cve_compatible_os.debian.parser import DebianParser
            from ..sources.cve_compatible_os.debian.config import get_debian_config
            
            # Initialize Debian source with its specialized pipeline
            debian_config = get_debian_config()
            self.sources["debian"] = DebianFetcher(debian_config)
            self.parsers["debian"] = DebianParser(debian_config)
            
            # Store Debian-specific processor for enhanced handling
            self.source_processors["debian"] = {
                'config': debian_config,
                'priority': 8,  # High priority for OS sources
                'batch_size': 100,
                'quality_threshold': 0.8
            }
            
            # Initialize other OS sources (Ubuntu, RedHat, SUSE, etc.)
            try:
                from ..sources.cve_compatible_os.ubuntu.fetcher import UbuntuFetcher
                from ..sources.cve_compatible_os.ubuntu.parser import UbuntuParser
                from ..sources.cve_compatible_os.ubuntu.config import get_ubuntu_config
                
                ubuntu_config = get_ubuntu_config()
                self.sources["ubuntu"] = UbuntuFetcher(ubuntu_config)
                self.parsers["ubuntu"] = UbuntuParser(ubuntu_config)
                self.source_processors["ubuntu"] = {
                    'config': ubuntu_config,
                    'priority': 8,
                    'batch_size': 100,
                    'quality_threshold': 0.8
                }
            except ImportError:
                logger.warning("Ubuntu source not available")
            
            # Add other OS sources as they become available
            # RedHat, SUSE, Alpine, CentOS, etc.
            
            logger.info(f"✓ Initialized {len(self.sources)} OS sources: {list(self.sources.keys())}")
            return True
            
        except ImportError as e:
            logger.warning(f"Some OS sources not available: {e}")
            # Continue with available sources
            return len(self.sources) > 0
            
    async def process_category(self, source_filter: Optional[List[str]] = None) -> Dict[str, Any]:
        """Process all OS vulnerability sources in priority order"""
        logger.info(f"🔄 Processing {self.category_name} category")
        
        results = {}
        total_vulnerabilities_added = 0
        total_vulnerabilities_updated = 0
        errors = []
        
        # Sort sources by priority (highest first)
        sorted_sources = sorted(
            self.source_processors.items(),
            key=lambda x: x[1]['priority'],
            reverse=True
        )
        
        for source_name, processor_config in sorted_sources:
            if source_filter and source_name not in source_filter:
                continue
                
            if source_name not in self.sources:
                continue
                
            logger.info(f"📥 Processing source: {source_name}")
            
            try:
                # Use enhanced processing for each source
                result = await self._process_source_enhanced(source_name, processor_config)
                results[source_name] = result
                
                if result["success"]:
                    total_vulnerabilities_added += result.get("vulnerabilities_added", 0)
                    total_vulnerabilities_updated += result.get("vulnerabilities_updated", 0)
                    logger.info(f"✓ {source_name}: {result.get('vulnerabilities_added', 0)} added, "
                               f"{result.get('vulnerabilities_updated', 0)} updated")
                else:
                    errors.append(f"{source_name}: {result.get('error', 'Unknown error')}")
                    logger.error(f"❌ {source_name} failed: {result.get('error', 'Unknown error')}")
                    
            except Exception as e:
                error_msg = f"{source_name}: {str(e)}"
                errors.append(error_msg)
                logger.error(f"❌ {source_name} exception: {e}")
                results[source_name] = {"success": False, "error": str(e)}
        
        return {
            "category": self.category_name,
            "sources_processed": len(results),
            "sources_successful": sum(1 for r in results.values() if r.get("success", False)),
            "vulnerabilities_added": total_vulnerabilities_added,
            "vulnerabilities_updated": total_vulnerabilities_updated,
            "errors": errors,
            "results": results
        }
    
    async def _process_source_enhanced(self, source_name: str, processor_config: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced processing for OS sources with quality validation"""
        try:
            fetcher = self.sources[source_name]
            parser = self.parsers.get(source_name)
            
            # Step 1: Fetch raw data
            logger.info(f"  📥 Fetching data from {source_name}")
            raw_data = await fetcher.fetch_vulnerabilities()
            
            if not raw_data:
                return {
                    "success": True, 
                    "vulnerabilities_added": 0, 
                    "vulnerabilities_updated": 0,
                    "message": "No new data available"
                }
            
            logger.info(f"  ✓ Fetched {len(raw_data)} records from {source_name}")
            
            # Step 2: Parse data
            if parser:
                logger.info(f"  🔄 Parsing data for {source_name}")
                parsed_data = await parser.parse_vulnerabilities(raw_data)
                logger.info(f"  ✓ Parsed {len(parsed_data)} records for {source_name}")
            else:
                parsed_data = raw_data
                logger.info(f"  ⚠️ No parser for {source_name}, using raw data")
            
            # Step 3: Apply quality validation (integrate with enhanced schema)
            logger.info(f"  🔍 Validating quality for {source_name}")
            validated_data = await self._apply_quality_validation(parsed_data, source_name, processor_config)
            logger.info(f"  ✓ Validated {len(validated_data)} records for {source_name}")
            
            # Step 4: Load to database using enhanced schema
            logger.info(f"  💾 Loading data to database for {source_name}")
            result = await self.common_loader.load_vulnerabilities_enhanced(
                validated_data, 
                source_name,
                processor_config
            )
            
            return {
                "success": True,
                "vulnerabilities_added": result.get("added", 0),
                "vulnerabilities_updated": result.get("updated", 0),
                "vulnerabilities_processed": len(validated_data),
                "quality_score": result.get("average_quality_score", 0.0),
                "data_loss_count": result.get("data_loss_count", 0)
            }
            
        except Exception as e:
            logger.error(f"Error in enhanced processing for {source_name}: {e}")
            return {"success": False, "error": str(e)}
    
    async def _apply_quality_validation(
        self, 
        data: List[Dict[str, Any]], 
        source_name: str,
        processor_config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Apply source-specific quality validation"""
        
        validated_data = []
        quality_threshold = processor_config.get('quality_threshold', 0.8)
        
        for record in data:
            # Apply source-specific validation rules
            validation_result = await self._validate_record(record, source_name)
            
            # Only include records that meet quality threshold
            if validation_result['quality_score'] >= quality_threshold:
                # Add quality metadata to record
                record['_quality_metadata'] = {
                    'quality_score': validation_result['quality_score'],
                    'completeness_score': validation_result['completeness_score'],
                    'accuracy_score': validation_result['accuracy_score'],
                    'consistency_score': validation_result['consistency_score'],
                    'validation_timestamp': datetime.utcnow().isoformat(),
                    'validation_errors': validation_result['errors'],
                    'source_name': source_name
                }
                validated_data.append(record)
            else:
                logger.warning(f"Record {record.get('cve_id', 'unknown')} from {source_name} "
                             f"below quality threshold: {validation_result['quality_score']:.2f}")
        
        return validated_data
    
    async def _validate_record(self, record: Dict[str, Any], source_name: str) -> Dict[str, Any]:
        """Validate individual vulnerability record"""
        errors = []
        scores = {'completeness': 1.0, 'accuracy': 1.0, 'consistency': 1.0}
        
        # Common validation rules
        if not record.get('cve_id'):
            errors.append("Missing CVE ID")
            scores['completeness'] -= 0.5
        
        if not record.get('description'):
            errors.append("Missing description")
            scores['completeness'] -= 0.3
        
        # Source-specific validation
        if source_name == 'debian':
            # Debian-specific validation
            if not record.get('packages'):
                errors.append("Missing Debian packages")
                scores['completeness'] -= 0.2
            
            # Validate Debian package format
            packages = record.get('packages', [])
            for pkg in packages:
                if not pkg.get('package_name'):
                    errors.append("Invalid package format")
                    scores['accuracy'] -= 0.1
                    break
        
        elif source_name == 'ubuntu':
            # Ubuntu-specific validation
            if not record.get('ubuntu_priority'):
                scores['completeness'] -= 0.1
        
        # Calculate overall quality score
        overall_quality = sum(scores.values()) / len(scores)
        
        return {
            'quality_score': max(0.0, overall_quality),
            'completeness_score': max(0.0, scores['completeness']),
            'accuracy_score': max(0.0, scores['accuracy']),
            'consistency_score': max(0.0, scores['consistency']),
            'errors': errors
        }
    
    async def run_category_orchestration(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Run the complete OS category orchestration"""
        start_time = datetime.now()
        
        try:
            # Initialize sources if not already done
            if not self.sources:
                await self.initialize_sources()
            
            # Process all sources in category
            result = await self.process_category()
            
            end_time = datetime.now()
            duration = end_time - start_time
            
            result.update({
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration.total_seconds(),
                'force_refresh': force_refresh
            })
            
            logger.info(f"✅ {self.category_name} orchestration completed in {duration}")
            return result
            
        except Exception as e:
            logger.error(f"❌ {self.category_name} orchestration failed: {e}")
            return {
                'category': self.category_name,
                'success': False,
                'error': str(e),
                'start_time': start_time.isoformat(),
                'end_time': datetime.now().isoformat()
            }
    
    async def check_source_health(self) -> Dict[str, Any]:
        """Check health of all OS sources"""
        health_status = {}
        
        for source_name, fetcher in self.sources.items():
            try:
                # Simple health check - attempt to connect to source
                health_check = await fetcher.health_check() if hasattr(fetcher, 'health_check') else True
                health_status[source_name] = {
                    'status': 'healthy' if health_check else 'unhealthy',
                    'last_checked': datetime.now().isoformat()
                }
            except Exception as e:
                health_status[source_name] = {
                    'status': 'error',
                    'error': str(e),
                    'last_checked': datetime.now().isoformat()
                }
        
        return health_status

class CveCompatibleLanguagesOrchestrator(BaseCategoryOrchestrator):
    """Orchestrator for CVE Compatible Language sources"""
    
    def __init__(self):
        super().__init__("CVE Compatible Languages")
        
    async def initialize_sources(self) -> bool:
        """Initialize language package vulnerability sources"""
        try:
            # Initialize NPM, PyPI, RubyGems, Maven, NuGet sources
            self.sources = {
                # Placeholder for now - actual implementations would go here
            }
            
            logger.info(f"Initialized {len(self.sources)} language sources")
            return True
            
        except Exception as e:
            logger.warning(f"Language sources initialization error: {e}")
            self.sources = {}
            return True
            
    async def process_category(self, source_filter: Optional[List[str]] = None) -> Dict[str, Any]:
        """Process all language vulnerability sources"""
        results = {}
        total_vulnerabilities = 0
        
        for source_name in self.sources:
            if source_filter and source_name not in source_filter:
                continue
                
            result = await self.process_source(source_name)
            results[source_name] = result
            if result["success"]:
                total_vulnerabilities += result.get("vulnerabilities", 0)
                
        return {
            "category": self.category_name,
            "sources_processed": len(self.sources),
            "total_vulnerabilities": total_vulnerabilities,
            "results": results
        }

class AdvisoryCloudBulletinsOrchestrator(BaseCategoryOrchestrator):
    """Orchestrator for Cloud Advisory sources"""
    
    def __init__(self):
        super().__init__("Advisory Cloud Bulletins")
        
    async def initialize_sources(self) -> bool:
        """Initialize cloud provider advisory sources"""
        try:
            # Initialize AWS, Azure, GCP, Oracle Cloud, IBM Cloud sources
            self.sources = {
                # Placeholder for now - actual implementations would go here
            }
            
            logger.info(f"Initialized {len(self.sources)} cloud advisory sources")
            return True
            
        except Exception as e:
            logger.warning(f"Cloud advisory sources initialization error: {e}")
            self.sources = {}
            return True
            
    async def process_category(self, source_filter: Optional[List[str]] = None) -> Dict[str, Any]:
        """Process all cloud advisory sources"""
        results = {}
        total_vulnerabilities = 0
        
        for source_name in self.sources:
            if source_filter and source_name not in source_filter:
                continue
                
            result = await self.process_source(source_name)
            results[source_name] = result
            if result["success"]:
                total_vulnerabilities += result.get("vulnerabilities", 0)
                
        return {
            "category": self.category_name,
            "sources_processed": len(self.sources),
            "total_vulnerabilities": total_vulnerabilities,
            "results": results
        }

class DatabaseVendorAdvisoriesOrchestrator(BaseCategoryOrchestrator):
    """Orchestrator for Database Vendor Advisory sources"""
    
    def __init__(self):
        super().__init__("Database Vendor Advisories")
        
    async def initialize_sources(self) -> bool:
        """Initialize database vendor advisory sources"""
        try:
            # Initialize Oracle, MySQL, PostgreSQL, MongoDB, etc. sources
            self.sources = {
                # Placeholder for now - actual implementations would go here
            }
            
            logger.info(f"Initialized {len(self.sources)} database vendor sources")
            return True
            
        except Exception as e:
            logger.warning(f"Database vendor sources initialization error: {e}")
            self.sources = {}
            return True
            
    async def process_category(self, source_filter: Optional[List[str]] = None) -> Dict[str, Any]:
        """Process all database vendor advisory sources"""
        results = {}
        total_vulnerabilities = 0
        
        for source_name in self.sources:
            if source_filter and source_name not in source_filter:
                continue
                
            result = await self.process_source(source_name)
            results[source_name] = result
            if result["success"]:
                total_vulnerabilities += result.get("vulnerabilities", 0)
                
        return {
            "category": self.category_name,
            "sources_processed": len(self.sources),
            "total_vulnerabilities": total_vulnerabilities,
            "results": results
        }

class MiddlewareVendorAdvisoriesOrchestrator(BaseCategoryOrchestrator):
    """Orchestrator for Middleware Vendor Advisory sources"""
    
    def __init__(self):
        super().__init__("Middleware Vendor Advisories")
        
    async def initialize_sources(self) -> bool:
        """Initialize middleware vendor advisory sources"""
        try:
            # Initialize Apache, Nginx, Tomcat, JBoss, etc. sources
            self.sources = {
                # Placeholder for now - actual implementations would go here
            }
            
            logger.info(f"Initialized {len(self.sources)} middleware vendor sources")
            return True
            
        except Exception as e:
            logger.warning(f"Middleware vendor sources initialization error: {e}")
            self.sources = {}
            return True
            
    async def process_category(self, source_filter: Optional[List[str]] = None) -> Dict[str, Any]:
        """Process all middleware vendor advisory sources"""
        results = {}
        total_vulnerabilities = 0
        
        for source_name in self.sources:
            if source_filter and source_name not in source_filter:
                continue
                
            result = await self.process_source(source_name)
            results[source_name] = result
            if result["success"]:
                total_vulnerabilities += result.get("vulnerabilities", 0)
                
        return {
            "category": self.category_name,
            "sources_processed": len(self.sources),
            "total_vulnerabilities": total_vulnerabilities,
            "results": results
        }