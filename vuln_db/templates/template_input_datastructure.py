#!/usr/bin/env python3
"""
[SOURCE_NAME] Data Downloader and Structure Analyzer

TEMPLATE: Replace [SOURCE_NAME] with your actual source name throughout this file.

OBJECTIVE:
Downloads complete [SOURCE_NAME] vulnerability data and saves as timestamped JSON file.
Analyzes data structure, validates API connectivity, and generates field mappings.

ENHANCED: Supports offline processing by saving data with comprehensive metadata.

IMPLEMENTATION STAGES:
Stage 1: API Connectivity and Data Download ✓
Stage 2: Data Structure Analysis ✓
Stage 3: Field Mapping Generation ✓
Stage 4: Offline JSON Processing ✓

RELATIONS TO LOCAL CODES:
- Inherits: sources/base/base_fetcher.py
- Uses: Centralized configuration system
- Integrates: [SOURCE_NAME]-specific configurations

RELATIONS TO WHOLE VUL_DB:
- Data Flow: API → JSON File → Parser → Database
- Schema: Converts to common vulnerability schema
- Quality: Maintains data quality standards
"""

import asyncio
import aiohttp
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

# Add vuln_db root to Python path for imports
current_dir = Path(__file__).resolve().parent
vuln_db_root = current_dir.parent.parent.parent
sys.path.insert(0, str(vuln_db_root))
sys.path.append(str(vuln_db_root / "config"))

from source_config import get_source_config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class [SOURCE_NAME]DataDownloader:
    """
    [SOURCE_NAME] data downloader and structure analyzer
    
    TEMPLATE INSTRUCTIONS:
    1. Replace [SOURCE_NAME] with your source name
    2. Update API_ENDPOINT with your source's URL
    3. Customize authentication if required
    4. Adapt data extraction logic for your source format
    """
    
    def __init__(self):
        """Initialize [SOURCE_NAME] downloader"""
        # UPDATE: Set your source configuration
        self.config = self.get_source_config()
        self.source_name = "[source_name]"  # UPDATE: lowercase with underscores
        self.api_endpoint = "https://your-source.com/api"  # UPDATE: your API URL
        
        # UPDATE: Add authentication if required
        self.headers = {
            'User-Agent': 'VulnDB/1.0',
            'Accept': 'application/json',
            # 'Authorization': f'Bearer {api_token}',  # Uncomment if needed
        }
        
        # Session for connection pooling
        self.session = None
        
        # Statistics tracking
        self.stats = {
            'total_records': 0,
            'total_vulnerabilities': 0,
            'unique_identifiers': set(),
            'data_size_mb': 0
        }
    
    def get_source_config(self) -> Dict[str, Any]:
        """Get [SOURCE_NAME] configuration"""
        # Try centralized config first
        try:
            return get_source_config(self.source_name)
        except:
            # Fallback to default config
            return {
                'name': self.source_name,
                'url': self.api_endpoint,
                'category': 'cve_compatible_os',  # UPDATE: your category
                'priority': 8,
                'status': 'working',
                'timeout_seconds': 30,
                'retry_attempts': 3
            }
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            headers=self.headers,
            timeout=aiohttp.ClientTimeout(total=self.config.get('timeout_seconds', 30))
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def download_and_save_data(self, output_dir: str = None) -> str:
        """
        Download complete [SOURCE_NAME] data and save as timestamped JSON file
        
        TEMPLATE: Customize this method for your source's API format
        """
        if output_dir is None:
            output_dir = current_dir / "output" / "data_downloads"
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"🚀 Starting [SOURCE_NAME] data download")
        
        try:
            # Download data from source
            raw_data = await self._download_raw_data()
            
            # Analyze data structure
            structure_analysis = self._analyze_data_structure(raw_data)
            logger.info(f"✓ Data structure analysis completed")
            
            # Update statistics
            self.stats['total_records'] = len(raw_data) if isinstance(raw_data, list) else len(raw_data.get('data', {}))
            self.stats['total_vulnerabilities'] = self._count_vulnerabilities(raw_data)
            
            # Generate timestamped filename
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"{self.source_name}_data_{timestamp}.json"
            output_file = output_path / filename
            
            # Prepare final data with metadata
            file_size_mb = len(json.dumps(raw_data).encode('utf-8')) / (1024 * 1024)
            self.stats['data_size_mb'] = file_size_mb
            
            final_data = {
                'metadata': {
                    'download_timestamp': datetime.utcnow().isoformat(),
                    'source_name': self.source_name,
                    'source_url': self.api_endpoint,
                    'total_records': self.stats['total_records'],
                    'total_vulnerabilities': self.stats['total_vulnerabilities'],
                    'data_size_mb': file_size_mb,
                    'content_type': 'application/json',
                    'structure_analysis': structure_analysis,
                    'field_mappings': self._generate_field_mappings(raw_data),
                    'download_config': self.config
                },
                'data': raw_data
            }
            
            # Save to file
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(final_data, f, indent=2, ensure_ascii=False, default=str)
            
            logger.info(f"✅ [SOURCE_NAME] data saved successfully")
            logger.info(f"📁 File: {output_file}")
            logger.info(f"📊 Records: {self.stats['total_records']:,}")
            logger.info(f"🛡️ Vulnerabilities: {self.stats['total_vulnerabilities']:,}")
            logger.info(f"💾 Size: {file_size_mb:.2f} MB")
            
            return str(output_file)
            
        except Exception as e:
            logger.error(f"❌ Failed to download [SOURCE_NAME] data: {e}")
            raise
    
    async def _download_raw_data(self) -> Dict[str, Any]:
        """
        Download raw data from [SOURCE_NAME] API
        
        TEMPLATE: Customize this method based on your source's API:
        - REST API: Use aiohttp.get()
        - GraphQL: Use aiohttp.post() with query
        - Paginated: Loop through pages
        - File download: Download and parse file
        """
        logger.info(f"📡 Downloading from {self.api_endpoint}")
        
        # EXAMPLE 1: Simple REST API
        async with self.session.get(self.api_endpoint) as response:
            if response.status == 200:
                data = await response.json()
                logger.info(f"✓ Downloaded {len(data)} records")
                return data
            else:
                raise Exception(f"API returned status {response.status}: {await response.text()}")
        
        # EXAMPLE 2: Paginated API (uncomment and adapt)
        # all_data = []
        # page = 1
        # page_size = 1000
        # 
        # while True:
        #     url = f"{self.api_endpoint}?page={page}&limit={page_size}"
        #     async with self.session.get(url) as response:
        #         if response.status != 200:
        #             break
        #         
        #         page_data = await response.json()
        #         if not page_data or len(page_data) == 0:
        #             break
        #         
        #         all_data.extend(page_data)
        #         logger.info(f"📄 Downloaded page {page}: {len(page_data)} records")
        #         page += 1
        #         
        #         # Rate limiting
        #         await asyncio.sleep(1)
        # 
        # logger.info(f"✓ Downloaded {len(all_data)} total records from {page-1} pages")
        # return all_data
        
        # EXAMPLE 3: XML/RSS Feed (uncomment and adapt)
        # import xml.etree.ElementTree as ET
        # 
        # async with self.session.get(self.api_endpoint) as response:
        #     if response.status == 200:
        #         xml_content = await response.text()
        #         root = ET.fromstring(xml_content)
        #         
        #         data = []
        #         for item in root.findall('.//item'):  # Adjust XPath for your XML
        #             record = {
        #                 'id': item.findtext('id'),
        #                 'title': item.findtext('title'),
        #                 'description': item.findtext('description'),
        #                 # Add more fields as needed
        #             }
        #             data.append(record)
        #         
        #         return data
        #     else:
        #         raise Exception(f"Failed to download XML: {response.status}")
    
    def _count_vulnerabilities(self, data: Any) -> int:
        """
        Count total vulnerabilities in the dataset
        
        TEMPLATE: Customize based on your data structure
        """
        if isinstance(data, list):
            return len(data)
        elif isinstance(data, dict):
            # UPDATE: Adapt for your data structure
            # Example for nested structure like Debian
            total = 0
            for package_data in data.values():
                if isinstance(package_data, dict):
                    for key in package_data.keys():
                        if key.startswith('CVE-'):  # or your vulnerability ID pattern
                            total += 1
            return total
        return 0
    
    def _analyze_data_structure(self, data: Any) -> Dict[str, Any]:
        """
        Analyze the structure of downloaded data
        
        TEMPLATE: This provides insights into the data format
        """
        analysis = {
            'data_type': type(data).__name__,
            'total_size': len(data) if hasattr(data, '__len__') else 0,
            'sample_keys': [],
            'nested_structure': False,
            'common_fields': {},
            'data_patterns': []
        }
        
        if isinstance(data, dict):
            analysis['sample_keys'] = list(data.keys())[:10]  # First 10 keys
            
            # Analyze nested structure
            for key, value in list(data.items())[:5]:  # Sample first 5 items
                if isinstance(value, dict):
                    analysis['nested_structure'] = True
                    analysis['common_fields'][key] = list(value.keys())[:5]
        
        elif isinstance(data, list) and data:
            # Analyze list structure
            sample_item = data[0]
            if isinstance(sample_item, dict):
                analysis['sample_keys'] = list(sample_item.keys())
                analysis['common_fields'] = {
                    'item_structure': list(sample_item.keys())
                }
        
        return analysis
    
    def _generate_field_mappings(self, data: Any) -> Dict[str, str]:
        """
        Generate suggested field mappings for parser
        
        TEMPLATE: Map source fields to standard vulnerability schema
        """
        mappings = {}
        
        # UPDATE: Add your source-specific field mappings
        common_mappings = {
            # Source field name -> Standard field name
            'cve_id': 'cve_id',
            'cve': 'cve_id',
            'vulnerability_id': 'cve_id',
            'id': 'identifier',
            'title': 'title',
            'summary': 'description',
            'description': 'description',
            'details': 'description',
            'severity': 'severity',
            'severity_level': 'severity',
            'priority': 'severity',
            'published': 'published_date',
            'published_date': 'published_date',
            'created': 'published_date',
            'modified': 'last_modified_date',
            'updated': 'last_modified_date',
            'packages': 'affected_packages',
            'affected_packages': 'affected_packages',
            'references': 'references',
            'links': 'references',
            'urls': 'references'
        }
        
        # Try to detect fields in the data
        detected_fields = set()
        
        if isinstance(data, dict):
            # For nested dict structure
            for value in list(data.values())[:5]:
                if isinstance(value, dict):
                    detected_fields.update(value.keys())
        elif isinstance(data, list) and data:
            # For list structure
            if isinstance(data[0], dict):
                detected_fields.update(data[0].keys())
        
        # Create mappings for detected fields
        for field in detected_fields:
            field_lower = field.lower()
            if field_lower in common_mappings:
                mappings[field] = common_mappings[field_lower]
        
        return mappings
    
    async def test_connectivity(self) -> Dict[str, Any]:
        """Test API connectivity and basic functionality"""
        logger.info(f"🔍 Testing [SOURCE_NAME] API connectivity")
        
        try:
            start_time = datetime.utcnow()
            
            # Simple connectivity test
            async with self.session.get(self.api_endpoint) as response:
                response_time = (datetime.utcnow() - start_time).total_seconds()
                
                test_results = {
                    'status': 'success' if response.status == 200 else 'failed',
                    'status_code': response.status,
                    'response_time_seconds': response_time,
                    'content_type': response.headers.get('content-type', 'unknown'),
                    'content_length': response.headers.get('content-length', 0),
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                if response.status == 200:
                    logger.info(f"✅ API connectivity test passed ({response_time:.2f}s)")
                else:
                    logger.warning(f"⚠️ API returned status {response.status}")
                
                return test_results
                
        except Exception as e:
            logger.error(f"❌ API connectivity test failed: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def display_statistics(self):
        """Display download statistics"""
        logger.info("=" * 60)
        logger.info(f"📊 [SOURCE_NAME] Download Statistics")
        logger.info("=" * 60)
        logger.info(f"📋 Total Records: {self.stats['total_records']:,}")
        logger.info(f"🛡️ Vulnerabilities: {self.stats['total_vulnerabilities']:,}")
        logger.info(f"💾 Data Size: {self.stats['data_size_mb']:.2f} MB")
        logger.info(f"🔗 API Endpoint: {self.api_endpoint}")
        logger.info("=" * 60)

async def main():
    """Main execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Download [SOURCE_NAME] vulnerability data')
    parser.add_argument('--download-only', action='store_true', 
                       help='Only download data, skip analysis')
    parser.add_argument('--test-connectivity', action='store_true',
                       help='Test API connectivity only')
    parser.add_argument('--output-dir', 
                       help='Output directory for downloaded data')
    
    args = parser.parse_args()
    
    async with [SOURCE_NAME]DataDownloader() as downloader:
        try:
            if args.test_connectivity:
                results = await downloader.test_connectivity()
                print(f"Connectivity test: {results['status']}")
                return
            
            # Download and save data
            output_file = await downloader.download_and_save_data(args.output_dir)
            
            # Display statistics
            downloader.display_statistics()
            
            print(f"✅ [SOURCE_NAME] data download completed successfully!")
            print(f"📁 Output file: {output_file}")
            
        except Exception as e:
            print(f"❌ Download failed: {e}")
            sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())