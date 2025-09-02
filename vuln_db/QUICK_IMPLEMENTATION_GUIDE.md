# Quick Implementation Guide: Standardized Source Processing

## 🚀 Fast Track Implementation

This guide provides step-by-step instructions to implement the standardized processing pipeline for any vulnerability source in under 2 hours.

## Prerequisites

- Source added to `/vuln_db/interest_datasource_final.json`
- Database schema already supports the source
- Basic understanding of the source's API/data format

## Step-by-Step Implementation

### 1. Create Source Structure (5 minutes)

```bash
# Set your source details
export CATEGORY="cve_compatible_os"  # or your category
export SOURCE_NAME="new_source"      # your source name

# Create directory structure
cd /path/to/vuln_db
mkdir -p sources/${CATEGORY}/${SOURCE_NAME}/output/{data_downloads,parsing_reports,upload_reports,integrity_reports}

# Copy template files from Debian implementation
cp sources/cve_compatible_os/debian/input_datastructure.py sources/${CATEGORY}/${SOURCE_NAME}/
cp sources/cve_compatible_os/debian/parser.py sources/${CATEGORY}/${SOURCE_NAME}/
cp sources/cve_compatible_os/debian/upload_json_to_db.py sources/${CATEGORY}/${SOURCE_NAME}/
cp sources/cve_compatible_os/debian/comprehensive_integrity_analyzer.py sources/${CATEGORY}/${SOURCE_NAME}/
```

### 2. Configure Source Settings (10 minutes)

Update each file's source-specific constants:

#### `input_datastructure.py`
```python
# Update these at the top of the file
SOURCE_NAME = "your_source_name"
API_ENDPOINT = "https://your-source.com/api"
DATA_FORMAT = "json"  # or "xml", "csv", etc.

# Update the config import
def get_source_config():
    return {
        'name': SOURCE_NAME,
        'url': API_ENDPOINT,
        'category': 'your_category',
        'priority': 8,  # Adjust based on source importance
        'status': 'working',
        'timeout_seconds': 30,
        'retry_attempts': 3
    }
```

#### `parser.py`
```python
# Update source name and schema mappings
class YourSourceParser(BaseParser):
    def __init__(self, config: Dict[str, Any]):
        super().__init__("your_source_name", config)
        
        # Update field mappings for your source
        self.field_mappings = {
            'vulnerability_id': 'cve_id',      # Map source field to standard field
            'summary': 'description',
            'severity_level': 'severity',
            # Add more mappings as needed
        }
```

#### `upload_json_to_db.py`
```python
# Update source identifier
SOURCE_NAME = "your_source_name"

# Update file pattern matching
json_files = list(data_dir.glob(f"{SOURCE_NAME}_data_*.json"))
```

### 3. Implement Source-Specific Logic (30-60 minutes)

This is where you customize for your source's data format:

#### A. Data Download Logic

In `input_datastructure.py`, update the download method:

```python
async def download_and_save_data(self):
    """Customize this method for your source"""
    
    # Example for REST API
    async with self.session.get(self.api_endpoint) as response:
        if response.status == 200:
            data = await response.json()  # or .text() for non-JSON
        else:
            raise Exception(f"API returned {response.status}")
    
    # Example for paginated API
    all_data = []
    page = 1
    while True:
        url = f"{self.api_endpoint}?page={page}"
        async with self.session.get(url) as response:
            page_data = await response.json()
            if not page_data or len(page_data) == 0:
                break
            all_data.extend(page_data)
            page += 1
    
    # Continue with standard metadata addition...
```

#### B. Data Parsing Logic

In `parser.py`, update parsing methods:

```python
def parse_raw_data(self, raw_data: List[Dict]) -> List[Dict]:
    """Customize parsing for your source format"""
    parsed_vulnerabilities = []
    
    for record in raw_data:
        try:
            # Map source fields to standard schema
            vulnerability = {
                'cve_id': self._extract_cve_id(record),
                'description': record.get('summary', ''),
                'severity': self._map_severity(record.get('severity_level')),
                'published_date': self._parse_date(record.get('published')),
                'affected_packages': self._extract_packages(record),
                'references': self._extract_references(record),
                'source': self.source_name,
                'source_specific': record  # Keep original data
            }
            
            parsed_vulnerabilities.append(vulnerability)
            
        except Exception as e:
            self.logger.warning(f"Failed to parse record: {e}")
            continue
    
    return parsed_vulnerabilities

def _extract_cve_id(self, record: Dict) -> str:
    """Extract CVE ID from source format"""
    # Customize based on your source's ID format
    cve_id = record.get('cve_id') or record.get('vulnerability_id')
    
    # Ensure CVE format
    if cve_id and not cve_id.startswith('CVE-'):
        # Some sources use different ID formats
        return f"CVE-{cve_id}"  # Adapt as needed
    
    return cve_id

def _map_severity(self, source_severity: str) -> str:
    """Map source severity to standard levels"""
    severity_mapping = {
        'critical': 'CRITICAL',
        'high': 'HIGH',
        'medium': 'MEDIUM',
        'low': 'LOW',
        # Add your source's severity levels
        'urgent': 'CRITICAL',
        'important': 'HIGH',
        'moderate': 'MEDIUM',
        'minor': 'LOW'
    }
    
    return severity_mapping.get(source_severity.lower(), 'UNKNOWN')
```

### 4. Test the Implementation (15 minutes)

Run each step to verify functionality:

```bash
cd sources/${CATEGORY}/${SOURCE_NAME}

# Test data download
python input_datastructure.py --download-only
# Should create file in output/data_downloads/

# Test parsing
python upload_json_to_db.py
# Should create parsing and upload reports

# Test integrity analysis
python comprehensive_integrity_analyzer.py
# Should show 100% integrity score
```

### 5. Common Source Patterns

#### REST API with JSON
```python
# In download method
async with self.session.get(url, headers=headers) as response:
    data = await response.json()
```

#### XML/RSS Feed
```python
import xml.etree.ElementTree as ET

# In download method
async with self.session.get(url) as response:
    xml_content = await response.text()
    root = ET.fromstring(xml_content)
    
    data = []
    for item in root.findall('.//item'):  # Adjust XPath
        record = {
            'title': item.findtext('title'),
            'description': item.findtext('description'),
            # Extract other fields
        }
        data.append(record)
```

#### CSV/Spreadsheet
```python
import csv
import io

# In download method
async with self.session.get(url) as response:
    csv_content = await response.text()
    
    data = []
    reader = csv.DictReader(io.StringIO(csv_content))
    for row in reader:
        data.append(dict(row))
```

#### GitHub Security Advisories
```python
# In download method
headers = {'Authorization': f'token {github_token}'}
url = 'https://api.github.com/advisories'

async with self.session.get(url, headers=headers) as response:
    data = await response.json()
```

### 6. Source-Specific Considerations

#### Security Advisory Sources
- Map advisory IDs to CVE IDs
- Handle multiple CVEs per advisory
- Extract vendor-specific package information

#### Package Manager Sources
- Map package names to ecosystems
- Handle version ranges and constraints
- Extract fix information

#### Vendor Sources
- Map product names to standard identifiers
- Handle vendor-specific severity scales
- Extract patch/fix information

### 7. Validation Checklist

Before marking implementation complete:

```bash
# Run complete pipeline
python input_datastructure.py --download-only
python upload_json_to_db.py
python comprehensive_integrity_analyzer.py

# Verify outputs
ls -la output/*/
# Should see files in all 4 output directories

# Check integrity score
grep "Integrity Score" output/integrity_reports/comprehensive_*.json
# Should show 100/100
```

## Common Issues and Solutions

### Issue: Import Errors
```python
# Add to top of each file
import sys
from pathlib import Path
current_dir = Path(__file__).resolve().parent
vuln_db_root = current_dir.parent.parent.parent
sys.path.insert(0, str(vuln_db_root))
```

### Issue: Data Format Mismatches
- Check source documentation for exact field names
- Use browser dev tools to inspect actual API responses
- Add debug logging to see raw data structure

### Issue: Rate Limiting
```python
# Add delays between requests
import asyncio

await asyncio.sleep(1)  # 1 second delay
```

### Issue: Authentication Required
```python
# Add API key/token
headers = {
    'Authorization': f'Bearer {api_token}',
    'User-Agent': 'VulnDB/1.0',
    'Accept': 'application/json'
}
```

## Performance Optimization

### For Large Datasets
```python
# Use streaming/pagination
async def download_paginated_data(self):
    all_data = []
    page = 1
    page_size = 1000
    
    while True:
        batch = await self._fetch_page(page, page_size)
        if not batch:
            break
        all_data.extend(batch)
        page += 1
        
        # Progress logging
        if page % 10 == 0:
            self.logger.info(f"Downloaded {len(all_data)} records...")
```

### For Frequent Updates
```python
# Implement incremental updates
def get_last_update_timestamp(self):
    """Get timestamp of last successful update"""
    # Check database or file system for last update
    pass

async def download_incremental_data(self, since_timestamp):
    """Download only new/updated records"""
    url = f"{self.api_endpoint}?since={since_timestamp}"
    # Continue with download logic
```

## Success Criteria

Your implementation is ready when:

1. ✅ **All 4 files run without errors**
2. ✅ **Output directories contain properly formatted reports**
3. ✅ **Integrity analyzer shows 100% accountability**
4. ✅ **Database contains expected number of new/updated records**
5. ✅ **No data loss detected in cross-validation**

## Estimated Time Investment

- **Simple REST API source**: 1-2 hours
- **Complex multi-format source**: 3-4 hours
- **Legacy/poorly documented source**: 4-6 hours

## Getting Help

If you encounter issues:

1. **Check the Debian implementation** for reference patterns
2. **Review source documentation** and API specs
3. **Use browser dev tools** to inspect actual data
4. **Add debug logging** to trace data flow
5. **Test with small datasets** first

This standardized approach has been proven with the Debian Security Tracker and provides a reliable foundation for implementing any vulnerability source efficiently.