import logging
import requests
import gzip
import time
import json
from pathlib import Path
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class NVDFetcher:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.data_dir.mkdir(exist_ok=True)
        
        # NVD API endpoints - Using only API 2.0 now
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.mitre_attack_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    def download_nvd_feeds(self, years=None):
        """Download NVD data using API 2.0 for specified years"""
        if years is None:
            current_year = datetime.now().year
            years = list(range(2020, current_year + 1))
        
        logger.info(f"🚀 Downloading NVD data using API 2.0 for years: {years}")
        
        downloaded_files = []
        for year in years:
            try:
                # Use API 2.0 to get data for each year
                start_date = f"{year}-01-01T00:00:00.000"
                end_date = f"{year}-12-31T23:59:59.999"
                
                logger.info(f"📥 Downloading CVEs for year {year} using NVD API 2.0")
                
                all_cves = []
                start_index = 0
                results_per_page = 2000
                
                while True:
                    params = {
                        'pubStartDate': start_date,
                        'pubEndDate': end_date,
                        'startIndex': start_index,
                        'resultsPerPage': results_per_page
                    }
                    
                    response = requests.get(self.nvd_api_base, params=params, timeout=120)
                    response.raise_for_status()
                    
                    data = response.json()
                    vulnerabilities = data.get('vulnerabilities', [])
                    
                    if not vulnerabilities:
                        break
                        
                    all_cves.extend(vulnerabilities)
                    
                    # Check if we have more data
                    total_results = data.get('totalResults', 0)
                    if start_index + results_per_page >= total_results:
                        break
                        
                    start_index += results_per_page
                    
                    # Rate limiting - NVD API has rate limits
                    time.sleep(6)  # 6 seconds between requests to respect rate limits
                    
                    logger.info(f"   Downloaded {len(all_cves)} CVEs for {year} so far...")
                
                # Save the data to a JSON file
                json_file = self.data_dir / f"nvdcve-2.0-{year}.json"
                with open(json_file, 'w', encoding='utf-8') as f:
                    json.dump({
                        'resultsPerPage': len(all_cves),
                        'startIndex': 0,
                        'totalResults': len(all_cves),
                        'format': 'NVD_CVE',
                        'version': '2.0',
                        'timestamp': datetime.now().isoformat(),
                        'vulnerabilities': all_cves
                    }, f, indent=2)
                
                logger.info(f"✅ Downloaded {len(all_cves)} CVEs for year {year} to {json_file}")
                downloaded_files.append(json_file)
                
                # Rate limiting between years
                time.sleep(6)
                
            except Exception as e:
                logger.error(f"❌ Failed to download {year}: {e}")
                
        return downloaded_files

    def download_recent_cves(self, days_back=30):
        """Download recent CVEs using NVD API 2.0"""
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days_back)
            
            logger.info(f"📥 Downloading recent CVEs from {start_date.date()} to {end_date.date()}")
            
            all_cves = []
            start_index = 0
            results_per_page = 2000
            
            while True:
                params = {
                    'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                    'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                    'startIndex': start_index,
                    'resultsPerPage': results_per_page
                }
                
                response = requests.get(self.nvd_api_base, params=params, timeout=60)
                response.raise_for_status()
                
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                if not vulnerabilities:
                    break
                    
                all_cves.extend(vulnerabilities)
                
                # Check if we have more data
                total_results = data.get('totalResults', 0)
                if start_index + results_per_page >= total_results:
                    break
                    
                start_index += results_per_page
                
                # Rate limiting
                time.sleep(6)
            
            if all_cves:
                recent_file = self.data_dir / "recent_cves.json"
                with open(recent_file, 'w') as f:
                    json.dump({
                        'resultsPerPage': len(all_cves),
                        'startIndex': 0,
                        'totalResults': len(all_cves),
                        'format': 'NVD_CVE',
                        'version': '2.0',
                        'timestamp': datetime.now().isoformat(),
                        'vulnerabilities': all_cves
                    }, f, indent=2)
                
                logger.info(f"✅ Downloaded {len(all_cves)} recent CVEs")
                return recent_file
            else:
                logger.info("✅ No recent CVEs found in the specified time range")
                return None
            
        except Exception as e:
            logger.error(f"❌ Failed to download recent CVEs: {e}")
            return None

    def download_mitre_attack(self):
        """Download MITRE ATT&CK framework data"""
        try:
            logger.info("📥 Downloading MITRE ATT&CK data...")
            
            response = requests.get(self.mitre_attack_url, timeout=60)
            response.raise_for_status()
            
            mitre_file = self.data_dir / "mitre_attack.json"
            with open(mitre_file, 'w') as f:
                json.dump(response.json(), f, indent=2)
            
            logger.info("✅ Downloaded MITRE ATT&CK data")
            return mitre_file
            
        except Exception as e:
            logger.error(f"❌ Failed to download MITRE ATT&CK data: {e}")
            return None
