#!/usr/bin/env python3
"""
Microsoft Security Response Center (MSRC) API Parser
Fetches and processes Microsoft security bulletins and advisories
"""

import json
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging
from dataclasses import dataclass

@dataclass
class MSRCAdvisory:
    """Microsoft Security Advisory data structure"""
    id: str
    title: str
    description: str
    severity: str
    published_date: datetime
    updated_date: datetime
    cve_numbers: List[str]
    affected_products: List[str]
    url: str
    tags: List[str]

class MSRCParser:
    """Parser for Microsoft Security Response Center advisories"""
    
    def __init__(self, config_path: str = None):
        self.base_url = "https://api.msrc.microsoft.com/cvrf/v2.0"
        self.api_version = "2.0"
        self.session = requests.Session()
        self.logger = logging.getLogger(__name__)
        
        if config_path:
            with open(config_path, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = self._default_config()
    
    def _default_config(self) -> Dict:
        """Default configuration for MSRC parser"""
        return {
            "rate_limit": 50,
            "timeout": 30,
            "max_retries": 3,
            "severity_levels": ["Critical", "Important", "Moderate", "Low"]
        }
    
    def fetch_security_updates(self, year: int = None, month: int = None) -> List[MSRCAdvisory]:
        """
        Fetch security updates from MSRC API
        
        Args:
            year: Target year (default: current year)
            month: Target month (default: current month)
        
        Returns:
            List of MSRCAdvisory objects
        """
        if not year:
            year = datetime.now().year
        if not month:
            month = datetime.now().month
        
        updates = []
        try:
            # Get available security updates for the specified period
            url = f"{self.base_url}/updates"
            response = self.session.get(url, timeout=self.config["timeout"])
            response.raise_for_status()
            
            update_ids = response.json().get("value", [])
            
            for update_id in update_ids:
                if self._is_target_period(update_id, year, month):
                    advisory = self._fetch_advisory_details(update_id)
                    if advisory:
                        updates.append(advisory)
            
        except requests.RequestException as e:
            self.logger.error(f"Failed to fetch MSRC updates: {e}")
        
        return updates
    
    def _is_target_period(self, update_id: str, year: int, month: int) -> bool:
        """Check if update ID matches target period"""
        # MSRC update IDs typically format: YYYY-MMM (e.g., 2024-Jan)
        try:
            if len(update_id.split('-')) >= 2:
                update_year = int(update_id.split('-')[0])
                update_month_str = update_id.split('-')[1]
                
                month_mapping = {
                    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
                    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
                }
                
                update_month = month_mapping.get(update_month_str, 0)
                return update_year == year and update_month == month
        except (ValueError, IndexError):
            return False
        
        return False
    
    def _fetch_advisory_details(self, update_id: str) -> Optional[MSRCAdvisory]:
        """Fetch detailed information for a specific advisory"""
        try:
            url = f"{self.base_url}/cvrf/{update_id}"
            response = self.session.get(url, timeout=self.config["timeout"])
            response.raise_for_status()
            
            data = response.json()
            return self._parse_advisory_data(data, update_id)
            
        except requests.RequestException as e:
            self.logger.error(f"Failed to fetch advisory {update_id}: {e}")
            return None
    
    def _parse_advisory_data(self, data: Dict, update_id: str) -> MSRCAdvisory:
        """Parse advisory data into MSRCAdvisory object"""
        document_title = data.get("DocumentTitle", {}).get("Value", "")
        document_notes = data.get("DocumentNotes", [])
        
        description = ""
        for note in document_notes:
            if note.get("Type") == "Description":
                description = note.get("Value", "")
                break
        
        # Extract CVE numbers
        cve_numbers = []
        vulnerabilities = data.get("Vulnerability", [])
        for vuln in vulnerabilities:
            cve = vuln.get("CVE", "")
            if cve and cve not in cve_numbers:
                cve_numbers.append(cve)
        
        # Extract affected products
        affected_products = []
        product_tree = data.get("ProductTree", {})
        branches = product_tree.get("Branch", [])
        for branch in branches:
            if branch.get("Type") == "Product Family":
                affected_products.append(branch.get("Name", ""))
        
        # Determine severity
        severity = self._determine_severity(vulnerabilities)
        
        # Extract dates
        published_date = self._parse_date(data.get("DocumentTracking", {}).get("InitialReleaseDate"))
        updated_date = self._parse_date(data.get("DocumentTracking", {}).get("CurrentReleaseDate"))
        
        # Generate URL
        url = f"https://msrc.microsoft.com/update-guide/vulnerability/{update_id}"
        
        return MSRCAdvisory(
            id=update_id,
            title=document_title,
            description=description,
            severity=severity,
            published_date=published_date,
            updated_date=updated_date,
            cve_numbers=cve_numbers,
            affected_products=affected_products,
            url=url,
            tags=["microsoft", "security-update", severity.lower()]
        )
    
    def _determine_severity(self, vulnerabilities: List[Dict]) -> str:
        """Determine overall severity from vulnerability list"""
        severity_scores = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1}
        max_severity = "Low"
        max_score = 0
        
        for vuln in vulnerabilities:
            threats = vuln.get("Threats", [])
            for threat in threats:
                if threat.get("Type") == "Impact":
                    severity = threat.get("Description", {}).get("Value", "")
                    score = severity_scores.get(severity, 0)
                    if score > max_score:
                        max_score = score
                        max_severity = severity
        
        return max_severity
    
    def _parse_date(self, date_str: str) -> datetime:
        """Parse date string to datetime object"""
        if not date_str:
            return datetime.now()
        
        try:
            # MSRC dates are typically in ISO format
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return datetime.now()
    
    def fetch_cve_details(self, cve_id: str) -> Optional[Dict]:
        """Fetch detailed information for a specific CVE"""
        try:
            # Search for CVE across all updates
            url = f"{self.base_url}/updates"
            response = self.session.get(url, timeout=self.config["timeout"])
            response.raise_for_status()
            
            update_ids = response.json().get("value", [])
            
            for update_id in update_ids:
                advisory_data = self._fetch_advisory_details(update_id)
                if advisory_data and cve_id in advisory_data.cve_numbers:
                    return {
                        "cve_id": cve_id,
                        "advisory": advisory_data,
                        "source": "Microsoft MSRC"
                    }
            
            return None
            
        except requests.RequestException as e:
            self.logger.error(f"Failed to fetch CVE details for {cve_id}: {e}")
            return None
    
    def get_recent_advisories(self, days: int = 30) -> List[MSRCAdvisory]:
        """Get advisories from the last N days"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        advisories = []
        current_date = start_date
        
        while current_date <= end_date:
            monthly_advisories = self.fetch_security_updates(
                current_date.year, 
                current_date.month
            )
            
            for advisory in monthly_advisories:
                if advisory.published_date >= start_date:
                    advisories.append(advisory)
            
            # Move to next month
            if current_date.month == 12:
                current_date = current_date.replace(year=current_date.year + 1, month=1)
            else:
                current_date = current_date.replace(month=current_date.month + 1)
        
        return sorted(advisories, key=lambda x: x.published_date, reverse=True)

if __name__ == "__main__":
    # Example usage
    parser = MSRCParser()
    
    # Get recent advisories
    recent_advisories = parser.get_recent_advisories(days=7)
    print(f"Found {len(recent_advisories)} recent advisories")
    
    for advisory in recent_advisories[:5]:  # Show first 5
        print(f"- {advisory.title} ({advisory.severity})")
        print(f"  CVEs: {', '.join(advisory.cve_numbers)}")
        print(f"  Published: {advisory.published_date.strftime('%Y-%m-%d')}")
        print()