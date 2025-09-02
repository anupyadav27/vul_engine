#!/usr/bin/env python3
"""
AWS Security Bulletins Parser
Extracts vulnerability data from AWS Security Bulletins
Priority: HIGH - Advisory Cloud Bulletins Source
"""

import requests
import json
import re
from datetime import datetime
from bs4 import BeautifulSoup
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class AwsSecurityParser:
    """Parser for AWS Security Bulletins"""
    
    def __init__(self):
        self.base_url = "https://aws.amazon.com/security/security-bulletins"
        self.rss_url = "https://aws.amazon.com/about-aws/whats-new/recent/feed/"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnDB-AWS-Parser/1.0'
        })
    
    def fetch_bulletins(self, limit: int = 50) -> List[Dict]:
        """Fetch AWS security bulletins"""
        try:
            # Try RSS feed first for recent bulletins
            bulletins = self._fetch_from_rss(limit)
            
            if not bulletins:
                # Fallback to HTML parsing
                bulletins = self._parse_html_bulletins(limit)
            
            return bulletins
            
        except Exception as e:
            logger.error(f"Error fetching AWS bulletins: {e}")
            return []
    
    def _fetch_from_rss(self, limit: int) -> List[Dict]:
        """Fetch bulletins from RSS feed"""
        try:
            response = self.session.get(self.rss_url)
            if response.status_code != 200:
                return []
            
            soup = BeautifulSoup(response.text, 'xml')
            items = soup.find_all('item')[:limit]
            
            bulletins = []
            for item in items:
                title = item.find('title')
                description = item.find('description')
                link = item.find('link')
                pub_date = item.find('pubDate')
                
                if title and 'security' in title.text.lower():
                    bulletin = {
                        'title': title.text.strip(),
                        'description': description.text.strip() if description else '',
                        'url': link.text.strip() if link else '',
                        'date': pub_date.text.strip() if pub_date else '',
                        'source': 'aws_security'
                    }
                    bulletins.append(bulletin)
            
            return bulletins
            
        except Exception as e:
            logger.error(f"Error parsing RSS feed: {e}")
            return []
    
    def _parse_html_bulletins(self, limit: int) -> List[Dict]:
        """Parse bulletins from HTML page"""
        try:
            response = self.session.get(self.base_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            bulletins = []
            # Look for bulletin containers
            bulletin_elements = soup.find_all('div', class_='lb-row')[:limit]
            
            for element in bulletin_elements:
                bulletin = self._extract_bulletin_details(element)
                if bulletin:
                    bulletins.append(bulletin)
            
            return bulletins
            
        except Exception as e:
            logger.error(f"Error parsing HTML bulletins: {e}")
            return []
    
    def _extract_bulletin_details(self, element) -> Optional[Dict]:
        """Extract details from bulletin element"""
        try:
            # Extract title
            title_elem = element.find('h3') or element.find('h2') or element.find('a')
            title = title_elem.text.strip() if title_elem else ""
            
            # Extract URL
            link_elem = element.find('a')
            url = link_elem.get('href', '') if link_elem else ''
            if url and not url.startswith('http'):
                url = f"https://aws.amazon.com{url}"
            
            # Extract description
            desc_elem = element.find('p')
            description = desc_elem.text.strip() if desc_elem else ""
            
            # Extract date
            date_elem = element.find('time') or element.find('span', class_='date')
            date_str = date_elem.text.strip() if date_elem else None
            
            if title and 'security' in title.lower():
                return {
                    'title': title,
                    'description': description,
                    'url': url,
                    'date': date_str,
                    'source': 'aws_security'
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Error extracting bulletin details: {e}")
            return None
    
    def get_bulletin_details(self, url: str) -> Optional[Dict]:
        """Get detailed information for a specific bulletin"""
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract CVE references
            cve_pattern = re.compile(r'CVE-\d{4}-\d+')
            page_text = soup.get_text()
            cves = list(set(cve_pattern.findall(page_text)))
            
            # Extract affected services
            services = []
            service_keywords = ['EC2', 'S3', 'Lambda', 'RDS', 'EKS', 'ECS', 'CloudFormation', 'IAM']
            for keyword in service_keywords:
                if keyword.lower() in page_text.lower():
                    services.append(keyword)
            
            # Extract severity if mentioned
            severity = "Unknown"
            severity_patterns = ['Critical', 'High', 'Medium', 'Low', 'Important']
            for pattern in severity_patterns:
                if pattern.lower() in page_text.lower():
                    severity = pattern
                    break
            
            return {
                'cves': cves,
                'affected_services': services,
                'severity': severity,
                'url': url
            }
            
        except Exception as e:
            logger.error(f"Error getting bulletin details for {url}: {e}")
            return None
    
    def get_service_advisories(self, service_name: str) -> List[Dict]:
        """Get security advisories for a specific AWS service"""
        try:
            # Search for service-specific security information
            search_url = f"https://aws.amazon.com/security/security-bulletins/?q={service_name}"
            response = self.session.get(search_url)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                return self._extract_service_advisories(soup, service_name)
            
            return []
            
        except Exception as e:
            logger.error(f"Error getting service advisories for {service_name}: {e}")
            return []
    
    def _extract_service_advisories(self, soup: BeautifulSoup, service_name: str) -> List[Dict]:
        """Extract service-specific advisories"""
        advisories = []
        
        # Look for relevant advisory links
        links = soup.find_all('a', href=True)
        for link in links:
            href = link.get('href', '')
            text = link.text.strip()
            
            if (service_name.lower() in text.lower() or 
                service_name.lower() in href.lower()):
                advisories.append({
                    'title': text,
                    'url': href if href.startswith('http') else f"https://aws.amazon.com{href}",
                    'service': service_name,
                    'source': 'aws_security'
                })
        
        return advisories

    def parse_to_vuln_format(self, bulletin: Dict) -> Dict:
        """Convert AWS bulletin to standard vulnerability format"""
        return {
            'vulnerability_id': f"AWS-{hash(bulletin.get('url', bulletin.get('title', '')))}",
            'source': 'aws_security',
            'source_id': bulletin.get('url', ''),
            'title': bulletin.get('title', ''),
            'description': bulletin.get('description', ''),
            'severity': bulletin.get('severity', 'Unknown'),
            'published_date': bulletin.get('date'),
            'modified_date': bulletin.get('date'),
            'cve_references': bulletin.get('cves', []),
            'affected_services': bulletin.get('affected_services', []),
            'references': [bulletin.get('url', '')],
            'source_url': bulletin.get('url', ''),
            'metadata': {
                'source_type': 'aws_security_bulletin',
                'cloud_provider': 'aws',
                'vendor': 'amazon'
            }
        }