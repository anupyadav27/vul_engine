#!/usr/bin/env python3
"""
AWS Security Bulletins Loader
Loads and processes AWS security bulletin data into the vulnerability database
Priority: HIGH - Advisory Cloud Bulletins Source
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional
from .parser import AwsSecurityParser
from ...base.loader import BaseLoader

logger = logging.getLogger(__name__)

class AwsSecurityLoader(BaseLoader):
    """Loader for AWS Security Bulletins"""
    
    def __init__(self, db_connection):
        super().__init__(db_connection)
        self.parser = AwsSecurityParser()
        self.source_name = "aws_security"
        
    async def load_latest(self, limit: int = 100) -> Dict:
        """Load latest AWS security bulletins"""
        start_time = datetime.now()
        results = {
            'source': self.source_name,
            'status': 'success',
            'bulletins_processed': 0,
            'errors': [],
            'start_time': start_time,
            'end_time': None
        }
        
        try:
            # Fetch bulletins
            logger.info(f"Fetching latest {limit} AWS security bulletins")
            bulletins = self.parser.fetch_bulletins(limit)
            
            if not bulletins:
                results['status'] = 'warning'
                results['errors'].append('No bulletins fetched')
                return results
            
            # Process each bulletin
            for bulletin in bulletins:
                try:
                    # Get detailed information
                    if bulletin.get('url'):
                        details = self.parser.get_bulletin_details(bulletin['url'])
                        if details:
                            bulletin.update(details)
                    
                    # Convert to standard format
                    vuln_data = self.parser.parse_to_vuln_format(bulletin)
                    
                    # Store in database
                    await self._store_vulnerability(vuln_data)
                    results['bulletins_processed'] += 1
                    
                except Exception as e:
                    error_msg = f"Error processing bulletin {bulletin.get('title', 'Unknown')}: {e}"
                    logger.error(error_msg)
                    results['errors'].append(error_msg)
            
            results['end_time'] = datetime.now()
            logger.info(f"Processed {results['bulletins_processed']} AWS security bulletins")
            
        except Exception as e:
            results['status'] = 'error'
            results['errors'].append(f"Critical error: {e}")
            logger.error(f"Critical error in AWS security loader: {e}")
        
        return results
    
    async def load_service_specific(self, service_name: str) -> Dict:
        """Load security advisories for a specific AWS service"""
        try:
            advisories = self.parser.get_service_advisories(service_name)
            
            results = {
                'service': service_name,
                'advisories_found': len(advisories),
                'processed': 0
            }
            
            for advisory in advisories:
                vuln_data = self.parser.parse_to_vuln_format(advisory)
                await self._store_vulnerability(vuln_data)
                results['processed'] += 1
            
            return results
            
        except Exception as e:
            logger.error(f"Error loading service-specific advisories for {service_name}: {e}")
            return {'error': str(e)}
    
    async def _store_vulnerability(self, vuln_data: Dict):
        """Store vulnerability data in database"""
        try:
            # Check if vulnerability already exists
            existing = await self._check_existing_vulnerability(
                vuln_data['source_id'], 
                vuln_data['source']
            )
            
            if existing:
                # Update existing record
                await self._update_vulnerability(vuln_data)
            else:
                # Insert new record
                await self._insert_vulnerability(vuln_data)
                
        except Exception as e:
            logger.error(f"Error storing vulnerability: {e}")
            raise
    
    def get_supported_services(self) -> List[str]:
        """Get list of AWS services that have security advisories"""
        return [
            'EC2', 'S3', 'Lambda', 'RDS', 'EKS', 'ECS', 
            'CloudFormation', 'IAM', 'VPC', 'CloudTrail',
            'CloudWatch', 'API Gateway', 'ElastiCache',
            'Redshift', 'DynamoDB', 'SQS', 'SNS'
        ]