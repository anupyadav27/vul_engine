"""
Base Fetcher for Multi-Source Vulnerability System

Abstract base class that all vulnerability sources inherit from.
Provides common fetching functionality and enforces consistent interface.
"""

import abc
import logging
import requests
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import json

from .exceptions import FetchException


class BaseFetcher(abc.ABC):
    """Abstract base class for all vulnerability source fetchers"""
    
    def __init__(self, source_name: str, config: Dict[str, Any]):
        """
        Initialize fetcher with source configuration
        
        Args:
            source_name: Name of the vulnerability source
            config: Configuration dict from interest_datasource_final.json
        """
        self.source_name = source_name
        self.config = config
        self.logger = logging.getLogger(f"fetcher.{source_name}")
        
        # Common configuration
        self.base_url = config.get('base_url', '')
        self.api_key = config.get('api_key')
        self.rate_limit = config.get('rate_limit', 1.0)  # seconds between requests
        self.timeout = config.get('timeout', 30)
        self.max_retries = config.get('max_retries', 3)
        
        # Session for connection pooling
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update(self._get_auth_headers())
    
    @abc.abstractmethod
    def fetch_vulnerabilities(self, last_update: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Fetch vulnerabilities from the source
        
        Args:
            last_update: Only fetch vulnerabilities updated after this date
            
        Returns:
            List of raw vulnerability data dictionaries
        """
        pass
    
    @abc.abstractmethod
    def _get_auth_headers(self) -> Dict[str, str]:
        """Return authentication headers for API requests"""
        pass
    
    def _make_request(self, url: str, params: Dict[str, Any] = None) -> requests.Response:
        """
        Make HTTP request with retry logic and rate limiting
        
        Args:
            url: URL to request
            params: Query parameters
            
        Returns:
            Response object
            
        Raises:
            FetchException: If request fails after retries
        """
        for attempt in range(self.max_retries):
            try:
                # Rate limiting
                time.sleep(self.rate_limit)
                
                response = self.session.get(
                    url, 
                    params=params, 
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    return response
                elif response.status_code == 429:  # Rate limited
                    wait_time = 2 ** attempt
                    self.logger.warning(f"Rate limited, waiting {wait_time}s")
                    time.sleep(wait_time)
                    continue
                else:
                    response.raise_for_status()
                    
            except requests.RequestException as e:
                if attempt == self.max_retries - 1:
                    raise FetchException(f"Request failed after {self.max_retries} attempts: {e}")
                self.logger.warning(f"Request attempt {attempt + 1} failed: {e}")
                time.sleep(2 ** attempt)
        
        raise FetchException(f"Request failed after {self.max_retries} attempts")
    
    def _paginate_requests(self, base_url: str, params: Dict[str, Any], 
                          page_param: str = 'page', page_size: int = 100) -> List[Dict[str, Any]]:
        """
        Handle paginated API requests
        
        Args:
            base_url: Base URL for requests
            params: Base parameters
            page_param: Name of page parameter
            page_size: Items per page
            
        Returns:
            Combined results from all pages
        """
        all_results = []
        page = 1
        
        while True:
            page_params = params.copy()
            page_params[page_param] = page
            page_params['per_page'] = page_size
            
            response = self._make_request(base_url, page_params)
            data = response.json()
            
            # Handle different pagination formats
            if isinstance(data, list):
                results = data
            elif 'data' in data:
                results = data['data']
            elif 'results' in data:
                results = data['results']
            else:
                results = data
            
            if not results:
                break
                
            all_results.extend(results)
            
            # Check if there are more pages
            if len(results) < page_size:
                break
                
            page += 1
            
        return all_results
    
    def get_incremental_updates(self, last_update: datetime) -> List[Dict[str, Any]]:
        """
        Get only vulnerabilities updated since last_update
        
        Args:
            last_update: Timestamp of last successful update
            
        Returns:
            List of updated vulnerabilities
        """
        self.logger.info(f"Fetching incremental updates since {last_update}")
        return self.fetch_vulnerabilities(last_update)
    
    def get_full_sync(self) -> List[Dict[str, Any]]:
        """
        Get all vulnerabilities for full synchronization
        
        Returns:
            List of all vulnerabilities
        """
        self.logger.info("Performing full synchronization")
        return self.fetch_vulnerabilities()
    
    def validate_config(self) -> bool:
        """
        Validate that required configuration is present
        
        Returns:
            True if configuration is valid
            
        Raises:
            FetchException: If configuration is invalid
        """
        required_fields = self.get_required_config_fields()
        
        for field in required_fields:
            if field not in self.config:
                raise FetchException(f"Missing required configuration field: {field}")
        
        return True
    
    @abc.abstractmethod
    def get_required_config_fields(self) -> List[str]:
        """Return list of required configuration fields for this source"""
        pass
    
    def cleanup(self):
        """Clean up resources (close sessions, etc.)"""
        if hasattr(self, 'session'):
            self.session.close()