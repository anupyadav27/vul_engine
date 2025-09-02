"""
Custom Exceptions for Multi-Source Vulnerability System

Purpose: Standardized error handling across all vulnerability sources
Usage: All fetchers and parsers should use these exceptions for consistent error reporting
Related Files: Used by all source implementations in sources/*

Exception Hierarchy:
- VulnSourceException (base)
  ├── FetchException (data retrieval errors)
  ├── ParseException (data parsing errors)
  ├── ConfigException (configuration errors)
  └── ValidationException (data validation errors)
"""

class VulnSourceException(Exception):
    """Base exception for all vulnerability source operations"""
    
    def __init__(self, message: str, source_name: str = None, details: dict = None):
        self.source_name = source_name
        self.details = details or {}
        super().__init__(message)
    
    def __str__(self):
        if self.source_name:
            return f"[{self.source_name}] {super().__str__()}"
        return super().__str__()

class FetchException(VulnSourceException):
    """Raised when data fetching fails"""
    
    def __init__(self, message: str, source_name: str = None, 
                 status_code: int = None, url: str = None, **kwargs):
        self.status_code = status_code
        self.url = url
        details = {'status_code': status_code, 'url': url, **kwargs}
        super().__init__(message, source_name, details)

class ParseException(VulnSourceException):
    """Raised when data parsing fails"""
    
    def __init__(self, message: str, source_name: str = None, 
                 raw_data_sample: str = None, **kwargs):
        self.raw_data_sample = raw_data_sample
        details = {'raw_data_sample': raw_data_sample, **kwargs}
        super().__init__(message, source_name, details)

class ConfigException(VulnSourceException):
    """Raised when configuration is invalid"""
    
    def __init__(self, message: str, source_name: str = None, 
                 config_key: str = None, **kwargs):
        self.config_key = config_key
        details = {'config_key': config_key, **kwargs}
        super().__init__(message, source_name, details)

class ValidationException(VulnSourceException):
    """Raised when data validation fails"""
    
    def __init__(self, message: str, source_name: str = None, 
                 validation_field: str = None, **kwargs):
        self.validation_field = validation_field
        details = {'validation_field': validation_field, **kwargs}
        super().__init__(message, source_name, details)