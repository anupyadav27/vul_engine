"""
Configuration settings for Vulnerability Engine
"""

import os
from typing import List
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    """Application settings"""
    
    # Server configuration
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False
    
    # Database configuration
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    DB_NAME: str = "vulnerability_db"
    DB_USER: str = "vuln_user"
    DB_PASSWORD: str = "vuln_pass"
    DB_POOL_SIZE: int = 10
    
    # Security
    API_KEYS: List[str] = ["your-secret-api-key"]
    SECRET_KEY: str = "your-secret-key-change-in-production"
    
    # CORS
    ALLOWED_ORIGINS: List[str] = ["*"]
    
    # Scanning
    MAX_CONCURRENT_SCANS: int = 5
    SCAN_TIMEOUT: int = 300  # 5 minutes
    
    # Vulnerability matching
    CVE_CACHE_TTL: int = 3600  # 1 hour
    SEVERITY_THRESHOLD: str = "MEDIUM"  # Minimum severity to report
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()