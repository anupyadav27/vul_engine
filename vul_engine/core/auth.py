"""
Authentication and authorization for Vulnerability Engine
"""

from fastapi import HTTPException, status
from typing import Optional
import logging

from .config import settings

logger = logging.getLogger(__name__)

def verify_api_key(api_key: str) -> dict:
    """
    Verify API key authentication
    
    Args:
        api_key: The API key to verify
        
    Returns:
        dict: User information if valid
        
    Raises:
        HTTPException: If API key is invalid
    """
    if not api_key:
        logger.warning("Missing API key in request")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required"
        )
    
    if api_key not in settings.API_KEYS:
        logger.warning(f"Invalid API key attempted: {api_key[:8]}...")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    logger.debug(f"Valid API key authenticated: {api_key[:8]}...")
    
    # Return user context (can be expanded for more complex auth)
    return {
        "api_key": api_key[:8] + "...",
        "authenticated": True,
        "permissions": ["scan", "read", "write"]  # Can be customized per key
    }

def get_api_key_permissions(api_key: str) -> list:
    """
    Get permissions for a given API key
    
    Args:
        api_key: The API key
        
    Returns:
        list: List of permissions
    """
    # For now, all valid keys have the same permissions
    # This can be expanded to have different permission levels
    if api_key in settings.API_KEYS:
        return ["scan", "read", "write", "admin"]
    return []

def check_permission(user: dict, required_permission: str) -> bool:
    """
    Check if user has required permission
    
    Args:
        user: User context from verify_api_key
        required_permission: Permission to check
        
    Returns:
        bool: True if user has permission
    """
    user_permissions = user.get("permissions", [])
    return required_permission in user_permissions or "admin" in user_permissions