#!/usr/bin/env python3
"""
Vulnerability Engine - Central API Server
Manages vulnerability scanning workflows and agent communication
"""

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Security, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
from datetime import datetime
from typing import Dict, List, Optional
import os

from api.routes import agents, scans, vulnerabilities, reports
from core.config import settings
from core.database import DatabaseManager
from core.scanner import VulnerabilityScanner
from core.auth import verify_api_key

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vul_engine.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Global instances
db_manager = None
vulnerability_scanner = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    global db_manager, vulnerability_scanner
    
    logger.info("Starting Vulnerability Engine...")
    
    # Initialize database connection
    db_manager = DatabaseManager()
    await db_manager.initialize()
    
    # Initialize vulnerability scanner
    vulnerability_scanner = VulnerabilityScanner(db_manager)
    
    logger.info("Vulnerability Engine started successfully")
    
    yield
    
    # Cleanup
    logger.info("Shutting down Vulnerability Engine...")
    if db_manager:
        await db_manager.close()

# Create FastAPI app
app = FastAPI(
    title="Vulnerability Engine API",
    description="Central API server for vulnerability management system",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Verify API key authentication"""
    return verify_api_key(credentials.credentials)

# Dependency injection
def get_db_manager():
    """Get database manager instance"""
    return db_manager

def get_vulnerability_scanner():
    """Get vulnerability scanner instance"""
    return vulnerability_scanner

# Update route includes with dependency injection
app.include_router(
    agents.router, 
    prefix="/api/v1/agents", 
    tags=["agents"],
    dependencies=[Depends(get_current_user)]
)
app.include_router(
    scans.router, 
    prefix="/api/v1/scans", 
    tags=["scans"],
    dependencies=[Depends(get_current_user)]
)
app.include_router(
    vulnerabilities.router, 
    prefix="/api/v1/vulnerabilities", 
    tags=["vulnerabilities"],
    dependencies=[Depends(get_current_user)]
)
app.include_router(
    reports.router, 
    prefix="/api/v1/reports", 
    tags=["reports"],
    dependencies=[Depends(get_current_user)]
)

# Root endpoint
@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "message": "Vulnerability Engine API",
        "version": "1.0.0",
        "status": "running",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health")
async def health_check():
    """Detailed health check"""
    try:
        # Check database connection
        db_status = await db_manager.check_connection() if db_manager else False
        
        return {
            "status": "healthy" if db_status else "unhealthy",
            "database": "connected" if db_status else "disconnected",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0.0"
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unavailable")

# Override dependency injection in route files
app.dependency_overrides[DatabaseManager] = get_db_manager
app.dependency_overrides[VulnerabilityScanner] = get_vulnerability_scanner

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info"
    )