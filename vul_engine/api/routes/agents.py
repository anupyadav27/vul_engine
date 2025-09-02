"""
Agent API routes - Handle agent registration and scan submissions
"""

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, List, Optional
from datetime import datetime
import logging

from core.auth import verify_api_key
from core.database import DatabaseManager
from core.scanner import VulnerabilityScanner

logger = logging.getLogger(__name__)
router = APIRouter()

# Pydantic models for request/response
class AgentRegistration(BaseModel):
    agent_id: str
    hostname: str
    platform: str
    architecture: str
    agent_version: str
    metadata: Optional[Dict] = {}

class ScanData(BaseModel):
    agent_id: str
    timestamp: str
    system_info: Dict
    packages: List[Dict]
    services: List[Dict]
    scan_duration: float
    # Additional fields for hybrid mode
    local_vulnerabilities: Optional[List[Dict]] = []
    analysis_mode: Optional[str] = "central"

class ScanResponse(BaseModel):
    success: bool
    scan_id: Optional[int] = None
    vulnerabilities_found: int = 0
    message: str = ""
    vulnerability_summary: Optional[Dict] = {}

@router.post("/register")
async def register_agent(
    agent_data: AgentRegistration,
    db_manager: DatabaseManager = Depends()
):
    """Register a new agent or update existing agent information"""
    try:
        agent_dict = agent_data.dict()
        success = await db_manager.register_agent(agent_dict)
        
        if success:
            logger.info(f"Agent registered successfully: {agent_data.agent_id}")
            return {
                "success": True,
                "message": "Agent registered successfully",
                "agent_id": agent_data.agent_id,
                "timestamp": datetime.utcnow().isoformat()
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to register agent")
            
    except Exception as e:
        logger.error(f"Agent registration failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan", response_model=ScanResponse)
async def submit_scan_results(
    scan_data: ScanData,
    background_tasks: BackgroundTasks,
    db_manager: DatabaseManager = Depends(),
    scanner: VulnerabilityScanner = Depends()
):
    """Submit scan results from agent for vulnerability analysis"""
    try:
        logger.info(f"Received scan from agent {scan_data.agent_id}")
        
        # Process scan in background for better response time
        background_tasks.add_task(
            process_scan_background, 
            scanner, 
            scan_data.dict()
        )
        
        # Quick validation and storage
        scan_id = await db_manager.store_scan_results(scan_data.dict())
        
        if scan_id:
            return ScanResponse(
                success=True,
                scan_id=scan_id,
                message="Scan received and processing started",
                vulnerabilities_found=0  # Will be updated after processing
            )
        else:
            return ScanResponse(
                success=False,
                message="Failed to store scan results"
            )
            
    except Exception as e:
        logger.error(f"Scan submission failed: {e}")
        return ScanResponse(
            success=False,
            message=f"Scan processing failed: {str(e)}"
        )

async def process_scan_background(scanner: VulnerabilityScanner, scan_data: Dict):
    """Background task to process scan results"""
    try:
        result = await scanner.process_scan_results(scan_data)
        logger.info(f"Background scan processing completed: {result['vulnerabilities_found']} vulnerabilities")
    except Exception as e:
        logger.error(f"Background scan processing failed: {e}")

@router.get("/")
async def list_agents(
    db_manager: DatabaseManager = Depends()
):
    """Get list of all registered agents"""
    try:
        agents = await db_manager.get_agent_list()
        return {
            "agents": agents,
            "total_count": len(agents),
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to get agent list: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve agents")

@router.get("/{agent_id}")
async def get_agent_details(
    agent_id: str,
    db_manager: DatabaseManager = Depends()
):
    """Get detailed information about a specific agent"""
    try:
        # Get agent info
        agents = await db_manager.get_agent_list()
        agent = next((a for a in agents if a['agent_id'] == agent_id), None)
        
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Get recent scans for this agent
        scans = await db_manager.get_scan_history(agent_id=agent_id, limit=10)
        
        return {
            "agent": agent,
            "recent_scans": scans,
            "scan_count": len(scans)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get agent details: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve agent details")

@router.get("/{agent_id}/scans")
async def get_agent_scans(
    agent_id: str,
    limit: int = 50,
    db_manager: DatabaseManager = Depends()
):
    """Get scan history for a specific agent"""
    try:
        scans = await db_manager.get_scan_history(agent_id=agent_id, limit=limit)
        return {
            "agent_id": agent_id,
            "scans": scans,
            "total_count": len(scans)
        }
    except Exception as e:
        logger.error(f"Failed to get agent scans: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve scan history")