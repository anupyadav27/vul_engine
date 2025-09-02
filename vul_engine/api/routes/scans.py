"""
Scans API routes - Handle scan management and history
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
from typing import Dict, List, Optional
from datetime import datetime
import logging

from core.auth import verify_api_key
from core.database import DatabaseManager

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/")
async def get_scan_history(
    agent_id: Optional[str] = Query(None, description="Filter by agent ID"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of scans to return"),
    db_manager: DatabaseManager = Depends(),
    user: dict = Depends(verify_api_key)
):
    """Get scan history with optional filtering"""
    try:
        scans = await db_manager.get_scan_history(agent_id=agent_id, limit=limit)
        return {
            "scans": scans,
            "total_count": len(scans),
            "filters": {
                "agent_id": agent_id,
                "limit": limit
            },
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to get scan history: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve scan history")

@router.get("/{scan_id}")
async def get_scan_details(
    scan_id: int,
    db_manager: DatabaseManager = Depends(),
    user: dict = Depends(verify_api_key)
):
    """Get detailed information about a specific scan"""
    try:
        # Get scan info
        scans = await db_manager.get_scan_history(limit=1000)
        scan = next((s for s in scans if s['scan_id'] == scan_id), None)
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Get vulnerabilities for this scan
        vulnerabilities = await db_manager.search_vulnerabilities()
        scan_vulns = [v for v in vulnerabilities if v.get('scan_id') == scan_id]
        
        return {
            "scan": scan,
            "vulnerabilities": scan_vulns,
            "vulnerability_count": len(scan_vulns)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get scan details: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve scan details")

@router.get("/{scan_id}/vulnerabilities")
async def get_scan_vulnerabilities(
    scan_id: int,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    db_manager: DatabaseManager = Depends(),
    user: dict = Depends(verify_api_key)
):
    """Get vulnerabilities found in a specific scan"""
    try:
        # Get all vulnerabilities and filter by scan_id
        all_vulnerabilities = await db_manager.search_vulnerabilities()
        scan_vulns = [v for v in all_vulnerabilities if v.get('scan_id') == scan_id]
        
        # Apply severity filter if provided
        if severity:
            scan_vulns = [v for v in scan_vulns if v.get('severity') == severity.upper()]
        
        # Group by severity for summary
        severity_summary = {}
        for vuln in scan_vulns:
            sev = vuln.get('severity', 'UNKNOWN')
            severity_summary[sev] = severity_summary.get(sev, 0) + 1
        
        return {
            "scan_id": scan_id,
            "vulnerabilities": scan_vulns,
            "total_count": len(scan_vulns),
            "severity_summary": severity_summary,
            "filters": {"severity": severity}
        }
        
    except Exception as e:
        logger.error(f"Failed to get scan vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve vulnerabilities")

@router.get("/stats/summary")
async def get_scan_statistics(
    days: int = Query(30, ge=1, le=365, description="Number of days to include in stats"),
    db_manager: DatabaseManager = Depends(),
    user: dict = Depends(verify_api_key)
):
    """Get scanning statistics and trends"""
    try:
        # Get recent scans
        scans = await db_manager.get_scan_history(limit=1000)
        
        # Calculate basic stats
        total_scans = len(scans)
        total_packages = sum(s.get('packages_found', 0) for s in scans)
        total_vulnerabilities = sum(s.get('vulnerabilities_found', 0) for s in scans)
        
        # Agent activity
        agent_stats = {}
        for scan in scans:
            agent_id = scan.get('agent_id')
            if agent_id not in agent_stats:
                agent_stats[agent_id] = {
                    'scan_count': 0,
                    'total_vulnerabilities': 0,
                    'last_scan': None
                }
            
            agent_stats[agent_id]['scan_count'] += 1
            agent_stats[agent_id]['total_vulnerabilities'] += scan.get('vulnerabilities_found', 0)
            
            scan_time = scan.get('scan_timestamp')
            if not agent_stats[agent_id]['last_scan'] or scan_time > agent_stats[agent_id]['last_scan']:
                agent_stats[agent_id]['last_scan'] = scan_time
        
        return {
            "summary": {
                "total_scans": total_scans,
                "total_packages_scanned": total_packages,
                "total_vulnerabilities_found": total_vulnerabilities,
                "active_agents": len(agent_stats),
                "average_vulnerabilities_per_scan": round(total_vulnerabilities / max(total_scans, 1), 2)
            },
            "agent_statistics": agent_stats,
            "period_days": days,
            "generated_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get scan statistics: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve statistics")