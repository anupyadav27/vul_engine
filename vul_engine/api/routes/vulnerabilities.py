"""
Vulnerabilities API routes - Handle vulnerability queries and management
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
async def search_vulnerabilities(
    cve_id: Optional[str] = Query(None, description="Filter by CVE ID"),
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"),
    package_name: Optional[str] = Query(None, description="Filter by package name"),
    agent_id: Optional[str] = Query(None, description="Filter by agent ID"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of results"),
    db_manager: DatabaseManager = Depends(),
    user: dict = Depends(verify_api_key)
):
    """Search vulnerabilities with various filters"""
    try:
        # Build filter dictionary
        filters = {}
        if cve_id:
            filters['cve_id'] = cve_id
        if severity:
            filters['severity'] = severity.upper()
        if package_name:
            filters['package_name'] = package_name
        
        vulnerabilities = await db_manager.search_vulnerabilities(**filters)
        
        # Filter by agent_id if provided (post-processing since it's not in the DB search)
        if agent_id:
            vulnerabilities = [v for v in vulnerabilities if v.get('agent_id') == agent_id]
        
        # Apply limit
        vulnerabilities = vulnerabilities[:limit]
        
        # Calculate summary statistics
        severity_summary = {}
        package_summary = {}
        
        for vuln in vulnerabilities:
            # Severity summary
            sev = vuln.get('severity', 'UNKNOWN')
            severity_summary[sev] = severity_summary.get(sev, 0) + 1
            
            # Package summary
            pkg = vuln.get('package_name', 'unknown')
            package_summary[pkg] = package_summary.get(pkg, 0) + 1
        
        return {
            "vulnerabilities": vulnerabilities,
            "total_count": len(vulnerabilities),
            "severity_summary": severity_summary,
            "top_affected_packages": dict(sorted(package_summary.items(), key=lambda x: x[1], reverse=True)[:10]),
            "filters": {
                "cve_id": cve_id,
                "severity": severity,
                "package_name": package_name,
                "agent_id": agent_id,
                "limit": limit
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to search vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail="Failed to search vulnerabilities")

@router.get("/{cve_id}")
async def get_vulnerability_details(
    cve_id: str,
    db_manager: DatabaseManager = Depends(),
    user: dict = Depends(verify_api_key)
):
    """Get detailed information about a specific CVE"""
    try:
        # Search for this specific CVE
        vulnerabilities = await db_manager.search_vulnerabilities(cve_id=cve_id)
        
        if not vulnerabilities:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        
        # Group by affected systems
        affected_systems = {}
        for vuln in vulnerabilities:
            agent_id = vuln.get('agent_id')
            if agent_id not in affected_systems:
                affected_systems[agent_id] = {
                    'packages': [],
                    'scan_count': 0,
                    'last_seen': None
                }
            
            affected_systems[agent_id]['packages'].append({
                'name': vuln.get('package_name'),
                'version': vuln.get('package_version'),
                'scan_id': vuln.get('scan_id')
            })
            affected_systems[agent_id]['scan_count'] += 1
            
            scan_time = vuln.get('scan_timestamp')
            if not affected_systems[agent_id]['last_seen'] or scan_time > affected_systems[agent_id]['last_seen']:
                affected_systems[agent_id]['last_seen'] = scan_time
        
        # Get the primary vulnerability info (use first entry)
        primary_vuln = vulnerabilities[0]
        
        return {
            "cve_id": cve_id,
            "description": primary_vuln.get('description'),
            "severity": primary_vuln.get('severity'),
            "score": primary_vuln.get('score'),
            "published_date": primary_vuln.get('published_date'),
            "total_affected_systems": len(affected_systems),
            "total_affected_packages": len(vulnerabilities),
            "affected_systems": affected_systems,
            "remediation": primary_vuln.get('remediation')
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get vulnerability details: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve vulnerability details")

@router.get("/stats/severity")
async def get_severity_statistics(
    agent_id: Optional[str] = Query(None, description="Filter by agent ID"),
    days: int = Query(30, ge=1, le=365, description="Number of days to include"),
    db_manager: DatabaseManager = Depends(),
    user: dict = Depends(verify_api_key)
):
    """Get vulnerability statistics grouped by severity"""
    try:
        vulnerabilities = await db_manager.search_vulnerabilities()
        
        # Filter by agent if specified
        if agent_id:
            vulnerabilities = [v for v in vulnerabilities if v.get('agent_id') == agent_id]
        
        # Group by severity
        severity_stats = {
            'CRITICAL': {'count': 0, 'packages': set(), 'cves': set()},
            'HIGH': {'count': 0, 'packages': set(), 'cves': set()},
            'MEDIUM': {'count': 0, 'packages': set(), 'cves': set()},
            'LOW': {'count': 0, 'packages': set(), 'cves': set()}
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            if severity in severity_stats:
                severity_stats[severity]['count'] += 1
                severity_stats[severity]['packages'].add(vuln.get('package_name', 'unknown'))
                severity_stats[severity]['cves'].add(vuln.get('cve_id', 'unknown'))
        
        # Convert sets to counts for JSON serialization
        for severity in severity_stats:
            severity_stats[severity]['unique_packages'] = len(severity_stats[severity]['packages'])
            severity_stats[severity]['unique_cves'] = len(severity_stats[severity]['cves'])
            del severity_stats[severity]['packages']
            del severity_stats[severity]['cves']
        
        return {
            "severity_statistics": severity_stats,
            "total_vulnerabilities": len(vulnerabilities),
            "filters": {
                "agent_id": agent_id,
                "days": days
            },
            "generated_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get severity statistics: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve severity statistics")

@router.get("/stats/trending")
async def get_trending_vulnerabilities(
    limit: int = Query(10, ge=1, le=50, description="Number of trending vulnerabilities to return"),
    db_manager: DatabaseManager = Depends(),
    user: dict = Depends(verify_api_key)
):
    """Get trending vulnerabilities (most frequently found)"""
    try:
        vulnerabilities = await db_manager.search_vulnerabilities()
        
        # Count occurrences of each CVE
        cve_counts = {}
        cve_details = {}
        
        for vuln in vulnerabilities:
            cve_id = vuln.get('cve_id')
            if cve_id:
                cve_counts[cve_id] = cve_counts.get(cve_id, 0) + 1
                if cve_id not in cve_details:
                    cve_details[cve_id] = {
                        'description': vuln.get('description'),
                        'severity': vuln.get('severity'),
                        'score': vuln.get('score'),
                        'affected_packages': set(),
                        'affected_agents': set()
                    }
                
                cve_details[cve_id]['affected_packages'].add(vuln.get('package_name'))
                cve_details[cve_id]['affected_agents'].add(vuln.get('agent_id'))
        
        # Sort by frequency and prepare results
        trending = []
        for cve_id, count in sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)[:limit]:
            details = cve_details[cve_id]
            trending.append({
                'cve_id': cve_id,
                'occurrences': count,
                'description': details['description'],
                'severity': details['severity'],
                'score': details['score'],
                'affected_packages_count': len(details['affected_packages']),
                'affected_agents_count': len(details['affected_agents'])
            })
        
        return {
            "trending_vulnerabilities": trending,
            "analysis_period": "all_time",
            "total_unique_cves": len(cve_counts),
            "generated_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get trending vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve trending vulnerabilities")