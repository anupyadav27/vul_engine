"""
Reports API routes - Handle vulnerability reporting and analytics
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import logging

from core.auth import verify_api_key
from core.database import DatabaseManager

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/dashboard")
async def get_dashboard_summary(
    db_manager: DatabaseManager = Depends(),
    user: dict = Depends(verify_api_key)
):
    """Get dashboard summary with key metrics"""
    try:
        # Get recent data
        agents = await db_manager.get_agent_list()
        scans = await db_manager.get_scan_history(limit=500)
        vulnerabilities = await db_manager.search_vulnerabilities()
        
        # Calculate key metrics
        active_agents = len([a for a in agents if a.get('status') == 'active'])
        recent_scans = len([s for s in scans if s.get('scan_timestamp')])
        critical_vulns = len([v for v in vulnerabilities if v.get('severity') == 'CRITICAL'])
        high_vulns = len([v for v in vulnerabilities if v.get('severity') == 'HIGH'])
        
        # Calculate trends (compare with older data)
        now = datetime.utcnow()
        week_ago = now - timedelta(days=7)
        
        recent_scan_count = len([s for s in scans[:100] if s.get('scan_timestamp')])
        total_packages_scanned = sum(s.get('packages_found', 0) for s in scans[:50])
        
        return {
            "overview": {
                "active_agents": active_agents,
                "total_agents": len(agents),
                "recent_scans_7d": recent_scan_count,
                "total_vulnerabilities": len(vulnerabilities),
                "critical_vulnerabilities": critical_vulns,
                "high_vulnerabilities": high_vulns,
                "packages_scanned": total_packages_scanned
            },
            "severity_breakdown": {
                "CRITICAL": critical_vulns,
                "HIGH": high_vulns,
                "MEDIUM": len([v for v in vulnerabilities if v.get('severity') == 'MEDIUM']),
                "LOW": len([v for v in vulnerabilities if v.get('severity') == 'LOW'])
            },
            "top_vulnerable_packages": _get_top_vulnerable_packages(vulnerabilities),
            "agent_health": _get_agent_health_summary(agents, scans),
            "generated_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to generate dashboard: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate dashboard")

@router.get("/executive")
async def generate_executive_report(
    days: int = Query(30, ge=1, le=365, description="Report period in days"),
    db_manager: DatabaseManager = Depends(),
    user: dict = Depends(verify_api_key)
):
    """Generate executive summary report"""
    try:
        agents = await db_manager.get_agent_list()
        scans = await db_manager.get_scan_history(limit=1000)
        vulnerabilities = await db_manager.search_vulnerabilities()
        
        # Risk assessment
        risk_score = _calculate_risk_score(vulnerabilities)
        
        # Compliance status
        compliance_score = _calculate_compliance_score(vulnerabilities, scans)
        
        return {
            "executive_summary": {
                "report_period_days": days,
                "overall_risk_score": risk_score,
                "compliance_score": compliance_score,
                "total_assets_scanned": len(agents),
                "scan_coverage": f"{min(100, (len(scans) / max(len(agents), 1)) * 100):.1f}%"
            },
            "key_findings": {
                "critical_issues": len([v for v in vulnerabilities if v.get('severity') == 'CRITICAL']),
                "systems_at_risk": len(set(v.get('agent_id') for v in vulnerabilities if v.get('severity') in ['CRITICAL', 'HIGH'])),
                "most_vulnerable_systems": _get_most_vulnerable_systems(vulnerabilities, agents),
                "trending_threats": _get_trending_threats(vulnerabilities)
            },
            "recommendations": _generate_executive_recommendations(vulnerabilities, scans),
            "generated_at": datetime.utcnow().isoformat(),
            "report_type": "executive_summary"
        }
        
    except Exception as e:
        logger.error(f"Failed to generate executive report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate executive report")

@router.get("/compliance")
async def generate_compliance_report(
    framework: str = Query("general", description="Compliance framework (general, pci, soc2, iso27001)"),
    db_manager: DatabaseManager = Depends(),
    user: dict = Depends(verify_api_key)
):
    """Generate compliance-focused report"""
    try:
        vulnerabilities = await db_manager.search_vulnerabilities()
        scans = await db_manager.get_scan_history(limit=500)
        agents = await db_manager.get_agent_list()
        
        # Framework-specific assessments
        compliance_items = _get_compliance_items(framework, vulnerabilities, scans)
        
        return {
            "compliance_framework": framework,
            "assessment_date": datetime.utcnow().isoformat(),
            "overall_compliance_score": _calculate_compliance_score(vulnerabilities, scans),
            "compliance_items": compliance_items,
            "vulnerability_summary": {
                "total": len(vulnerabilities),
                "critical": len([v for v in vulnerabilities if v.get('severity') == 'CRITICAL']),
                "high": len([v for v in vulnerabilities if v.get('severity') == 'HIGH']),
                "remediation_required": len([v for v in vulnerabilities if v.get('severity') in ['CRITICAL', 'HIGH']])
            },
            "scanning_coverage": {
                "total_systems": len(agents),
                "scanned_systems": len(set(s.get('agent_id') for s in scans)),
                "coverage_percentage": f"{(len(set(s.get('agent_id') for s in scans)) / max(len(agents), 1)) * 100:.1f}%"
            },
            "recommendations": _get_compliance_recommendations(framework, vulnerabilities)
        }
        
    except Exception as e:
        logger.error(f"Failed to generate compliance report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate compliance report")

@router.get("/technical")
async def generate_technical_report(
    agent_id: Optional[str] = Query(None, description="Focus on specific agent"),
    severity_filter: Optional[str] = Query(None, description="Filter by severity"),
    db_manager: DatabaseManager = Depends(),
    user: dict = Depends(verify_api_key)
):
    """Generate detailed technical report"""
    try:
        # Get filtered data
        filters = {}
        if severity_filter:
            filters['severity'] = severity_filter.upper()
        
        vulnerabilities = await db_manager.search_vulnerabilities(**filters)
        
        if agent_id:
            vulnerabilities = [v for v in vulnerabilities if v.get('agent_id') == agent_id]
            scans = await db_manager.get_scan_history(agent_id=agent_id)
        else:
            scans = await db_manager.get_scan_history(limit=200)
        
        # Technical analysis
        package_analysis = _analyze_vulnerable_packages(vulnerabilities)
        remediation_plan = _generate_remediation_plan(vulnerabilities)
        
        return {
            "technical_summary": {
                "vulnerabilities_analyzed": len(vulnerabilities),
                "unique_cves": len(set(v.get('cve_id') for v in vulnerabilities if v.get('cve_id'))),
                "affected_packages": len(set(v.get('package_name') for v in vulnerabilities if v.get('package_name'))),
                "scan_period": _get_scan_period(scans)
            },
            "vulnerability_breakdown": {
                "by_severity": _group_by_severity(vulnerabilities),
                "by_package_type": _group_by_package_type(vulnerabilities),
                "by_cve_year": _group_by_cve_year(vulnerabilities)
            },
            "package_analysis": package_analysis,
            "remediation_plan": remediation_plan,
            "technical_recommendations": _get_technical_recommendations(vulnerabilities),
            "filters_applied": {
                "agent_id": agent_id,
                "severity_filter": severity_filter
            },
            "generated_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to generate technical report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate technical report")

# Helper functions
def _get_top_vulnerable_packages(vulnerabilities: List[Dict]) -> List[Dict]:
    """Get packages with most vulnerabilities"""
    package_counts = {}
    for vuln in vulnerabilities:
        pkg = vuln.get('package_name', 'unknown')
        package_counts[pkg] = package_counts.get(pkg, 0) + 1
    
    return [
        {"package": pkg, "vulnerability_count": count}
        for pkg, count in sorted(package_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    ]

def _get_agent_health_summary(agents: List[Dict], scans: List[Dict]) -> Dict:
    """Calculate agent health metrics"""
    recent_scans = {}
    for scan in scans[:100]:  # Recent scans only
        agent_id = scan.get('agent_id')
        if agent_id:
            recent_scans[agent_id] = recent_scans.get(agent_id, 0) + 1
    
    active_agents = len([a for a in agents if a.get('status') == 'active'])
    scanning_agents = len(recent_scans)
    
    return {
        "total_agents": len(agents),
        "active_agents": active_agents,
        "recently_scanned": scanning_agents,
        "health_percentage": f"{(scanning_agents / max(active_agents, 1)) * 100:.1f}%"
    }

def _calculate_risk_score(vulnerabilities: List[Dict]) -> float:
    """Calculate overall risk score (0-100)"""
    if not vulnerabilities:
        return 0.0
    
    severity_weights = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 1}
    total_score = sum(severity_weights.get(v.get('severity', 'LOW'), 1) for v in vulnerabilities)
    max_possible = len(vulnerabilities) * 10
    
    return min(100.0, (total_score / max_possible) * 100)

def _calculate_compliance_score(vulnerabilities: List[Dict], scans: List[Dict]) -> float:
    """Calculate compliance score (0-100)"""
    critical_vulns = len([v for v in vulnerabilities if v.get('severity') == 'CRITICAL'])
    high_vulns = len([v for v in vulnerabilities if v.get('severity') == 'HIGH'])
    
    # Deduct points for high-severity vulnerabilities
    deductions = (critical_vulns * 15) + (high_vulns * 5)
    base_score = 100
    
    return max(0.0, base_score - deductions)

def _get_most_vulnerable_systems(vulnerabilities: List[Dict], agents: List[Dict]) -> List[Dict]:
    """Identify systems with most vulnerabilities"""
    system_counts = {}
    for vuln in vulnerabilities:
        agent_id = vuln.get('agent_id')
        if agent_id:
            system_counts[agent_id] = system_counts.get(agent_id, 0) + 1
    
    # Get agent details
    agent_map = {a.get('agent_id'): a for a in agents}
    
    result = []
    for agent_id, count in sorted(system_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
        agent_info = agent_map.get(agent_id, {})
        result.append({
            "agent_id": agent_id,
            "hostname": agent_info.get('hostname', 'unknown'),
            "vulnerability_count": count,
            "platform": agent_info.get('platform', 'unknown')
        })
    
    return result

def _get_trending_threats(vulnerabilities: List[Dict]) -> List[str]:
    """Identify trending threat patterns"""
    cve_counts = {}
    for vuln in vulnerabilities:
        cve_id = vuln.get('cve_id')
        if cve_id:
            cve_counts[cve_id] = cve_counts.get(cve_id, 0) + 1
    
    return [cve for cve, count in sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)[:5]]

def _generate_executive_recommendations(vulnerabilities: List[Dict], scans: List[Dict]) -> List[str]:
    """Generate executive-level recommendations"""
    recommendations = []
    
    critical_count = len([v for v in vulnerabilities if v.get('severity') == 'CRITICAL'])
    high_count = len([v for v in vulnerabilities if v.get('severity') == 'HIGH'])
    
    if critical_count > 0:
        recommendations.append(f"Immediate action required: {critical_count} critical vulnerabilities need patching")
    
    if high_count > 10:
        recommendations.append("Implement automated patch management for high-volume vulnerability remediation")
    
    if len(scans) < 10:
        recommendations.append("Increase scanning frequency to improve vulnerability detection coverage")
    
    return recommendations

def _get_compliance_items(framework: str, vulnerabilities: List[Dict], scans: List[Dict]) -> List[Dict]:
    """Get compliance items based on framework"""
    items = []
    
    if framework == "pci":
        items = [
            {"requirement": "11.2.1", "description": "Quarterly vulnerability scanning", "status": "compliant" if scans else "non-compliant"},
            {"requirement": "6.1", "description": "Critical vulnerability patching", "status": "non-compliant" if any(v.get('severity') == 'CRITICAL' for v in vulnerabilities) else "compliant"}
        ]
    else:
        items = [
            {"requirement": "General", "description": "Regular vulnerability assessment", "status": "compliant" if scans else "non-compliant"},
            {"requirement": "General", "description": "High-risk vulnerability management", "status": "needs-attention" if any(v.get('severity') in ['CRITICAL', 'HIGH'] for v in vulnerabilities) else "compliant"}
        ]
    
    return items

def _get_compliance_recommendations(framework: str, vulnerabilities: List[Dict]) -> List[str]:
    """Get compliance-specific recommendations"""
    recommendations = []
    
    if any(v.get('severity') == 'CRITICAL' for v in vulnerabilities):
        recommendations.append("Critical vulnerabilities detected - immediate remediation required for compliance")
    
    recommendations.append("Implement regular vulnerability scanning schedule")
    recommendations.append("Establish vulnerability management policies and procedures")
    
    return recommendations

def _analyze_vulnerable_packages(vulnerabilities: List[Dict]) -> Dict:
    """Analyze vulnerable packages"""
    package_analysis = {}
    for vuln in vulnerabilities:
        pkg_name = vuln.get('package_name', 'unknown')
        if pkg_name not in package_analysis:
            package_analysis[pkg_name] = {
                'total_vulnerabilities': 0,
                'severities': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
                'versions_affected': set()
            }
        
        package_analysis[pkg_name]['total_vulnerabilities'] += 1
        severity = vuln.get('severity', 'LOW')
        if severity in package_analysis[pkg_name]['severities']:
            package_analysis[pkg_name]['severities'][severity] += 1
        
        version = vuln.get('package_version')
        if version:
            package_analysis[pkg_name]['versions_affected'].add(version)
    
    # Convert sets to lists for JSON serialization
    for pkg in package_analysis:
        package_analysis[pkg]['versions_affected'] = list(package_analysis[pkg]['versions_affected'])
    
    return package_analysis

def _generate_remediation_plan(vulnerabilities: List[Dict]) -> List[Dict]:
    """Generate prioritized remediation plan"""
    plan = []
    
    # Group by severity
    critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'CRITICAL']
    high_vulns = [v for v in vulnerabilities if v.get('severity') == 'HIGH']
    
    if critical_vulns:
        plan.append({
            "priority": "IMMEDIATE",
            "action": f"Patch {len(critical_vulns)} critical vulnerabilities",
            "timeline": "24-48 hours",
            "affected_packages": list(set(v.get('package_name') for v in critical_vulns if v.get('package_name')))
        })
    
    if high_vulns:
        plan.append({
            "priority": "HIGH",
            "action": f"Patch {len(high_vulns)} high severity vulnerabilities",
            "timeline": "1-2 weeks",
            "affected_packages": list(set(v.get('package_name') for v in high_vulns if v.get('package_name')))
        })
    
    return plan

def _group_by_severity(vulnerabilities: List[Dict]) -> Dict:
    """Group vulnerabilities by severity"""
    groups = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'LOW')
        if severity in groups:
            groups[severity] += 1
    return groups

def _group_by_package_type(vulnerabilities: List[Dict]) -> Dict:
    """Group vulnerabilities by package type"""
    groups = {}
    for vuln in vulnerabilities:
        pkg_type = vuln.get('package_type', 'unknown')
        groups[pkg_type] = groups.get(pkg_type, 0) + 1
    return groups

def _group_by_cve_year(vulnerabilities: List[Dict]) -> Dict:
    """Group vulnerabilities by CVE year"""
    groups = {}
    for vuln in vulnerabilities:
        cve_id = vuln.get('cve_id', '')
        if cve_id and 'CVE-' in cve_id:
            try:
                year = cve_id.split('-')[1]
                groups[year] = groups.get(year, 0) + 1
            except IndexError:
                groups['unknown'] = groups.get('unknown', 0) + 1
        else:
            groups['unknown'] = groups.get('unknown', 0) + 1
    return groups

def _get_technical_recommendations(vulnerabilities: List[Dict]) -> List[str]:
    """Generate technical recommendations"""
    recommendations = []
    
    # Package manager specific
    package_managers = set(v.get('package_manager') for v in vulnerabilities if v.get('package_manager'))
    for pm in package_managers:
        recommendations.append(f"Implement automated {pm} package updates")
    
    # Version management
    recommendations.append("Consider implementing dependency scanning in CI/CD pipeline")
    recommendations.append("Establish package version pinning strategy")
    
    return recommendations

def _get_scan_period(scans: List[Dict]) -> str:
    """Get the scanning period from scan data"""
    if not scans:
        return "No scans available"
    
    timestamps = [s.get('scan_timestamp') for s in scans if s.get('scan_timestamp')]
    if timestamps:
        return f"Last {len(scans)} scans"
    return "Recent scans"