import os
import json
import requests
from tqdm import tqdm
from collections import defaultdict
import re

# Constants
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
NVD_DATA_FOLDER = os.path.join(SCRIPT_DIR, "nvd_data")
OUTPUT_FOLDER = os.path.join(SCRIPT_DIR, "output")
MITRE_ATTACK_FILE = os.path.join(OUTPUT_FOLDER, "mitre_techniques.json")
OUTPUT_FILE = os.path.join(OUTPUT_FOLDER, "cve_vulnerability_report.json")
PRODUCT_MAPPING_FILE = os.path.join(OUTPUT_FOLDER, "cve_product_mapping.json")
TECHNOLOGY_MAPPING_FILE = os.path.join(OUTPUT_FOLDER, "technology_mapping.json")
COMPLIANCE_MAPPING_FILE = os.path.join(OUTPUT_FOLDER, "compliance_mapping.json")
ATTACK_JSON_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# Ensure necessary folders exist
os.makedirs(NVD_DATA_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# Enhanced mapping configurations
TECHNOLOGY_CATEGORIES = {
    "cloud_platforms": ["aws", "azure", "gcp", "google", "microsoft", "amazon"],
    "databases": ["mysql", "postgresql", "oracle", "mongodb", "redis", "sqlite"],
    "web_servers": ["apache", "nginx", "iis", "tomcat", "jetty"],
    "operating_systems": ["windows", "linux", "ubuntu", "centos", "redhat", "macos"],
    "network_devices": ["cisco", "juniper", "fortinet", "paloalto", "checkpoint"],
    "containers": ["docker", "kubernetes", "containerd", "podman"],
    "programming_languages": ["python", "java", "javascript", "php", "ruby", "go"],
    "security_tools": ["openssl", "ssh", "ssl", "tls", "ipsec"]
}

COMPLIANCE_FRAMEWORKS = {
    "SOC2": {
        "categories": ["access_control", "data_protection", "availability"],
        "severity_mapping": {"CRITICAL": "Type I", "HIGH": "Type II", "MEDIUM": "Advisory", "LOW": "Minor"}
    },
    "ISO27001": {
        "categories": ["information_security", "risk_management", "incident_response"],
        "severity_mapping": {"CRITICAL": "Major", "HIGH": "Significant", "MEDIUM": "Minor", "LOW": "Observation"}
    },
    "NIST": {
        "categories": ["identify", "protect", "detect", "respond", "recover"],
        "severity_mapping": {"CRITICAL": "P0", "HIGH": "P1", "MEDIUM": "P2", "LOW": "P3"}
    },
    "PCI_DSS": {
        "categories": ["cardholder_data", "encryption", "access_control"],
        "severity_mapping": {"CRITICAL": "Level 1", "HIGH": "Level 2", "MEDIUM": "Level 3", "LOW": "Level 4"}
    }
}

# Utility Functions
def extract_title(description: str) -> str:
    return description.split('.')[0] if description else ""

def parse_cpe_uri(cpe_uri):
    parts = cpe_uri.split(":")
    if len(parts) >= 6:
        return {
            "vendor": parts[3],
            "product": parts[4],
            "version": parts[5]
        }
    return {}

def categorize_technology(affected_products):
    """Categorize affected products into technology categories"""
    categories = []
    platforms = []
    
    for product in affected_products:
        vendor = product.get("vendor", "").lower()
        product_name = product.get("product", "").lower()
        
        # Check technology categories
        for category, keywords in TECHNOLOGY_CATEGORIES.items():
            if any(keyword in vendor or keyword in product_name for keyword in keywords):
                if category not in categories:
                    categories.append(category)
                    
        # Determine platform type
        if any(cloud in vendor or cloud in product_name for cloud in ["aws", "azure", "gcp", "google", "microsoft", "amazon"]):
            platforms.append("cloud")
        elif any(os_name in vendor or os_name in product_name for os_name in ["windows", "linux", "ubuntu", "centos"]):
            platforms.append("on_premise")
        elif any(container in vendor or container in product_name for container in ["docker", "kubernetes"]):
            platforms.append("containerized")
    
    return {
        "categories": list(set(categories)),
        "platforms": list(set(platforms)),
        "source_type": "nvd_cve_data"
    }

def map_compliance_frameworks(cve_data):
    """Map CVE data to compliance frameworks"""
    base_severity = cve_data.get("base_severity", "LOW")
    cwe_id = cve_data.get("cwe_id", "")
    
    compliance_mapping = {}
    
    for framework, config in COMPLIANCE_FRAMEWORKS.items():
        # Map severity
        severity_mapping = config["severity_mapping"].get(base_severity, "Unknown")
        
        # Determine applicable categories based on CWE
        applicable_categories = []
        if "access" in cwe_id.lower() or "authentication" in cwe_id.lower():
            applicable_categories.append("access_control")
        if "encryption" in cwe_id.lower() or "crypto" in cwe_id.lower():
            applicable_categories.append("data_protection")
        if "injection" in cwe_id.lower() or "xss" in cwe_id.lower():
            applicable_categories.append("information_security")
        
        # Default category if none matched
        if not applicable_categories:
            applicable_categories = config["categories"][:1]  # Take first category as default
            
        compliance_mapping[framework] = {
            "applicable": True,
            "severity": severity_mapping,
            "categories": applicable_categories,
            "regulatory_impact": "high" if base_severity in ["CRITICAL", "HIGH"] else "medium"
        }
    
    return compliance_mapping

def generate_remediation_details(cve_data):
    """Generate practical remediation details for security teams"""
    base_score = cve_data.get("base_score", 0)
    base_severity = cve_data.get("base_severity", "LOW")
    attack_vector = cve_data.get("attack_vector", "")
    affected_products = cve_data.get("affected_products", [])
    
    # Determine priority based on CVSS score and attack vector
    if base_score >= 9.0:
        priority = "P0 - Critical"
        estimated_effort = "4-8 hours"
    elif base_score >= 7.0:
        priority = "P1 - High"
        estimated_effort = "2-4 hours"
    elif base_score >= 4.0:
        priority = "P2 - Medium"
        estimated_effort = "1-2 hours"
    else:
        priority = "P3 - Low"
        estimated_effort = "30-60 minutes"
        
    # Generate remediation steps based on common patterns
    remediation_steps = []
    
    if attack_vector == "NETWORK":
        remediation_steps.extend([
            "Review and restrict network access to affected services",
            "Implement network segmentation if not already in place",
            "Monitor network traffic for suspicious activity"
        ])
    
    if affected_products:
        remediation_steps.extend([
            "Identify all instances of affected products in your environment",
            "Check for available security patches or updates",
            "Plan and execute patching in a controlled manner"
        ])
    
    # Add generic steps
    remediation_steps.extend([
        "Assess impact on your specific environment",
        "Document remediation actions taken",
        "Verify fix effectiveness through testing"
    ])
    
    return {
        "priority": priority,
        "estimated_effort": estimated_effort,
        "remediation_steps": remediation_steps,
        "patch_availability": "check_vendor_advisories",
        "business_impact": "high" if base_score >= 7.0 else "medium" if base_score >= 4.0 else "low",
        "recommended_timeline": "immediate" if base_score >= 9.0 else "within_72h" if base_score >= 7.0 else "within_30d"
    }

def generate_cve_urls(cve_id):
    """Generate standard CVE URLs for reference"""
    return {
        "mitre_url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "primary_reference": f"https://nvd.nist.gov/vuln/detail/{cve_id}"  # NVD is more comprehensive
    }

# Step 1: Download and Save MITRE ATT&CK Techniques
def download_mitre_attack_data():
    print("Downloading MITRE ATT&CK techniques...")
    response = requests.get(ATTACK_JSON_URL)
    response.raise_for_status()  # Ensure the request was successful
    data = response.json()
    techniques = {}
    mitigations = {}

    # First collect mitigations
    for obj in data["objects"]:
        if obj.get("type") == "course-of-action":
            mitigation_id = obj.get("id")
            mitigations[mitigation_id] = {
                "type": "course-of-action",
                "id": mitigation_id,
                "name": obj.get("name"),
                "description": obj.get("description")
            }

    # Then collect techniques and map mitigations
    for obj in data["objects"]:
        if obj.get("type") == "attack-pattern":
            technique_id = next((x["external_id"] for x in obj.get("external_references", []) if x["source_name"] == "mitre-attack"), None)
            if technique_id:
                tactic_refs = obj.get("kill_chain_phases", [])
                tactics = [ref.get("phase_name") for ref in tactic_refs]

                # Find mitigations from relationships
                related_mitigations = []
                for rel in data["objects"]:
                    if rel.get("type") == "relationship" and rel.get("relationship_type") == "mitigates":
                        if rel.get("target_ref") == obj.get("id"):
                            mitigation_obj = mitigations.get(rel.get("source_ref"))
                            if mitigation_obj:
                                related_mitigations.append(mitigation_obj)

                techniques[technique_id] = {
                    "technique_id": technique_id,
                    "technique_name": obj.get("name"),
                    "url": next((x["url"] for x in obj.get("external_references", []) if x.get("url")), f"https://attack.mitre.org/techniques/{technique_id}/"),
                    "tactics": tactics,
                    "mitigations": related_mitigations
                }

    # Save techniques to file
    with open(MITRE_ATTACK_FILE, "w") as f:
        json.dump(techniques, f, indent=4)
    print(f"Saved MITRE ATT&CK techniques to {MITRE_ATTACK_FILE}")

# Step 2: Load MITRE ATT&CK Techniques
def load_mitre_attack_mapping():
    if not os.path.exists(MITRE_ATTACK_FILE):
        print("MITRE ATT&CK techniques file not found. Downloading...")
        download_mitre_attack_data()

    with open(MITRE_ATTACK_FILE, "r") as f:
        return json.load(f)

# Step 3: Process NVD CVE Files
def process_nvd_files(nvd_path: str, mitre_map: dict):
    output = []
    processed_count = 0
    enhancement_errors = 0
    
    for filename in tqdm(os.listdir(nvd_path)):
        if not filename.endswith(".json"):
            continue
        filepath = os.path.join(nvd_path, filename)
        with open(filepath) as f:
            try:
                data = json.load(f)
            except Exception as e:
                print(f"Error loading {filename}: {e}")
                continue

        for item in data.get("CVE_Items", []):
            try:
                cve_id = item['cve']['CVE_data_meta']['ID']
                description = next((desc['value'] for desc in item['cve']['description']['description_data'] if desc['lang'] == 'en'), "")
                title = extract_title(description)

                cvss = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {})
                base_score = cvss.get('baseScore')
                base_severity = cvss.get('baseSeverity')
                attack_vector = cvss.get('attackVector')
                attack_complexity = cvss.get('attackComplexity')
                privileges_required = cvss.get('privilegesRequired')
                user_interaction = cvss.get('userInteraction')

                cwe_id = ""
                for ptype in item['cve']['problemtype']['problemtype_data']:
                    for desc in ptype.get('description', []):
                        if 'CWE' in desc['value']:
                            cwe_id = desc['value']
                            break

                # Extract affected products (vendor, product, version)
                affected = []
                for node in item.get('configurations', {}).get('nodes', []):
                    for match in node.get('cpe_match', []):
                        if match.get('vulnerable'):
                            parsed = parse_cpe_uri(match['cpe23Uri'])
                            if parsed:
                                affected.append(parsed)

                # Get MITRE ID from CWE ID
                mitre_info = {}
                try:
                    for tech_id, tech_data in mitre_map.items():
                        if cwe_id and cwe_id in str(tech_data.get("description", "")):
                            mitre_info = tech_data
                            break
                except Exception as e:
                    print(f"Error processing MITRE data for {cve_id}: {e}")

                # Generate enhancements with error handling
                cve_urls = {}
                technology_info = {}
                compliance_info = {}
                remediation_info = {}
                
                try:
                    # Generate CVE URLs
                    cve_urls = generate_cve_urls(cve_id)
                except Exception as e:
                    print(f"Error generating CVE URLs for {cve_id}: {e}")
                    enhancement_errors += 1

                try:
                    # Categorize technology
                    technology_info = categorize_technology(affected)
                except Exception as e:
                    print(f"Error categorizing technology for {cve_id}: {e}")
                    enhancement_errors += 1

                try:
                    # Map compliance frameworks
                    compliance_info = map_compliance_frameworks({
                        "base_severity": base_severity,
                        "cwe_id": cwe_id
                    })
                except Exception as e:
                    print(f"Error mapping compliance frameworks for {cve_id}: {e}")
                    enhancement_errors += 1

                try:
                    # Generate remediation details
                    remediation_info = generate_remediation_details({
                        "base_score": base_score or 0,
                        "base_severity": base_severity or "LOW",
                        "attack_vector": attack_vector or "UNKNOWN",
                        "affected_products": affected
                    })
                except Exception as e:
                    print(f"Error generating remediation details for {cve_id}: {e}")
                    enhancement_errors += 1

                # Build the CVE entry with all enhancements
                cve_entry = {
                    "cve_id": cve_id,
                    "title": title,
                    "description": description,
                    "cwe_id": cwe_id,
                    "base_score": base_score,
                    "base_severity": base_severity,
                    "attack_vector": attack_vector,
                    "attack_complexity": attack_complexity,
                    "privileges_required": privileges_required,
                    "user_interaction": user_interaction,
                    "affected_products": affected,
                    "mitre_attack": mitre_info
                }
                
                # Add enhancements if they were generated successfully
                if cve_urls:
                    cve_entry["cve_urls"] = cve_urls
                if technology_info:
                    cve_entry["technology_info"] = technology_info
                if compliance_info:
                    cve_entry["compliance_info"] = compliance_info
                if remediation_info:
                    cve_entry["remediation_info"] = remediation_info
                
                output.append(cve_entry)
                processed_count += 1
                
                # Debug output every 1000 CVEs
                if processed_count % 1000 == 0:
                    print(f"Processed {processed_count} CVEs, enhancement errors: {enhancement_errors}")
                    
            except Exception as e:
                print(f"Error processing CVE in {filename}: {e}")
                continue
    
    print(f"Total CVEs processed: {processed_count}")
    print(f"Total enhancement errors: {enhancement_errors}")
    return output

# Step 4: Generate CVE-to-Product Mapping
def generate_cve_product_mapping():
    print("Generating CVE-to-Product mapping...")
    if not os.path.exists(OUTPUT_FILE):
        print(f"Output file {OUTPUT_FILE} not found. Run the CVE processing first.")
        return

    with open(OUTPUT_FILE, "r") as f:
        cve_data = json.load(f)

    product_mapping = defaultdict(list)
    for entry in cve_data:
        cve_id = entry.get("cve_id")
        for product in entry.get("affected_products", []):
            vendor = product.get("vendor", "Unknown")
            product_name = product.get("product", "Unknown")
            version = product.get("version", "Unknown")
            product_mapping[f"{vendor}:{product_name}:{version}"].append(cve_id)

    # Save product mapping to file
    with open(PRODUCT_MAPPING_FILE, "w") as f:
        json.dump(product_mapping, f, indent=4)

    print(f"Saved CVE-to-Product mapping to {PRODUCT_MAPPING_FILE}")

if __name__ == "__main__":
    print("Starting CVE processing...")
    mitre_map = load_mitre_attack_mapping()
    final_data = process_nvd_files(NVD_DATA_FOLDER, mitre_map)

    with open(OUTPUT_FILE, "w") as out:
        json.dump(final_data, out, indent=2)

    print(f"Saved {len(final_data)} CVE entries with enrichments to {OUTPUT_FILE}")

    # Generate CVE-to-Product mapping
    generate_cve_product_mapping()
