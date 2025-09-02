import requests
import logging
from typing import List, Dict
from tqdm import tqdm
import os
import json

logger = logging.getLogger(__name__)

class MITREImporter:
    def __init__(self, output_folder: str):
        self.attack_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        self.output_folder = output_folder
        os.makedirs(self.output_folder, exist_ok=True)

    def import_attack_data(self):
        """Import MITRE ATT&CK data and save to JSON files"""
        logger.info("Downloading MITRE ATT&CK data")
        try:
            data = self._fetch_attack_data()
            techniques, mappings = self._parse_attack_data(data)
            self._store_attack_data(techniques, mappings)
        except Exception as e:
            logger.error(f"MITRE import failed: {str(e)}")
            raise

    def _fetch_attack_data(self) -> Dict:
        """Download MITRE ATT&CK data"""
        response = requests.get(self.attack_url)
        response.raise_for_status()
        return response.json()

    def _parse_attack_data(self, data: Dict) -> tuple:
        """Parse ATT&CK data into techniques and mappings"""
        techniques = []
        mappings = []
        
        for obj in tqdm(data['objects'], desc="Processing ATT&CK objects"):
            if obj['type'] != 'attack-pattern':
                continue
                
            technique = self._parse_technique(obj)
            if technique:
                techniques.append(technique)
                mappings.extend(self._parse_mappings(obj))
                
        return techniques, mappings

    def _parse_technique(self, obj: Dict) -> Dict:
        """Extract technique information"""
        ext_refs = obj.get('external_references', [])
        attack_ref = next((ref for ref in ext_refs if ref.get('source_name') == 'mitre-attack'), None)
        
        if not attack_ref:
            return None
            
        tactic = next((
            phase['phase_name'] for phase in obj.get('kill_chain_phases', [])
            if phase.get('kill_chain_name') == 'mitre-attack'
        ), None)
        
        return {
            'technique_id': attack_ref['external_id'],
            'technique_name': obj.get('name', ''),
            'tactic': tactic,
            'url': attack_ref.get('url', '')
        }

    def _parse_mappings(self, obj: Dict) -> List[Dict]:
        """Extract CVE to technique mappings"""
        mappings = []
        ext_refs = obj.get('external_references', [])
        technique_id = next(
            (ref['external_id'] for ref in ext_refs 
             if ref.get('source_name') == 'mitre-attack'),
            None
        )
        
        if not technique_id:
            return mappings
            
        for ref in ext_refs:
            if ref.get('source_name') == 'cve':
                mappings.append({
                    'cve_id': ref['external_id'].upper(),
                    'technique_id': technique_id
                })
                
        return mappings

    def _store_attack_data(self, techniques: List[Dict], mappings: List[Dict]):
        """Store techniques and mappings in JSON files"""
        try:
            # Save techniques to JSON file
            techniques_file = os.path.join(self.output_folder, "mitre_techniques.json")
            with open(techniques_file, 'w') as file:
                json.dump(techniques, file, indent=4)
            logger.info(f"Techniques saved to {techniques_file}")

            # Save mappings to JSON file
            mappings_file = os.path.join(self.output_folder, "cve_attack_mappings.json")
            with open(mappings_file, 'w') as file:
                json.dump(mappings, file, indent=4)
            logger.info(f"Mappings saved to {mappings_file}")
        except Exception as e:
            logger.error(f"Failed to store ATT&CK data: {str(e)}")
            raise

# Usage
if __name__ == "__main__":
    output_folder = "/Users/apple/Desktop/utility/vuln_db/scripts/cspm_vul_data/"
    importer = MITREImporter(output_folder)
    importer.import_attack_data()