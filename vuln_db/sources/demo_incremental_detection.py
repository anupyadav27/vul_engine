#!/usr/bin/env python3
"""
Demo: CVE ID-Based Incremental Detection

This script demonstrates the efficiency and accuracy of using CVE IDs
for incremental vulnerability detection across different sources.
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from universal_incremental_updater import NVDIncrementalUpdater, DebianIncrementalUpdater
from vuln_db.sources.cve_compatible_os.debian.step4a_incremental_cve_detector import SimpleIncrementalDetector
import json
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def demo_cve_id_comparison():
    """Demonstrate CVE ID-based comparison logic"""
    print("🎯 CVE ID-Based Incremental Detection Demo")
    print("=" * 50)
    
    # Initialize detector
    detector = SimpleIncrementalDetector("demo")
    
    # Test CVE ID parsing and comparison
    test_cases = [
        ("CVE-2025-0001", "CVE-2025-0000", True),   # 2025-1 > 2025-0
        ("CVE-2025-1000", "CVE-2025-0999", True),  # 2025-1000 > 2025-999
        ("CVE-2025-0001", "CVE-2024-9999", True),  # 2025 > 2024
        ("CVE-2024-5000", "CVE-2025-0001", False), # 2024 < 2025
        ("CVE-2025-0001", "CVE-2025-0001", False), # Equal
    ]
    
    print("\n🧪 CVE ID Comparison Tests:")
    for cve1, cve2, expected in test_cases:
        result = detector.is_cve_newer(cve1, cve2)
        status = "✅" if result == expected else "❌"
        print(f"   {status} {cve1} > {cve2}: {result} (expected: {expected})")
    
    # Test with realistic CVE data
    sample_vulnerabilities = [
        {"cve_id": "CVE-2025-0001", "description": "First CVE of 2025"},
        {"cve_id": "CVE-2025-0002", "description": "Second CVE of 2025"},
        {"cve_id": "CVE-2025-0100", "description": "100th CVE of 2025"},
        {"cve_id": "CVE-2024-9999", "description": "Last CVE of 2024"},
        {"cve_id": "CVE-2025-1234", "description": "Current latest CVE"},
    ]
    
    print(f"\n📊 Sample Data: {len(sample_vulnerabilities)} CVEs")
    
    # Simulate incremental detection
    last_processed = "CVE-2025-0050"  # Simulate we've processed up to CVE-2025-0050
    
    print(f"\n🎯 Last Processed CVE: {last_processed}")
    print("🔍 Finding incremental changes...")
    
    incremental_results = detector.find_incremental_changes(
        sample_vulnerabilities, last_processed
    )
    
    print(f"\n✅ Results:")
    print(f"   • Total CVEs in fresh data: {len(sample_vulnerabilities)}")
    print(f"   • New CVEs found: {len(incremental_results)}")
    print(f"   • Efficiency: {len(incremental_results)}/{len(sample_vulnerabilities)} = {(len(incremental_results)/len(sample_vulnerabilities)*100):.1f}% processed")
    
    print(f"\n📋 New CVEs to process:")
    for result in incremental_results:
        print(f"   • {result.cve_id} (confidence: {result.confidence_score})")

def demo_nvd_incremental_update():
    """Demonstrate NVD incremental update"""
    print("\n" + "=" * 50)
    print("🚀 NVD Incremental Update Demo")
    print("=" * 50)
    
    # Check if NVD data exists
    nvd_data_dir = "/Users/apple/Desktop/utility/vuln_db/nvd"
    
    if not os.path.exists(nvd_data_dir):
        print(f"⚠️  NVD data directory not found: {nvd_data_dir}")
        return
    
    try:
        # Initialize NVD updater
        nvd_updater = NVDIncrementalUpdater(nvd_data_dir)
        
        # Check current state
        latest_cve = nvd_updater.get_latest_processed_cve()
        print(f"📍 Current latest CVE: {latest_cve or 'None (first run)'}")
        
        # Get update statistics if available
        stats = nvd_updater.get_update_statistics()
        if stats:
            print(f"📊 Last Update Stats:")
            print(f"   • Source: {stats.get('source_name')}")
            print(f"   • Status: {stats.get('status')}")
            print(f"   • New CVEs: {stats.get('new_cves_found', 0)}")
            print(f"   • Duration: {stats.get('duration_seconds', 0):.2f}s")
        
        # Simulate what would happen on incremental update
        print(f"\n🔄 Simulating incremental update...")
        fresh_data = nvd_updater.load_fresh_vulnerability_data()
        
        if fresh_data:
            print(f"📥 Loaded {len(fresh_data):,} vulnerabilities from NVD files")
            
            # Find what would be new
            incremental_results = nvd_updater.detector.find_incremental_changes(
                fresh_data[:1000],  # Sample first 1000 for demo
                latest_cve
            )
            
            print(f"🎯 Incremental Detection Results:")
            print(f"   • Sample size: 1,000 CVEs")
            print(f"   • New CVEs found: {len(incremental_results)}")
            print(f"   • Efficiency gain: {((1000-len(incremental_results))/1000*100):.1f}% skipped")
            
            if incremental_results:
                latest_new = max(incremental_results, key=lambda r: nvd_updater.detector.parse_cve_id(r.cve_id))
                print(f"   • Latest new CVE: {latest_new.cve_id}")
        else:
            print("⚠️  No NVD data found")
            
    except Exception as e:
        print(f"❌ Error in NVD demo: {e}")

def demo_debian_incremental_update():
    """Demonstrate Debian incremental update"""
    print("\n" + "=" * 50)
    print("🐧 Debian Incremental Update Demo")
    print("=" * 50)
    
    # Check if Debian data exists
    debian_data_dir = "/Users/apple/Desktop/utility/vuln_db/sources/cve_compatible_os/debian"
    
    if not os.path.exists(debian_data_dir):
        print(f"⚠️  Debian data directory not found: {debian_data_dir}")
        return
    
    try:
        # Initialize Debian updater
        debian_updater = DebianIncrementalUpdater(debian_data_dir)
        
        # Check current state
        latest_cve = debian_updater.get_latest_processed_cve()
        print(f"📍 Current latest CVE: {latest_cve or 'None (first run)'}")
        
        # Load fresh Debian data
        print(f"\n🔄 Loading Debian Security Tracker data...")
        fresh_data = debian_updater.load_fresh_vulnerability_data()
        
        if fresh_data:
            print(f"📥 Loaded {len(fresh_data):,} vulnerabilities from Debian")
            
            # Sample for demo (Debian has a lot of data)
            sample_size = min(500, len(fresh_data))
            sample_data = fresh_data[:sample_size]
            
            # Find what would be new
            incremental_results = debian_updater.detector.find_incremental_changes(
                sample_data,
                latest_cve
            )
            
            print(f"🎯 Incremental Detection Results:")
            print(f"   • Sample size: {sample_size:,} CVEs")
            print(f"   • New CVEs found: {len(incremental_results)}")
            print(f"   • Efficiency gain: {((sample_size-len(incremental_results))/sample_size*100):.1f}% skipped")
            
            if incremental_results:
                # Show range of new CVEs
                cve_years = {}
                for result in incremental_results:
                    year = result.cve_id.split('-')[1] if '-' in result.cve_id else 'unknown'
                    cve_years[year] = cve_years.get(year, 0) + 1
                
                print(f"   • CVE distribution by year:")
                for year, count in sorted(cve_years.items()):
                    print(f"     - {year}: {count} CVEs")
                    
                latest_new = max(incremental_results, key=lambda r: debian_updater.detector.parse_cve_id(r.cve_id))
                print(f"   • Latest new CVE: {latest_new.cve_id}")
        else:
            print("⚠️  No Debian data found")
            
    except Exception as e:
        print(f"❌ Error in Debian demo: {e}")

def main():
    """Run all demos"""
    print("🎯 CVE ID-Based Incremental Detection System Demo")
    print("This demonstrates how simple CVE ID comparison replaces complex fingerprinting")
    print()
    
    # Run demos
    demo_cve_id_comparison()
    demo_nvd_incremental_update()  
    demo_debian_incremental_update()
    
    print("\n" + "=" * 50)
    print("✅ Demo completed!")
    print("\nKey Benefits of CVE ID-Based Approach:")
    print("  1. ⚡ FAST: No cryptographic hashing needed")
    print("  2. 🎯 ACCURATE: CVE IDs are naturally chronological")
    print("  3. 🔧 SIMPLE: Just string comparison")
    print("  4. 🌐 UNIVERSAL: Works for all vulnerability sources")
    print("  5. 📈 EFFICIENT: Only process genuinely new CVEs")

if __name__ == "__main__":
    main()