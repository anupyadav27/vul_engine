#!/usr/bin/env python3
"""
Quick test script to evaluate enhanced vulnerability agent's NVD database coverage
"""

import sys
import os
sys.path.append('.')

from vul_agent import VulnerabilityAgent

def test_nvd_coverage():
    print("Testing Enhanced Vulnerability Agent - NVD Database Coverage")
    print("=" * 60)
    
    agent = VulnerabilityAgent('agent_config.json')
    packages = agent.discover_packages()
    
    print(f"Total packages discovered: {len(packages)}")
    print()
    
    # Group by package manager/type
    manager_stats = {}
    for pkg in packages:
        manager = pkg.get('manager', 'unknown')
        if manager not in manager_stats:
            manager_stats[manager] = []
        manager_stats[manager].append(pkg)
    
    print("Package discovery breakdown:")
    print("-" * 40)
    
    for manager, pkgs in sorted(manager_stats.items()):
        print(f"{manager:15} : {len(pkgs):4d} packages")
        # Show sample packages
        for i, pkg in enumerate(pkgs[:3]):
            print(f"                  └─ {pkg['name']} {pkg['version']}")
        if len(pkgs) > 3:
            print(f"                  └─ ... and {len(pkgs) - 3} more")
        print()
    
    # Evaluate NVD coverage potential
    print("NVD Database Coverage Assessment:")
    print("-" * 40)
    
    high_nvd_coverage = ['dpkg', 'rpm', 'pip', 'npm', 'gem']
    medium_nvd_coverage = ['homebrew', 'system', 'cargo']
    low_nvd_coverage = ['macports', 'flatpak', 'snap', 'go_modules']
    
    high_count = sum(len(manager_stats.get(mgr, [])) for mgr in high_nvd_coverage)
    medium_count = sum(len(manager_stats.get(mgr, [])) for mgr in medium_nvd_coverage)
    low_count = sum(len(manager_stats.get(mgr, [])) for mgr in low_nvd_coverage)
    
    total = high_count + medium_count + low_count
    
    if total > 0:
        print(f"High NVD Coverage    : {high_count:4d} packages ({high_count/total*100:.1f}%)")
        print(f"Medium NVD Coverage  : {medium_count:4d} packages ({medium_count/total*100:.1f}%)")
        print(f"Low NVD Coverage     : {low_count:4d} packages ({low_count/total*100:.1f}%)")
        print()
        print(f"Overall NVD Coverage Estimate: {(high_count + medium_count*0.6)/total*100:.1f}%")

if __name__ == "__main__":
    test_nvd_coverage()