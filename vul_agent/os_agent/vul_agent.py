#!/usr/bin/env python3
"""
Vulnerability Agent - Server-side vulnerability scanner
Discovers system components and reports to central vul_engine
"""

import os
import json
import platform
import subprocess
import requests
import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional
import hashlib
import socket

# Import local analyzer for hybrid mode
try:
    from local_analyzer import LocalVulnerabilityAnalyzer
    LOCAL_ANALYZER_AVAILABLE = True
except ImportError:
    LOCAL_ANALYZER_AVAILABLE = False
    logging.warning("Local analyzer not available - falling back to central analysis only")

class VulnerabilityAgent:
    def __init__(self, config_file: str = "agent_config.json"):
        self.config = self._load_config(config_file)
        self.setup_logging()
        self.agent_id = self._generate_agent_id()
        self.system_info = self._get_system_info()
        
        # Initialize local analyzer if enabled and available
        self.local_analyzer = None
        if (LOCAL_ANALYZER_AVAILABLE and 
            self.config.get('analysis_mode') in ['hybrid', 'local'] and 
            self.config.get('local_analysis', {}).get('enabled', False)):
            try:
                self.local_analyzer = LocalVulnerabilityAnalyzer(self.config)
                self.logger.info("Local vulnerability analyzer initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize local analyzer: {e}")
    
    def _load_config(self, config_file: str) -> Dict:
        """Load agent configuration"""
        default_config = {
            "engine_url": "http://localhost:8000",
            "api_key": "",
            "scan_interval": 3600,  # 1 hour
            "include_packages": True,
            "include_services": True,
            "include_ports": False,
            "offline_mode": False,
            "log_level": "INFO",
            "analysis_mode": "central",  # central, hybrid, local
            "local_analysis": {
                "enabled": False,
                "vuln_db_cache": True,
                "cache_update_interval": 86400,
                "severity_threshold": "MEDIUM"
            }
        }
        
        # Load from config file first
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
        
        # Override with environment variables (for Docker compatibility)
        if os.getenv('ENGINE_URL'):
            default_config['engine_url'] = os.getenv('ENGINE_URL')
        if os.getenv('API_KEY'):
            default_config['api_key'] = os.getenv('API_KEY')
        if os.getenv('SCAN_INTERVAL'):
            try:
                default_config['scan_interval'] = int(os.getenv('SCAN_INTERVAL'))
            except ValueError:
                pass
        if os.getenv('OFFLINE_MODE'):
            default_config['offline_mode'] = os.getenv('OFFLINE_MODE').lower() in ['true', '1', 'yes']
        if os.getenv('LOG_LEVEL'):
            default_config['log_level'] = os.getenv('LOG_LEVEL')
        if os.getenv('ANALYSIS_MODE'):
            default_config['analysis_mode'] = os.getenv('ANALYSIS_MODE')
        
        return default_config
    
    def setup_logging(self):
        """Setup logging configuration"""
        log_level = getattr(logging, self.config.get("log_level", "INFO").upper())
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('vul_agent.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def _generate_agent_id(self) -> str:
        """Generate unique agent ID based on system characteristics"""
        hostname = socket.gethostname()
        # Get MAC address
        mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                               for elements in range(0,2*6,2)][::-1])
        unique_string = f"{hostname}-{mac_address}-{platform.machine()}"
        return hashlib.md5(unique_string.encode()).hexdigest()[:16]
    
    def _get_system_info(self) -> Dict:
        """Get basic system information"""
        return {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "architecture": platform.architecture(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "agent_version": "1.0.0"
        }
    
    def discover_packages(self) -> List[Dict]:
        """Discover installed packages based on OS"""
        packages = []
        system = platform.system().lower()
        
        try:
            if system == "linux":
                packages.extend(self._discover_deb_packages())
                packages.extend(self._discover_rpm_packages())
                packages.extend(self._discover_pip_packages())
                packages.extend(self._discover_snap_packages())
                # Enhanced Linux package discovery
                packages.extend(self._discover_flatpak_packages())
                packages.extend(self._discover_npm_packages())
                packages.extend(self._discover_gem_packages())
                packages.extend(self._discover_cargo_packages())
                packages.extend(self._discover_go_packages())
                packages.extend(self._discover_system_libraries())
            elif system == "darwin":  # macOS
                packages.extend(self._discover_brew_packages())
                packages.extend(self._discover_pip_packages())
                packages.extend(self._discover_port_packages())
                # Enhanced macOS package discovery
                packages.extend(self._discover_npm_packages())
                packages.extend(self._discover_gem_packages())
                packages.extend(self._discover_cargo_packages())
                packages.extend(self._discover_go_packages())
                packages.extend(self._discover_macos_applications())
            elif system == "windows":
                packages.extend(self._discover_windows_packages())
                packages.extend(self._discover_pip_packages())
                # Enhanced Windows package discovery
                packages.extend(self._discover_chocolatey_packages())
                packages.extend(self._discover_scoop_packages())
                packages.extend(self._discover_npm_packages())
                packages.extend(self._discover_nuget_packages())
        
        except Exception as e:
            self.logger.error(f"Error discovering packages: {e}")
        
        return packages
    
    def _discover_deb_packages(self) -> List[Dict]:
        """Discover Debian/Ubuntu packages"""
        packages = []
        try:
            result = subprocess.run(['dpkg', '-l'], capture_output=True, text=True, timeout=30)
            for line in result.stdout.split('\n')[5:]:  # Skip header lines
                if line.strip() and line.startswith('ii'):
                    parts = line.split()
                    if len(parts) >= 3:
                        packages.append({
                            "name": parts[1],
                            "version": parts[2],
                            "type": "deb",
                            "manager": "dpkg"
                        })
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.debug(f"dpkg not available or timeout: {e}")
        except Exception as e:
            self.logger.debug(f"dpkg error: {e}")
        
        return packages
    
    def _discover_rpm_packages(self) -> List[Dict]:
        """Discover RPM packages (RedHat/CentOS/Fedora)"""
        packages = []
        try:
            result = subprocess.run(['rpm', '-qa', '--queryformat', '%{NAME}|%{VERSION}-%{RELEASE}\n'], 
                                  capture_output=True, text=True, timeout=30)
            for line in result.stdout.strip().split('\n'):
                if '|' in line:
                    name, version = line.split('|', 1)
                    packages.append({
                        "name": name,
                        "version": version,
                        "type": "rpm",
                        "manager": "rpm"
                    })
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.debug(f"rpm not available or timeout: {e}")
        except Exception as e:
            self.logger.debug(f"rpm error: {e}")
        
        return packages
    
    def _discover_pip_packages(self) -> List[Dict]:
        """Discover Python packages"""
        packages = []
        try:
            result = subprocess.run(['pip', 'list', '--format=json'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                pip_packages = json.loads(result.stdout)
                for pkg in pip_packages:
                    packages.append({
                        "name": pkg['name'],
                        "version": pkg['version'],
                        "type": "python",
                        "manager": "pip"
                    })
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as e:
            self.logger.debug(f"pip list failed: {e}")
        except Exception as e:
            self.logger.debug(f"pip error: {e}")
        
        return packages
    
    def _discover_brew_packages(self) -> List[Dict]:
        """Discover Homebrew packages (macOS)"""
        packages = []
        try:
            result = subprocess.run(['brew', 'list', '--versions'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            packages.append({
                                "name": parts[0],
                                "version": parts[1],
                                "type": "brew",
                                "manager": "homebrew"
                            })
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.debug(f"brew not available or timeout: {e}")
        except Exception as e:
            self.logger.debug(f"brew error: {e}")
        
        return packages
    
    def _discover_port_packages(self) -> List[Dict]:
        """Discover MacPorts packages (macOS)"""
        packages = []
        try:
            result = subprocess.run(['port', 'installed'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n')[1:]:  # Skip header
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            packages.append({
                                "name": parts[0],
                                "version": parts[1],
                                "type": "port",
                                "manager": "macports"
                            })
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.debug(f"port not available or timeout: {e}")
        except Exception as e:
            self.logger.debug(f"port error: {e}")
        
        return packages
    
    def _discover_snap_packages(self) -> List[Dict]:
        """Discover Snap packages (Linux)"""
        packages = []
        try:
            result = subprocess.run(['snap', 'list'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n')[1:]:  # Skip header
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            packages.append({
                                "name": parts[0],
                                "version": parts[1],
                                "type": "snap",
                                "manager": "snapd"
                            })
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.debug(f"snap not available or timeout: {e}")
        except Exception as e:
            self.logger.debug(f"snap error: {e}")
        
        return packages
    
    def _discover_windows_packages(self) -> List[Dict]:
        """Discover Windows packages"""
        packages = []
        try:
            # Use PowerShell to get installed programs
            cmd = 'Get-WmiObject -Class Win32_Product | Select-Object Name, Version | ConvertTo-Json'
            result = subprocess.run(['powershell', '-Command', cmd], 
                                  capture_output=True, text=True, timeout=60)
            if result.stdout:
                win_packages = json.loads(result.stdout)
                if isinstance(win_packages, dict):
                    win_packages = [win_packages]
                
                for pkg in win_packages:
                    if pkg.get('Name') and pkg.get('Version'):
                        packages.append({
                            "name": pkg['Name'],
                            "version": pkg['Version'],
                            "type": "windows",
                            "manager": "wmi"
                        })
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            self.logger.debug(f"Windows package discovery failed: {e}")
        except Exception as e:
            self.logger.debug(f"Windows package error: {e}")
        
        return packages
    
    def discover_services(self) -> List[Dict]:
        """Discover running services"""
        services = []
        system = platform.system().lower()
        
        try:
            if system == "linux":
                services.extend(self._discover_systemd_services())
            elif system == "darwin":
                services.extend(self._discover_launchd_services())
            elif system == "windows":
                services.extend(self._discover_windows_services())
        except Exception as e:
            self.logger.error(f"Error discovering services: {e}")
        
        return services
    
    def _discover_systemd_services(self) -> List[Dict]:
        """Discover systemd services (Linux)"""
        services = []
        try:
            result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=active', '--no-pager'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.split('\n')[1:]:  # Skip header
                    if '.service' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            services.append({
                                "name": parts[0].replace('.service', ''),
                                "status": parts[2],
                                "type": "systemd",
                                "description": ' '.join(parts[4:]) if len(parts) > 4 else ""
                            })
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.debug(f"systemctl not available or timeout: {e}")
        except Exception as e:
            self.logger.debug(f"systemctl error: {e}")
        
        return services
    
    def _discover_launchd_services(self) -> List[Dict]:
        """Discover launchd services (macOS)"""
        services = []
        try:
            result = subprocess.run(['launchctl', 'list'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.split('\n')[1:]:  # Skip header
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            services.append({
                                "name": parts[2],
                                "status": "running" if parts[0] != "-" else "stopped",
                                "type": "launchd",
                                "description": parts[2]
                            })
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.debug(f"launchctl not available or timeout: {e}")
        except Exception as e:
            self.logger.debug(f"launchctl error: {e}")
        
        return services
    
    def _discover_windows_services(self) -> List[Dict]:
        """Discover Windows services"""
        services = []
        try:
            cmd = 'Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, Status, DisplayName | ConvertTo-Json'
            result = subprocess.run(['powershell', '-Command', cmd], 
                                  capture_output=True, text=True, timeout=60)
            if result.stdout:
                win_services = json.loads(result.stdout)
                if isinstance(win_services, dict):
                    win_services = [win_services]
                
                for svc in win_services:
                    if svc.get('Name'):
                        services.append({
                            "name": svc['Name'],
                            "status": svc.get('Status', 'unknown'),
                            "type": "windows_service",
                            "description": svc.get('DisplayName', '')
                        })
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            self.logger.debug(f"Windows service discovery failed: {e}")
        except Exception as e:
            self.logger.debug(f"Windows service error: {e}")
        
        return services
    
    # Enhanced package discovery methods for better NVD coverage
    def _discover_flatpak_packages(self) -> List[Dict]:
        """Discover Flatpak packages (Linux)"""
        packages = []
        try:
            result = subprocess.run(['flatpak', 'list', '--app', '--columns=name,version'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n')[1:]:  # Skip header
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            packages.append({
                                "name": parts[0],
                                "version": parts[1] if parts[1] else "unknown",
                                "type": "flatpak",
                                "manager": "flatpak"
                            })
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.debug(f"flatpak not available or timeout: {e}")
        except Exception as e:
            self.logger.debug(f"flatpak error: {e}")
        
        return packages
    
    def _discover_npm_packages(self) -> List[Dict]:
        """Discover Node.js packages"""
        packages = []
        try:
            # Global packages
            result = subprocess.run(['npm', 'list', '-g', '--depth=0', '--json'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                npm_data = json.loads(result.stdout)
                dependencies = npm_data.get('dependencies', {})
                for name, info in dependencies.items():
                    packages.append({
                        "name": name,
                        "version": info.get('version', 'unknown'),
                        "type": "nodejs",
                        "manager": "npm"
                    })
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as e:
            self.logger.debug(f"npm not available or failed: {e}")
        except Exception as e:
            self.logger.debug(f"npm error: {e}")
        
        return packages
    
    def _discover_gem_packages(self) -> List[Dict]:
        """Discover Ruby gems"""
        packages = []
        try:
            result = subprocess.run(['gem', 'list', '--local'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip() and '(' in line:
                        name = line.split('(')[0].strip()
                        version = line.split('(')[1].split(')')[0].strip()
                        packages.append({
                            "name": name,
                            "version": version,
                            "type": "ruby",
                            "manager": "gem"
                        })
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.debug(f"gem not available or timeout: {e}")
        except Exception as e:
            self.logger.debug(f"gem error: {e}")
        
        return packages
    
    def _discover_cargo_packages(self) -> List[Dict]:
        """Discover Rust packages"""
        packages = []
        try:
            # Check installed cargo packages
            result = subprocess.run(['cargo', 'install', '--list'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                current_package = None
                for line in result.stdout.strip().split('\n'):
                    if line and not line.startswith(' '):
                        if ' v' in line:
                            parts = line.split(' v')
                            if len(parts) >= 2:
                                packages.append({
                                    "name": parts[0],
                                    "version": parts[1].split(':')[0],
                                    "type": "rust",
                                    "manager": "cargo"
                                })
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.debug(f"cargo not available or timeout: {e}")
        except Exception as e:
            self.logger.debug(f"cargo error: {e}")
        
        return packages
    
    def _discover_go_packages(self) -> List[Dict]:
        """Discover Go packages"""
        packages = []
        try:
            # Go modules in current workspace
            result = subprocess.run(['go', 'list', '-m', 'all'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip() and ' ' in line:
                        parts = line.split(' ')
                        if len(parts) >= 2:
                            packages.append({
                                "name": parts[0],
                                "version": parts[1],
                                "type": "go",
                                "manager": "go_modules"
                            })
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.debug(f"go not available or timeout: {e}")
        except Exception as e:
            self.logger.debug(f"go error: {e}")
        
        return packages
    
    def _discover_system_libraries(self) -> List[Dict]:
        """Discover system libraries (Linux)"""
        packages = []
        try:
            # Check shared libraries
            result = subprocess.run(['ldconfig', '-p'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                seen_libs = set()
                for line in result.stdout.strip().split('\n')[1:]:  # Skip header
                    if '=>' in line:
                        lib_info = line.split('=>')[0].strip()
                        if ' ' in lib_info:
                            lib_name = lib_info.split(' ')[0]
                            if lib_name not in seen_libs and lib_name.startswith('lib'):
                                seen_libs.add(lib_name)
                                # Extract version if available
                                version = "unknown"
                                if '.so.' in lib_name:
                                    version_part = lib_name.split('.so.')[-1]
                                    if version_part:
                                        version = version_part
                                
                                packages.append({
                                    "name": lib_name,
                                    "version": version,
                                    "type": "system_library",
                                    "manager": "ldconfig"
                                })
                                
                                # Limit to avoid too many results
                                if len(packages) >= 50:
                                    break
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.debug(f"ldconfig not available or timeout: {e}")
        except Exception as e:
            self.logger.debug(f"ldconfig error: {e}")
        
        return packages
    
    def _discover_macos_applications(self) -> List[Dict]:
        """Discover macOS applications"""
        packages = []
        try:
            # Scan /Applications directory
            apps_dir = '/Applications'
            if os.path.exists(apps_dir):
                for item in os.listdir(apps_dir):
                    if item.endswith('.app'):
                        app_name = item.replace('.app', '')
                        info_plist_path = os.path.join(apps_dir, item, 'Contents', 'Info.plist')
                        
                        version = "unknown"
                        try:
                            # Try to get version from Info.plist
                            result = subprocess.run(['plutil', '-p', info_plist_path], 
                                                  capture_output=True, text=True, timeout=5)
                            if result.returncode == 0:
                                for line in result.stdout.split('\n'):
                                    if 'CFBundleShortVersionString' in line:
                                        version = line.split('=>')[1].strip().strip('"')
                                        break
                        except:
                            pass
                        
                        packages.append({
                            "name": app_name,
                            "version": version,
                            "type": "macos_app",
                            "manager": "system"
                        })
        except Exception as e:
            self.logger.debug(f"macOS app discovery error: {e}")
        
        return packages
    
    def _discover_chocolatey_packages(self) -> List[Dict]:
        """Discover Chocolatey packages (Windows)"""
        packages = []
        try:
            result = subprocess.run(['choco', 'list', '--local-only'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if ' ' in line and not line.startswith('Chocolatey'):
                        parts = line.split(' ')
                        if len(parts) >= 2:
                            packages.append({
                                "name": parts[0],
                                "version": parts[1],
                                "type": "chocolatey",
                                "manager": "choco"
                            })
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.debug(f"chocolatey not available or timeout: {e}")
        except Exception as e:
            self.logger.debug(f"chocolatey error: {e}")
        
        return packages
    
    def _discover_scoop_packages(self) -> List[Dict]:
        """Discover Scoop packages (Windows)"""
        packages = []
        try:
            result = subprocess.run(['scoop', 'list'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n')[2:]:  # Skip headers
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            packages.append({
                                "name": parts[0],
                                "version": parts[1],
                                "type": "scoop",
                                "manager": "scoop"
                            })
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.debug(f"scoop not available or timeout: {e}")
        except Exception as e:
            self.logger.debug(f"scoop error: {e}")
        
        return packages
    
    def _discover_nuget_packages(self) -> List[Dict]:
        """Discover NuGet packages (Windows)"""
        packages = []
        try:
            # Check global packages
            result = subprocess.run(['dotnet', 'list', 'package', '--include-transitive'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if '>' in line and 'Package' in line:
                        # Parse NuGet package format
                        parts = line.split()
                        if len(parts) >= 3 and parts[0] == '>':
                            packages.append({
                                "name": parts[1],
                                "version": parts[2],
                                "type": "nuget",
                                "manager": "dotnet"
                            })
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.debug(f"dotnet not available or timeout: {e}")
        except Exception as e:
            self.logger.debug(f"dotnet/nuget error: {e}")
        
        return packages
    
    def perform_scan(self) -> Dict:
        """Perform complete vulnerability scan"""
        self.logger.info(f"Starting vulnerability scan for agent {self.agent_id}")
        
        scan_data = {
            "agent_id": self.agent_id,
            "timestamp": datetime.utcnow().isoformat(),
            "system_info": self.system_info,
            "packages": [],
            "services": [],
            "scan_duration": 0,
            "local_vulnerabilities": [],
            "analysis_mode": self.config.get('analysis_mode', 'central')
        }
        
        start_time = datetime.utcnow()
        
        # Discover packages
        if self.config.get("include_packages", True):
            self.logger.info("Discovering packages...")
            scan_data["packages"] = self.discover_packages()
            self.logger.info(f"Found {len(scan_data['packages'])} packages")
            
            # Perform local analysis if enabled
            if self.local_analyzer and self.config.get('analysis_mode') in ['hybrid', 'local']:
                local_vulns = self._perform_local_analysis(scan_data["packages"])
                scan_data["local_vulnerabilities"] = local_vulns
        
        # Discover services
        if self.config.get("include_services", True):
            self.logger.info("Discovering services...")
            scan_data["services"] = self.discover_services()
            self.logger.info(f"Found {len(scan_data['services'])} services")
        
        end_time = datetime.utcnow()
        scan_data["scan_duration"] = (end_time - start_time).total_seconds()
        
        return scan_data
    
    def _perform_local_analysis(self, packages: List[Dict]) -> List[Dict]:
        """Perform local vulnerability analysis"""
        if not self.local_analyzer:
            return []
        
        try:
            # Update cache if needed
            if self.local_analyzer.should_update_cache():
                self.logger.info("Updating local vulnerability cache...")
                success = self.local_analyzer.update_cache_from_engine(
                    self.config['engine_url'], 
                    self.config.get('api_key', '')
                )
                if not success:
                    self.logger.warning("Failed to update local cache - using existing cache")
            
            # Analyze packages locally
            vulnerabilities = self.local_analyzer.analyze_packages_locally(packages)
            
            # Log cache stats
            cache_stats = self.local_analyzer.get_cache_stats()
            self.logger.info(f"Local analysis complete. Cache: {cache_stats}")
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Local analysis failed: {e}")
            return []
    
    def send_scan_results(self, scan_data: Dict) -> Optional[Dict]:
        """Send scan results to vulnerability engine"""
        analysis_mode = self.config.get('analysis_mode', 'central')
        
        # In local-only mode, don't send to central engine
        if analysis_mode == 'local':
            self.logger.info("Local analysis mode - saving results locally only")
            self._save_offline_results(scan_data)
            return {
                "success": True,
                "analysis_mode": "local",
                "vulnerabilities_found": len(scan_data.get('local_vulnerabilities', [])),
                "message": "Local analysis completed"
            }
        
        if self.config.get("offline_mode", False):
            self.logger.info("Offline mode - saving results locally")
            self._save_offline_results(scan_data)
            return None
        
        try:
            url = f"{self.config['engine_url']}/api/v1/agents/scan"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.config.get('api_key', '')}"
            }
            
            response = requests.post(url, json=scan_data, headers=headers, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            
            # In hybrid mode, combine local and central results
            if analysis_mode == 'hybrid' and scan_data.get('local_vulnerabilities'):
                local_count = len(scan_data['local_vulnerabilities'])
                central_count = result.get('vulnerabilities_found', 0)
                
                result['local_vulnerabilities_found'] = local_count
                result['central_vulnerabilities_found'] = central_count
                result['total_vulnerabilities_found'] = local_count + central_count
                result['analysis_mode'] = 'hybrid'
                
                self.logger.info(f"Hybrid analysis: {local_count} local + {central_count} central = {local_count + central_count} total vulnerabilities")
            else:
                self.logger.info(f"Central analysis: {result.get('vulnerabilities_found', 0)} vulnerabilities found")
            
            return result
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to send scan results: {e}")
            self._save_offline_results(scan_data)
            return None
    
    def get_local_cache_status(self) -> Dict:
        """Get status of local vulnerability cache"""
        if not self.local_analyzer:
            return {"status": "disabled", "reason": "Local analyzer not available or not enabled"}
        
        return self.local_analyzer.get_cache_stats()
    
    def update_local_cache(self) -> bool:
        """Manually update local vulnerability cache"""
        if not self.local_analyzer:
            self.logger.warning("Local analyzer not available")
            return False
        
        return self.local_analyzer.update_cache_from_engine(
            self.config['engine_url'], 
            self.config.get('api_key', '')
        )
    
    def _save_offline_results(self, scan_data: Dict):
        """Save scan results locally when offline"""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(scan_data, f, indent=2)
        
        self.logger.info(f"Scan results saved offline: {filename}")
    
    def run_scan(self) -> Dict:
        """Run complete scan and send results"""
        try:
            # Perform scan
            scan_data = self.perform_scan()
            
            # Send results to engine
            result = self.send_scan_results(scan_data)
            
            return {
                "success": True,
                "scan_data": scan_data,
                "engine_response": result
            }
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }

def main():
    """Main entry point for vulnerability agent"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Vulnerability Agent')
    parser.add_argument('--config', default='agent_config.json', help='Configuration file path')
    parser.add_argument('--scan', action='store_true', help='Run vulnerability scan')
    parser.add_argument('--daemon', action='store_true', help='Run as daemon')
    parser.add_argument('--test', action='store_true', help='Test system discovery')
    
    args = parser.parse_args()
    
    agent = VulnerabilityAgent(args.config)
    
    if args.scan:
        result = agent.run_scan()
        print(json.dumps(result, indent=2))
    
    elif args.test:
        print("Testing system discovery...")
        packages = agent.discover_packages()
        services = agent.discover_services()
        
        print(f"\nSystem Info:")
        print(json.dumps(agent.system_info, indent=2))
        
        print(f"\nPackages found: {len(packages)}")
        if packages:
            print("Sample packages:")
            for pkg in packages[:5]:
                print(f"  {pkg['name']} {pkg['version']} ({pkg['manager']})")
        
        print(f"\nServices found: {len(services)}")
        if services:
            print("Sample services:")
            for svc in services[:5]:
                print(f"  {svc['name']} - {svc['status']} ({svc['type']})")
    
    elif args.daemon:
        # TODO: Implement daemon mode with periodic scanning
        agent.logger.info("Daemon mode not yet implemented")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()