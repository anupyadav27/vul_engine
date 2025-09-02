# Vulnerability Agent

A lightweight vulnerability scanner agent that discovers system components and reports to the central vulnerability engine.

## Features

- **Multi-Platform Support**: Works on Linux, macOS, and Windows
- **Package Discovery**: Detects packages from multiple package managers:
  - Linux: apt/dpkg, yum/rpm, snap, pip
  - macOS: Homebrew, MacPorts, pip
  - Windows: WMI installed programs, pip
- **Service Discovery**: Identifies running services
- **Secure Communication**: API key authentication with the engine
- **Offline Mode**: Can cache results when engine is unavailable
- **Configurable**: JSON-based configuration

## Quick Start

1. **Setup the agent:**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

2. **Configure the agent:**
   Edit `agent_config.json` to set your engine URL and API key:
   ```json
   {
     "engine_url": "http://your-engine-server:8000",
     "api_key": "your-secret-api-key"
   }
   ```

3. **Test system discovery:**
   ```bash
   python3 vul_agent.py --test
   ```

4. **Run a vulnerability scan:**
   ```bash
   python3 vul_agent.py --scan
   ```

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `engine_url` | URL of the vulnerability engine API | `http://localhost:8000` |
| `api_key` | API key for authentication | `""` |
| `scan_interval` | Scan interval in seconds (for daemon mode) | `3600` |
| `include_packages` | Include package discovery | `true` |
| `include_services` | Include service discovery | `true` |
| `include_ports` | Include port scanning (future) | `false` |
| `offline_mode` | Save results locally if engine unavailable | `false` |
| `log_level` | Logging level (DEBUG, INFO, WARNING, ERROR) | `INFO` |

## Usage

### Command Line Options

```bash
python3 vul_agent.py [OPTIONS]

Options:
  --config FILE    Configuration file path (default: agent_config.json)
  --scan          Run vulnerability scan
  --test          Test system discovery without sending to engine
  --daemon        Run as daemon (future feature)
  --help          Show help message
```

### Examples

**Test system discovery:**
```bash
python3 vul_agent.py --test
```

**Run scan with custom config:**
```bash
python3 vul_agent.py --config /path/to/config.json --scan
```

**Enable offline mode for testing:**
```bash
# Edit agent_config.json to set "offline_mode": true
python3 vul_agent.py --scan
```

## Output

The agent discovers and reports:

### System Information
- Hostname and platform details
- Architecture and processor info
- Python version and agent version

### Packages
- Package name and version
- Package type (deb, rpm, brew, pip, etc.)
- Package manager used

### Services
- Service name and status
- Service type (systemd, launchd, windows_service)
- Service description

## Integration with Vulnerability Engine

The agent communicates with the vulnerability engine via REST API:

1. **POST /api/v1/agent/scan** - Submit scan results
2. Receives vulnerability analysis and recommendations
3. Logs results and optionally saves offline

## Troubleshooting

### Common Issues

**"Command not found" errors:**
- The agent gracefully handles missing package managers
- Install the package manager or disable discovery in config

**Permission denied:**
- Some commands may require elevated privileges
- Run with appropriate permissions for your system

**Network connectivity:**
- Check `engine_url` in configuration
- Verify API key is correct
- Enable `offline_mode` for testing without engine

### Logs

Check `vul_agent.log` for detailed execution logs:
```bash
tail -f vul_agent.log
```

## Security Considerations

- Store API keys securely
- Use HTTPS for production engine URLs
- Restrict agent execution permissions
- Review discovered data before transmission

## Platform-Specific Notes

### Linux
- Supports both Debian-based (apt) and Red Hat-based (yum/rpm) systems
- Requires appropriate permissions for systemctl commands
- Snap packages require snapd installation

### macOS
- Homebrew detection requires brew command
- MacPorts detection requires port command
- Some services may require admin privileges

### Windows
- Uses PowerShell for package and service discovery
- May require elevated permissions for WMI queries
- Performance may vary based on installed software

## Development

### Adding New Package Managers

1. Add detection method to the appropriate `_discover_*_packages()` function
2. Follow the standard package format:
   ```python
   {
       "name": "package_name",
       "version": "version_string", 
       "type": "package_type",
       "manager": "manager_name"
   }
   ```

### Testing

Run the test mode to verify discovery without engine connectivity:
```bash
python3 vul_agent.py --test
```

## License

This vulnerability agent is part of the vulnerability management system.