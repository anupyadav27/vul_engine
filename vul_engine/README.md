# Vulnerability Engine API

A FastAPI-based central engine for vulnerability management that processes scan results from agents and provides comprehensive vulnerability analysis and reporting.

## Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   vul_agent     │    │   vul_engine    │    │   vuln_db       │
│  (Target Server)│◄──►│ (Central API)   │◄──►│ (PostgreSQL)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Features

- **Agent Management**: Register and manage vulnerability scanning agents
- **Scan Processing**: Process scan results and match against vulnerability database
- **Vulnerability Analysis**: Advanced CVE matching with version comparison
- **Reporting & Analytics**: Executive, compliance, and technical reports
- **Real-time API**: RESTful API with automatic documentation
- **Security**: API key authentication and CORS protection
- **Database Integration**: PostgreSQL with asyncpg for high performance

## Quick Start

1. **Setup the engine:**
   ```bash
   cd vul_engine
   ./setup.sh
   ```

2. **Configure environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your database credentials and API keys
   ```

3. **Start the server:**
   ```bash
   python3 main.py
   ```

4. **Access API documentation:**
   - Swagger UI: http://localhost:8000/api/docs
   - ReDoc: http://localhost:8000/api/redoc

## API Endpoints

### Agent Management
- `POST /api/v1/agents/register` - Register new agent
- `POST /api/v1/agents/scan` - Submit scan results
- `GET /api/v1/agents` - List all agents
- `GET /api/v1/agents/{agent_id}` - Get agent details

### Scan Management
- `GET /api/v1/scans` - Get scan history
- `GET /api/v1/scans/{scan_id}` - Get scan details
- `GET /api/v1/scans/stats/summary` - Scan statistics

### Vulnerability Analysis
- `GET /api/v1/vulnerabilities` - Search vulnerabilities
- `GET /api/v1/vulnerabilities/{cve_id}` - CVE details
- `GET /api/v1/vulnerabilities/stats/severity` - Severity statistics
- `GET /api/v1/vulnerabilities/stats/trending` - Trending vulnerabilities

### Reporting
- `GET /api/v1/reports/dashboard` - Dashboard summary
- `GET /api/v1/reports/executive` - Executive report
- `GET /api/v1/reports/compliance` - Compliance report
- `GET /api/v1/reports/technical` - Technical report

## Configuration

Environment variables (set in `.env`):

```bash
# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=vulnerability_db
DB_USER=vuln_user
DB_PASSWORD=vuln_pass

# Server
HOST=0.0.0.0
PORT=8000
DEBUG=false

# Security
API_KEYS=["your-secret-api-key"]
SECRET_KEY=your-secret-key

# Scanning
SEVERITY_THRESHOLD=MEDIUM
MAX_CONCURRENT_SCANS=5
```

## Integration with Existing Components

### With vul_agent
The engine receives scan data from agents via the `/api/v1/agents/scan` endpoint:

```python
# Agent configuration (agent_config.json)
{
  "engine_url": "http://localhost:8000",
  "api_key": "your-secret-api-key"
}
```

### With vuln_db
The engine connects to your existing PostgreSQL vulnerability database and creates additional tables for:
- Agent registration and tracking
- Scan result storage
- Vulnerability-to-scan mappings

## Vulnerability Matching Algorithm

The engine implements sophisticated vulnerability matching:

1. **Package Discovery**: Processes packages from agent scans
2. **Database Query**: Searches CVE database by package name
3. **Version Analysis**: Compares package versions against vulnerability ranges
4. **Severity Filtering**: Applies configurable severity thresholds
5. **Remediation**: Generates actionable remediation advice

## Security Features

- **API Key Authentication**: All endpoints require valid API keys
- **Input Validation**: Pydantic models ensure data integrity
- **CORS Protection**: Configurable cross-origin policies
- **SQL Injection Prevention**: Parameterized queries throughout

## Performance Optimizations

- **Async Architecture**: FastAPI with asyncpg for concurrent processing
- **Connection Pooling**: Database connection pool management
- **Background Processing**: Non-blocking scan analysis
- **Caching**: CVE data caching for improved response times

## Monitoring & Logging

- **Health Checks**: `/health` endpoint for monitoring
- **Structured Logging**: Comprehensive logging throughout
- **Error Handling**: Graceful error handling with proper HTTP codes
- **Metrics**: Built-in statistics and performance tracking

## Example Usage

### Submit Scan Results
```bash
curl -X POST "http://localhost:8000/api/v1/agents/scan" \
  -H "Authorization: Bearer your-secret-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-123",
    "timestamp": "2025-08-30T10:00:00",
    "system_info": {...},
    "packages": [...],
    "services": [...],
    "scan_duration": 45.2
  }'
```

### Get Vulnerability Report
```bash
curl -X GET "http://localhost:8000/api/v1/reports/dashboard" \
  -H "Authorization: Bearer your-secret-api-key"
```

## Development

### Running in Development Mode
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Testing
```bash
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run tests
pytest tests/
```

## Troubleshooting

### Common Issues

**Database Connection Errors:**
- Verify PostgreSQL is running
- Check database credentials in `.env`
- Ensure vulnerability database is initialized

**Agent Connection Issues:**
- Verify API keys match between agent and engine
- Check network connectivity
- Review engine logs for authentication errors

**Performance Issues:**
- Monitor database connection pool usage
- Check system resources during high-volume scanning
- Consider increasing `MAX_CONCURRENT_SCANS`

### Logs
Check `vul_engine.log` for detailed execution logs:
```bash
tail -f vul_engine.log
```

## License

This vulnerability engine is part of the vulnerability management system.