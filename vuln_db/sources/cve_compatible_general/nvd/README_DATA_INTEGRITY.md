# NVD Data Processing Orchestrator

## 🛡️ Data Integrity & Testing Guide

### Data Consistency Protection

Your NVD pipeline includes robust mechanisms to prevent data duplicates and maintain integrity:

#### Built-in Safeguards:
1. **UPSERT Operations**: Uses `ON CONFLICT (cve_id) DO UPDATE` to handle duplicates intelligently
2. **Source-Aware Updates**: Only updates data when it comes from the same source (NVD)
3. **Clean Relationship Data**: Removes old CPE matches and MITRE mappings before inserting new ones
4. **Transaction Safety**: All database operations use transactions with rollback capability

#### Test Mode Safeguards:
- **Limited Scope**: Test mode processes only current year by default
- **Record Limits**: Maximum 100 records in test mode (configurable)
- **Dry Run Option**: Parse data without writing to database
- **Backup Points**: Creates restoration points before test operations
- **Error Isolation**: Stops processing immediately on errors in test mode

## 🧪 Safe Testing Commands

### Test Mode Options

```bash
# Safe dry-run test (NO database writes)
./nvd_launcher.sh test 2024 50 true

# Limited database test (max 100 records)
./nvd_launcher.sh test 2024 100 false

# Test specific years with limits
./nvd_launcher.sh test 2023,2024 50 false

# Dry-run test for current year
python3 nvd_orchestrator.py --test --dry-run --limit-records 50
```

### Production Commands

```bash
# Check current status
./nvd_launcher.sh status

# Run incremental updates (safe for existing data)
./nvd_launcher.sh incremental

# Process specific years only
./nvd_launcher.sh years 2023,2024

# Full pipeline (use with caution)
./nvd_launcher.sh full
```

### Data Cleanup

```bash
# Remove test data (requires explicit confirmation)
./nvd_launcher.sh cleanup_test
```

## 🔍 Data Integrity Features

### 1. Duplicate Prevention
- CVE IDs are unique constraints in the database
- UPSERT operations prevent duplicate insertions
- Source-specific updates preserve data from other sources

### 2. Relationship Data Management
```sql
-- CPE matches are cleaned before insertion
DELETE FROM cpe_matches WHERE cve_id = $1

-- MITRE mappings are refreshed completely
DELETE FROM cve_mitre_techniques WHERE cve_id = $1
```

### 3. Source Isolation
- Each vulnerability source has its own ID
- Updates only affect data from the same source
- Cross-source conflicts are resolved intelligently

## 📊 Monitoring & Validation

### Real-time Monitoring
```bash
# Check processing status
./nvd_launcher.sh status

# Validate data integrity
./nvd_launcher.sh validate

# View processing logs
tail -f nvd_orchestrator.log
```

### Database Validation
The orchestrator automatically validates:
- Database connectivity before processing
- Schema integrity during operations
- Data quality after processing
- Performance metrics and error rates

## 🚨 Best Practices

### For Testing:
1. **Always start with dry-run mode**
2. **Use small record limits (≤100)**
3. **Test with recent years only**
4. **Monitor database size before/after**

### For Production:
1. **Start with incremental updates**
2. **Process specific years before full pipeline**
3. **Monitor error rates and performance**
4. **Backup database before major operations**

### Emergency Procedures:
1. **Stop processing**: `docker stop vuln_db_postgres`
2. **Restore backup**: Use database backup procedures
3. **Clean test data**: `./nvd_launcher.sh cleanup_test`

## 📈 Performance Expectations

### Test Mode (100 records):
- Duration: 30-60 seconds
- Database writes: Minimal
- Disk usage: ~10MB

### Full Processing (2002-2025):
- Duration: 2-6 hours
- Database writes: ~200,000+ CVEs
- Disk usage: ~5-10GB

### Incremental Updates (24h):
- Duration: 1-5 minutes
- Database writes: 10-100 CVEs
- Disk usage: ~10-50MB

## 🔧 Troubleshooting

### Common Issues:
1. **Port conflicts**: Ensure local PostgreSQL is stopped
2. **Memory issues**: Reduce batch sizes in large operations
3. **Network timeouts**: Check NVD API availability
4. **Disk space**: Ensure sufficient storage for downloads

### Recovery Commands:
```bash
# Restart database container
cd ../../../../db && ./deploy.sh restart

# Reset to known good state
./nvd_launcher.sh repair

# Check database integrity
./nvd_launcher.sh validate
```