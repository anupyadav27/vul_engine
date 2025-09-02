# 🚀 Vulnerability Database Local Deployment Guide

## 📋 Prerequisites
- Docker and Docker Compose installed
- PostgreSQL client tools (psql, pg_dump)
- Git repository cloned

## 🔧 Quick Setup

### 1. Start Database Container
```bash
# Navigate to the vuln_db/db directory
cd vuln_db/db

# Start PostgreSQL container
docker-compose up -d

# Verify container is running
docker ps
```

### 2. Wait for Database to be Ready
```bash
# Wait about 10-15 seconds for PostgreSQL to fully start
# You can check logs with:
docker logs vuln_db_postgres
```

### 3. Restore Database from Dump
```bash
# Navigate back to vuln_db root
cd ..

# Restore the complete database
psql -h localhost -p 5432 -U vuln_user -d vulnerability_db < vuln_db_backup.sql

# If you get a password prompt, use: vuln_secure_pass
```

## 🗄️ Database Details
- **Host**: localhost
- **Port**: 5432
- **Database**: vulnerability_db
- **Username**: vuln_user
- **Password**: vuln_secure_pass

## 📊 What's Included in the Dump
- **Complete Database Schema** - All tables, indexes, triggers
- **NVD Data** - Government vulnerability database
- **Debian Security Tracker** - OS-specific vulnerabilities
- **Total CVEs**: 266,000+ vulnerabilities
- **Sources**: NVD (source_id: 4), Debian (source_id: 7)

## 🧪 Test Your Setup
```bash
# Navigate to Debian scripts
cd vuln_db/sources/cve_compatible_os/debian

# Test database connection
python3 step4_debian_incremental_updater.py

# Or run the full pipeline
python3 step1_debian_data_downloader.py
python3 step2_debian_parser.py
python3 step3_debian_full_uploader.py
```

## 🔍 Verify Database Content
```bash
# Connect to database
psql -h localhost -p 5432 -U vuln_user -d vulnerability_db

# Check CVE counts by source
SELECT source_id, COUNT(*) as cve_count FROM cves GROUP BY source_id;

# View sample NVD data
SELECT cve_id, description, severity FROM cves WHERE source_id = 4 LIMIT 5;

# View sample Debian data
SELECT cve_id, description, affected_packages FROM cves WHERE source_id = 7 LIMIT 5;

# Exit psql
\q
```

## 🚨 Troubleshooting

### Container Won't Start
```bash
# Check if port 5432 is already in use
lsof -i :5432

# Stop and remove existing containers
docker-compose down
docker-compose up -d
```

### Database Connection Failed
```bash
# Verify container is running
docker ps

# Check container logs
docker logs vuln_db_postgres

# Ensure password file exists
echo "localhost:5432:vulnerability_db:vuln_user:vuln_secure_pass" > /tmp/pgpassfile
chmod 600 /tmp/pgpassfile
```

### Permission Denied on Dump File
```bash
# Make sure you have read access
chmod 644 vuln_db_backup.sql
```

## 📁 File Structure After Setup
```
vuln_db/
├── db/
│   ├── docker-compose.yml
│   └── postgresql.conf
├── sources/
│   └── cve_compatible_os/
│       └── debian/
│           ├── step1_debian_data_downloader.py
│           ├── step2_debian_parser.py
│           ├── step3_debian_full_uploader.py
│           └── step4_debian_incremental_updater.py
├── config/
│   └── schemas_and_config/
├── vuln_db_backup.sql          # Full database dump
├── vuln_db_backup.sql.gz       # Compressed dump
└── README_DEPLOYMENT.md        # This file
```

## 🎯 Next Steps
1. **Verify Setup** - Run test scripts
2. **Explore Data** - Query database to understand structure
3. **Run Updates** - Execute incremental updates
4. **Develop** - Start building new features

## 📞 Support
If you encounter issues:
1. Check container logs: `docker logs vuln_db_postgres`
2. Verify database connection: `psql -h localhost -p 5432 -U vuln_user -d vulnerability_db`
3. Check file permissions and paths
4. Ensure Docker has sufficient resources (at least 2GB RAM recommended)

---
**Happy Coding! 🎉**
