# Partner Data Setup Guide

## 📦 Essential Data Files for Partner

Your partner needs these key data files to get started quickly:

### **🎯 High Priority Files (Must Have)**
1. **`vuln_db_backup.sql.gz`** (230MB) - Complete database with 266K+ CVEs
2. **`vulnerability_sources.json`** - Complete list of 49 vulnerability sources
3. **`vulnerability_sources_simple.json`** - Simplified source list by category
4. **`interest_datasource_final.json`** - Source analysis and priority mapping

### **🔧 Configuration Files (Important)**
1. **`vuln_db/config/schemas_and_config/vulnerability_schema.sql`** - Database schema
2. **`vuln_db/config/schemas_and_config/database_settings.json`** - DB config
3. **`vuln_db/config/schemas_and_config/pgadmin_servers.json`** - PgAdmin settings

### **📊 Sample Data Files (Useful)**
1. **`vuln_db/nvd/output/`** - Sample processed data
2. **`vuln_db/reports/`** - Analysis reports
3. **Source config files** - Template configurations

## 🚀 Quick Setup for Partner

### Step 1: Clone Repository
```bash
git clone https://github.com/anupyadav27/vul_engine.git
cd vul_engine
```

### Step 2: Download Data Package
```bash
# Download the data package (you'll provide this link)
wget https://your-file-sharing-service.com/vuln_data_package.tar.gz
tar -xzf vuln_data_package.tar.gz
```

### Step 3: Setup Database
```bash
cd vuln_db/db
docker-compose up -d
sleep 15
```

### Step 4: Restore Database
```bash
cd ..
psql -h localhost -p 5432 -U vuln_user -d vulnerability_db < vuln_db_backup.sql.gz
```

## 📋 File Sharing Options

### Option A: File Sharing Service
- Upload to Google Drive, Dropbox, or similar
- Share download link with partner
- Include in repository README

### Option B: Docker Hub (Recommended)
- Create Docker image with data
- Partner can pull and use immediately
- No manual file downloads needed

### Option C: Compressed Archive
- Create tar.gz with essential files
- Upload to GitHub releases
- Partner downloads and extracts

## 📁 Data Package Contents

```
vuln_data_package/
├── vuln_db_backup.sql.gz          # Complete database (230MB)
├── vulnerability_sources.json     # Source configuration
├── vulnerability_sources_simple.json
├── interest_datasource_final.json
├── config/
│   └── schemas_and_config/        # Database configuration
├── nvd/output/                    # Sample processed data
└── reports/                       # Analysis reports
```

## 🔄 Alternative: Fresh Data Download

If partner prefers fresh data:
```bash
cd vuln_db/nvd
python run_initial_load.py  # Downloads fresh NVD data
```

This will take 2-3 hours but ensures latest data.
