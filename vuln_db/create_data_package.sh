#!/bin/bash

# Script to create data package for partner
# This packages essential files needed for partner setup

set -e

PACKAGE_NAME="vuln_data_package"
PACKAGE_FILE="${PACKAGE_NAME}.tar.gz"

echo "📦 Creating vulnerability data package for partner..."

# Create temporary directory
mkdir -p ${PACKAGE_NAME}

# Copy essential data files
echo "📋 Copying essential data files..."

# Database backup
cp vuln_db_backup.sql.gz ${PACKAGE_NAME}/

# Source configuration files
cp vulnerability_sources.json ${PACKAGE_NAME}/
cp vulnerability_sources_simple.json ${PACKAGE_NAME}/
cp interest_datasource_final.json ${PACKAGE_NAME}/

# Database configuration
cp -r config/schemas_and_config ${PACKAGE_NAME}/config/

# Sample processed data (smaller subset)
mkdir -p ${PACKAGE_NAME}/nvd/output
cp nvd/output/*.json ${PACKAGE_NAME}/nvd/output/ 2>/dev/null || echo "No output files found"

# Reports
mkdir -p ${PACKAGE_NAME}/reports
cp reports/*.json ${PACKAGE_NAME}/reports/ 2>/dev/null || echo "No report files found"

# Source configurations
mkdir -p ${PACKAGE_NAME}/sources
find sources/ -name "config.json" -exec cp {} ${PACKAGE_NAME}/sources/ \;

# Create README for package
cat > ${PACKAGE_NAME}/README.md << 'EOF'
# Vulnerability Database Data Package

## Contents
- `vuln_db_backup.sql.gz` - Complete database with 266K+ CVEs (230MB)
- `vulnerability_sources.json` - Complete list of 49 vulnerability sources
- `vulnerability_sources_simple.json` - Simplified source list by category
- `interest_datasource_final.json` - Source analysis and priority mapping
- `config/` - Database configuration files
- `nvd/output/` - Sample processed data
- `reports/` - Analysis reports
- `sources/` - Source configuration templates

## Quick Setup
1. Extract this package in your vul_engine/vuln_db/ directory
2. Follow PARTNER_DATA_SETUP.md for complete setup instructions
3. Use vuln_db_backup.sql.gz to restore the database

## Database Stats
- 266,369 CVEs from NVD
- 2,558,637 CPE matches
- Multiple vulnerability sources integrated
- Complete database schema and indexes
EOF

# Create compressed package
echo "🗜️ Creating compressed package..."
tar -czf ${PACKAGE_FILE} ${PACKAGE_NAME}

# Clean up temporary directory
rm -rf ${PACKAGE_NAME}

# Show package info
PACKAGE_SIZE=$(du -h ${PACKAGE_FILE} | cut -f1)
echo ""
echo "✅ Data package created successfully!"
echo ""
echo "📦 Package details:"
echo "   File: ${PACKAGE_FILE}"
echo "   Size: ${PACKAGE_SIZE}"
echo ""
echo "🚀 Next steps:"
echo "   1. Upload ${PACKAGE_FILE} to file sharing service"
echo "   2. Share download link with partner"
echo "   3. Partner follows PARTNER_DATA_SETUP.md"
echo ""
echo "💡 Recommended upload locations:"
echo "   - Google Drive"
echo "   - Dropbox"
echo "   - GitHub Releases"
echo "   - AWS S3"
echo ""
echo "🔗 Update PARTNER_DATA_SETUP.md with the download link"
