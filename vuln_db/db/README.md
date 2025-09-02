# Local Database Setup

Simplified setup for local PostgreSQL database installation and configuration for the Vulnerability Database system.

## Quick Setup

### 1. Run the Setup Script
```bash
# Make the script executable
chmod +x setup_local_db.sh

# Run the setup
./setup_local_db.sh
```

This script will:
- ✅ Check if PostgreSQL is installed
- 🚀 Start PostgreSQL service (if not running)
- 👤 Create database user (`vuln_user`)
- 🗄️ Create databases (`vulnerability_db` and `vulnerability_db_test`)
- 🔧 Install required PostgreSQL extensions
- 📋 Initialize database schema
- 🔍 Test the connection

### 2. Manual Database Initialization (Optional)
If you need to reinitialize the database schema:

```bash
# Test connection only
python3 init_database.py --test-only --environment development

# Initialize database schema
python3 init_database.py --environment development

# Force re-initialization
python3 init_database.py --environment development --force
```

## Database Configuration

The database uses settings from `config/schemas_and_config/database_settings.json`:

**Development Environment:**
- Host: `localhost`
- Port: `5432`
- Database: `vulnerability_db`
- Username: `vuln_user`
- Password: `vuln_pass`

## Environment Variables (Optional)

You can override default settings with environment variables:

```bash
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=vulnerability_db
export DB_USER=vuln_user
export DB_PASSWORD=your_password
export ENVIRONMENT=development
```

## Testing the Setup

After setup, test your database connection:

```bash
# Using the init script
python3 init_database.py --test-only

# Using psql directly
psql -h localhost -U vuln_user -d vulnerability_db -c "\l"
```

## Troubleshooting

### PostgreSQL Not Installed
```bash
# macOS (Homebrew)
brew install postgresql
brew services start postgresql

# Ubuntu/Debian
sudo apt-get install postgresql postgresql-contrib
sudo systemctl start postgresql

# CentOS/RHEL
sudo yum install postgresql postgresql-server
sudo systemctl start postgresql
```

### Permission Issues
If you get permission errors, ensure the PostgreSQL user has proper privileges:

```sql
-- Connect as postgres user
sudo -u postgres psql

-- Grant privileges
ALTER USER vuln_user CREATEDB;
GRANT ALL PRIVILEGES ON DATABASE vulnerability_db TO vuln_user;
```

### Connection Issues
1. Check if PostgreSQL is running: `pg_isready -h localhost -p 5432`
2. Verify configuration in `config/schemas_and_config/database_settings.json`
3. Check environment variables: `echo $DB_PASSWORD`

## File Structure

```
db/
├── setup_local_db.sh        # Main setup script
├── init_database.py         # Database initialization
└── README.md               # This file
```

## Next Steps

After successful setup:
1. ✅ Database is ready for use
2. 🔧 Configure your application to use the database
3. 🚀 Start developing with the vulnerability database system
4. 📊 Use the database migration tools in `db_schema/migrations/` if needed