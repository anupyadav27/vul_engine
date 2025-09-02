#!/bin/bash

# Vulnerability Database Docker Deployment Script
# Uses existing schema and config files from ../config/schemas_and_config

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
    print_success "Docker is running"
}

# Deploy the database
deploy() {
    print_status "🚀 Deploying Vulnerability Database Container..."
    
    # Create backups directory
    mkdir -p ./backups
    
    # Check if existing schema file exists
    if [ ! -f "../config/schemas_and_config/vulnerability_schema.sql" ]; then
        print_error "Schema file not found at ../config/schemas_and_config/vulnerability_schema.sql"
        exit 1
    fi
    
    print_success "Found existing schema file"
    
    # Build and start the container
    print_status "Building and starting database container..."
    docker-compose up -d --build
    
    # Wait for database to be ready
    print_status "Waiting for database to be ready..."
    timeout 60 bash -c 'until docker-compose exec -T vuln_db pg_isready -U vuln_user -d vulnerability_db; do sleep 2; done'
    
    if [ $? -eq 0 ]; then
        print_success "Database is ready!"
        print_status "Database connection details:"
        echo "  Host: localhost"
        echo "  Port: 5432"
        echo "  Database: vulnerability_db"
        echo "  Username: vuln_user"
        echo "  Password: vuln_secure_pass"
    else
        print_error "Database failed to start within 60 seconds"
        exit 1
    fi
}

# Stop the database
stop() {
    print_status "🛑 Stopping Vulnerability Database Container..."
    docker-compose down
    print_success "Database stopped"
}

# Restart the database
restart() {
    print_status "🔄 Restarting Vulnerability Database Container..."
    docker-compose restart
    print_success "Database restarted"
}

# Show status
status() {
    print_status "📊 Database Container Status:"
    docker-compose ps
    
    # Check if database is responding
    if docker-compose exec -T vuln_db pg_isready -U vuln_user -d vulnerability_db > /dev/null 2>&1; then
        print_success "Database is responding"
        
        # Show table count
        TABLE_COUNT=$(docker-compose exec -T vuln_db psql -U vuln_user -d vulnerability_db -t -c "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';" 2>/dev/null | tr -d ' ')
        echo "  Tables created: $TABLE_COUNT"
        
        # Show CVE count if table exists
        CVE_COUNT=$(docker-compose exec -T vuln_db psql -U vuln_user -d vulnerability_db -t -c "SELECT count(*) FROM cves;" 2>/dev/null | tr -d ' ' || echo "0")
        echo "  CVEs in database: $CVE_COUNT"
    else
        print_warning "Database is not responding"
    fi
}

# Clean up (remove container and volumes)
clean() {
    print_warning "⚠️  This will remove the database container and all data!"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "🧹 Cleaning up database container and volumes..."
        docker-compose down -v
        docker system prune -f
        print_success "Cleanup completed"
    else
        print_status "Cleanup cancelled"
    fi
}

# Show logs
logs() {
    print_status "📋 Database Container Logs:"
    docker-compose logs -f vuln_db
}

# Main script logic
case "$1" in
    deploy)
        check_docker
        deploy
        ;;
    stop)
        stop
        ;;
    restart)
        restart
        ;;
    status)
        status
        ;;
    logs)
        logs
        ;;
    clean)
        clean
        ;;
    *)
        echo "Vulnerability Database Docker Management"
        echo ""
        echo "Usage: $0 {deploy|stop|restart|status|logs|clean}"
        echo ""
        echo "Commands:"
        echo "  deploy  - Build and start the database container"
        echo "  stop    - Stop the database container"
        echo "  restart - Restart the database container"
        echo "  status  - Show container status and database info"
        echo "  logs    - Show container logs"
        echo "  clean   - Remove container and all data (WARNING: destructive)"
        echo ""
        exit 1
        ;;
esac