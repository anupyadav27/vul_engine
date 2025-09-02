#!/bin/bash

# NVD Data Processing Launcher
# Simplified interface for the NVD orchestrator

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

# Change to the orchestration directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Function to run full NVD processing
run_full() {
    print_status "🚀 Starting Full NVD Processing Pipeline"
    print_status "This will download, parse, upload, update, and validate all NVD data (2002-2024)"
    print_warning "This process may take several hours and require significant disk space"
    
    read -p "Continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Full processing cancelled"
        exit 0
    fi
    
    python3 nvd_orchestrator.py --full
}

# Function to run incremental update
run_incremental() {
    local hours=${1:-24}
    print_status "🔄 Starting NVD Incremental Update (last $hours hours)"
    python3 nvd_orchestrator.py --incremental --since-hours $hours
}

# Function to run validation only
run_validation() {
    print_status "🔍 Running NVD Data Validation"
    python3 nvd_orchestrator.py --validate
}

# Function to show status
show_status() {
    print_status "📊 NVD Processing Status"
    python3 nvd_orchestrator.py --status
}

# Function to run repair mode
run_repair() {
    print_status "🔧 Running NVD Repair Mode"
    print_warning "This will detect and repair missing or corrupted data"
    python3 nvd_orchestrator.py --repair
}

# Function to run specific years
run_years() {
    local years=$1
    if [ -z "$years" ]; then
        print_error "Please specify years (e.g., 2020,2021,2022)"
        exit 1
    fi
    
    print_status "📅 Processing NVD data for years: $years"
    python3 nvd_orchestrator.py --full --years "$years"
}

# Function to run specific steps
run_steps() {
    local steps=$1
    if [ -z "$steps" ]; then
        print_error "Please specify steps (e.g., download,parse,upload)"
        exit 1
    fi
    
    print_status "🔧 Running NVD steps: $steps"
    python3 nvd_orchestrator.py --full --steps "$steps"
}

# Check database status first
check_database() {
    print_status "🔍 Checking database connection..."
    
    # Check if database container is running
    if ! docker ps | grep -q vuln_db_postgres; then
        print_error "Database container is not running!"
        print_status "Starting database container..."
        cd ../db
        ./deploy.sh deploy
        cd ../orchestration
        sleep 5
    else
        print_success "Database container is running"
    fi
}

# Display help
show_help() {
    echo "NVD Data Processing Launcher"
    echo ""
    echo "Usage: $0 COMMAND [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  full                    - Run complete NVD processing pipeline (2002-2024)"
    echo "  incremental [HOURS]     - Run incremental update (default: 24 hours)"
    echo "  validate               - Run data validation only"
    echo "  status                 - Show current processing status"
    echo "  repair                 - Run repair mode for missing/corrupted data"
    echo "  years YEAR_LIST        - Process specific years (e.g., 2020,2021,2022)"
    echo "  steps STEP_LIST        - Run specific steps (download,parse,upload,update,validate)"
    echo ""
    echo "Examples:"
    echo "  $0 full                     # Full processing pipeline"
    echo "  $0 incremental              # Last 24 hours updates"
    echo "  $0 incremental 48           # Last 48 hours updates"
    echo "  $0 years 2022,2023,2024     # Process 2022-2024 only"
    echo "  $0 steps download,parse     # Run download and parse steps only"
    echo "  $0 validate                 # Validate existing data"
    echo "  $0 status                   # Check processing status"
    echo ""
}

# Main script logic
case "$1" in
    full)
        check_database
        run_full
        ;;
    incremental)
        check_database
        run_incremental "$2"
        ;;
    validate)
        check_database
        run_validation
        ;;
    status)
        show_status
        ;;
    repair)
        check_database
        run_repair
        ;;
    years)
        if [ -z "$2" ]; then
            print_error "Please specify years (e.g., 2020,2021,2022)"
            exit 1
        fi
        check_database
        run_years "$2"
        ;;
    steps)
        if [ -z "$2" ]; then
            print_error "Please specify steps (e.g., download,parse,upload)"
            exit 1
        fi
        check_database
        run_steps "$2"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        print_error "Unknown command: $1"
        echo ""
        show_help
        exit 1
        ;;
esac