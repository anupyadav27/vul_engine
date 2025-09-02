#!/bin/bash
# Vulnerability Engine Setup Script

echo "Setting up Vulnerability Engine..."

# Check if Python 3.8+ is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3.8+ is required but not installed."
    exit 1
fi

# Check Python version
python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then 
    echo "Error: Python 3.8+ is required. Current version: $python_version"
    exit 1
fi

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

# Create environment file if it doesn't exist
if [ ! -f .env ]; then
    echo "Creating environment configuration file..."
    cp .env.example .env
    echo "Please edit .env file with your database credentials and API keys"
fi

# Create log directory
mkdir -p logs

# Make the engine executable
chmod +x main.py

echo "Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit .env file with your database credentials"
echo "2. Ensure PostgreSQL is running with vulnerability database"
echo "3. Update API keys in .env file"
echo "4. Start the engine: python3 main.py"
echo ""
echo "API Documentation will be available at:"
echo "  http://localhost:8000/api/docs (Swagger UI)"
echo "  http://localhost:8000/api/redoc (ReDoc)"
echo ""
echo "Health check: curl http://localhost:8000/health"