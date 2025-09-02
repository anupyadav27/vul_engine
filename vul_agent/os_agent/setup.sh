#!/bin/bash
# Vulnerability Agent Setup Script

echo "Setting up Vulnerability Agent..."

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed."
    exit 1
fi

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

# Make the agent executable
chmod +x vul_agent.py

# Create log directory
mkdir -p logs

echo "Setup complete!"
echo ""
echo "Usage:"
echo "  Test system discovery: python3 vul_agent.py --test"
echo "  Run vulnerability scan: python3 vul_agent.py --scan"
echo "  Configure settings in: agent_config.json"
echo ""
echo "Make sure to:"
echo "1. Update the engine_url in agent_config.json"
echo "2. Set the correct api_key"
echo "3. Start the vul_engine server before running scans"