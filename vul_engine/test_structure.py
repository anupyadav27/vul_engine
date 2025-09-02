#!/usr/bin/env python3
"""
Test script to verify vulnerability engine structure
"""

import os
import sys

def test_structure():
    """Test that all required files exist"""
    required_files = [
        'main.py',
        'requirements.txt',
        'setup.sh',
        '.env.example',
        'README.md',
        'core/__init__.py',
        'core/config.py',
        'core/auth.py',
        'core/database.py',
        'core/scanner.py',
        'api/__init__.py',
        'api/routes/__init__.py',
        'api/routes/agents.py',
        'api/routes/scans.py',
        'api/routes/vulnerabilities.py',
        'api/routes/reports.py'
    ]
    
    print("Checking vulnerability engine structure...")
    missing_files = []
    
    for file_path in required_files:
        if os.path.exists(file_path):
            print(f"✓ {file_path}")
        else:
            print(f"✗ {file_path}")
            missing_files.append(file_path)
    
    if missing_files:
        print(f"\nMissing files: {missing_files}")
        return False
    
    print("\n✓ All required files present!")
    return True

def test_python_syntax():
    """Test Python syntax of main files"""
    python_files = [
        'main.py',
        'core/config.py',
        'core/auth.py',
        'core/database.py',
        'core/scanner.py'
    ]
    
    print("\nChecking Python syntax...")
    for file_path in python_files:
        try:
            with open(file_path, 'r') as f:
                compile(f.read(), file_path, 'exec')
            print(f"✓ {file_path} - syntax OK")
        except SyntaxError as e:
            print(f"✗ {file_path} - syntax error: {e}")
            return False
        except Exception as e:
            print(f"? {file_path} - {e}")
    
    print("✓ Python syntax checks passed!")
    return True

if __name__ == "__main__":
    print("Vulnerability Engine Structure Test")
    print("=" * 40)
    
    structure_ok = test_structure()
    syntax_ok = test_python_syntax()
    
    if structure_ok and syntax_ok:
        print("\n🎉 Vulnerability Engine is ready!")
        print("\nNext steps:")
        print("1. Create a virtual environment: python3 -m venv venv")
        print("2. Activate it: source venv/bin/activate")
        print("3. Install dependencies: pip install -r requirements.txt")
        print("4. Copy .env.example to .env and configure")
        print("5. Start the engine: python3 main.py")
    else:
        print("\n❌ Setup incomplete - please check the errors above")
        sys.exit(1)