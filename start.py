#!/usr/bin/env python3
"""
Startup script for AI Security Analysis Tool Web Application
"""
import sys
import os
import subprocess
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        return False
    print(f"✅ Python {sys.version.split()[0]} detected")
    return True

def check_dependencies():
    """Check if required dependencies are installed."""
    required_packages = [
        'flask', 'pandas', 'requests', 'pathlib'
    ]

    missing = []
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)

    if missing:
        print(f"❌ Missing required packages: {', '.join(missing)}")
        print("Install with: pip install -r requirements.txt")
        return False

    print("✅ All required dependencies are installed")
    return True

def check_optional_dependencies():
    """Check optional dependencies and warn if missing."""
    optional_packages = {
        'rarfile': 'RAR archive support',
        'semgrep': 'Advanced security scanning (install separately: pip install semgrep)'
    }

    for package, description in optional_packages.items():
        try:
            __import__(package)
            print(f"✅ {package} available - {description}")
        except ImportError:
            print(f"⚠️ {package} not available - {description}")

def setup_environment():
    """Setup environment variables."""
    print("\n🔧 Environment Setup")
    print("-" * 30)

    # Check API key
    api_key = os.getenv('OPENROUTER_API_KEY')
    if api_key:
        print("✅ OPENROUTER_API_KEY is set")
    else:
        print("⚠️ OPENROUTER_API_KEY not set")
        print("   Set with: export OPENROUTER_API_KEY='your_key_here'")
        print("   Tool will work with limited functionality without it")

    # Set default model
    model = os.getenv('LLM_MODEL', 'anthropic/claude-3.5-sonnet')
    os.environ['LLM_MODEL'] = model
    print(f"✅ Model: {model}")

    # Set default max tokens  
    max_tokens = os.getenv('LLM_MAX_TOKENS', '1500')
    os.environ['LLM_MAX_TOKENS'] = max_tokens
    print(f"✅ Max Tokens: {max_tokens}")

def create_directories():
    """Create necessary directories."""
    directories = ['uploads', 'results', 'temp', 'logs']

    for directory in directories:
        Path(directory).mkdir(exist_ok=True)

    print("✅ Created necessary directories")

def check_vault_integration():
    """Check if vault analysis modules are available."""
    try:
        from orchestrator import AnalysisOrchestrator
        from utils import setup_logging
        print("✅ Vault analysis modules are available")
        return True
    except ImportError as e:
        print(f"❌ Vault integration issue: {e}")
        print("   Make sure you're running this from the correct directory")
        print("   The vault analysis modules should be in the parent directory")
        return False

def main():
    """Main startup function."""
    print("🚀 AI Security Analysis Tool - Web Application Startup")
    print("=" * 55)

    # Check system requirements
    if not check_python_version():
        sys.exit(1)

    if not check_dependencies():
        print("\nInstall missing dependencies and try again:")
        print("pip install -r requirements.txt")
        sys.exit(1)

    # Check optional dependencies
    check_optional_dependencies()

    # Setup environment
    setup_environment()

    # Create directories
    create_directories()

    # Check vault integration
    if not check_vault_integration():
        print("\n⚠️ Warning: Vault integration may not work properly")
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            sys.exit(1)

    print("\n" + "=" * 55)
    print("✅ All checks passed! Starting web application...")
    print("=" * 55)
    print()
    print("📱 Web Interface: http://localhost:5000")
    print("🔧 Configuration: Check config.py for settings")
    print("📁 Upload Formats: ZIP, RAR, TAR.GZ (code) | PDF, MD (reports)")
    print()
    print("Press Ctrl+C to stop the server")
    print("=" * 55)

    # Start the Flask app
    try:
        from app import app
        app.run(debug=False, host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down gracefully...")
    except Exception as e:
        print(f"\n❌ Error starting application: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
