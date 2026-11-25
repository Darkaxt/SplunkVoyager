#!/usr/bin/env python3

import os
import sys
import subprocess
import shutil
import platform
import webbrowser
import time
from pathlib import Path

# Define base directories
BASE_DIR = Path(__file__).resolve().parent
VENV_DIR = os.path.join(BASE_DIR, 'venv')
REQUIREMENTS_FILE = os.path.join(BASE_DIR, 'requirements.txt')
MONITORS_DIR = os.path.join(BASE_DIR, 'monitors')

def create_requirements_file():
    """Create requirements.txt file if it doesn't exist"""
    if not os.path.exists(REQUIREMENTS_FILE):
        print("Creating requirements.txt file...")
        
        with open(REQUIREMENTS_FILE, 'w') as f:
            f.write("""
flask>=2.0,<2.3
werkzeug>=2.0,<2.3
waitress>=2.1
requests>=2.26
psutil>=5.9
openpyxl>=3.1
windows-curses>=2.3; sys_platform == "win32"
            """.strip())
        
        print("requirements.txt created successfully.")

def setup_virtual_environment():
    """Set up a Python virtual environment"""
    print("Setting up Python virtual environment...")
    
    if os.path.exists(VENV_DIR):
        print("Virtual environment already exists.")
        return
    
    try:
        subprocess.check_call([sys.executable, '-m', 'venv', VENV_DIR])
        print("Virtual environment created successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error creating virtual environment: {e}")
        sys.exit(1)

def install_dependencies():
    """Install Python dependencies"""
    print("Installing dependencies...")
    
    # Determine pip path based on platform
    if platform.system() == 'Windows':
        pip_path = os.path.join(VENV_DIR, 'Scripts', 'pip')
    else:
        pip_path = os.path.join(VENV_DIR, 'bin', 'pip')
    
    try:
        subprocess.check_call([pip_path, 'install', '-r', REQUIREMENTS_FILE])
        print("Dependencies installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error installing dependencies: {e}")
        sys.exit(1)

def ensure_directories():
    """Ensure required directories exist"""
    print("Ensuring required directories exist...")
    
    # Create data directories
    os.makedirs(os.path.join(BASE_DIR, 'data'), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, 'data', 'cookies'), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, 'data', 'logs'), exist_ok=True)
    
    # Create monitors directory for the terminal UI
    os.makedirs(MONITORS_DIR, exist_ok=True)
    
    # Create __init__.py in monitors directory if it doesn't exist
    init_file = os.path.join(MONITORS_DIR, "__init__.py")
    if not os.path.exists(init_file):
        with open(init_file, 'w') as f:
            f.write("# Terminal monitor package\n")
    
    print("Directories created successfully.")

def copy_userscript():
    """Copy userscript to static directory"""
    print("Copying userscript to static directory...")
    
    source = os.path.join(BASE_DIR, 'SplunkVoyager Cookie Extractor-0.1.user.js')
    destination = os.path.join(BASE_DIR, 'app', 'static')
    
    # Create static directory if it doesn't exist
    os.makedirs(destination, exist_ok=True)
    
    if os.path.exists(source):
        shutil.copy2(source, destination)
        print("Userscript copied successfully.")
    else:
        print("Userscript not found. Skipping.")

def start_application(use_terminal_ui=False):
    """Start the application"""
    print("Starting SplunkVoyager...")
    
    # Determine python path based on platform
    if platform.system() == 'Windows':
        python_path = os.path.join(VENV_DIR, 'Scripts', 'python')
    else:
        python_path = os.path.join(VENV_DIR, 'bin', 'python')
    
    try:
        # Start the application in a separate process
        # Add terminal_ui flag if requested
        cmd = [python_path, 'run.py']
        if use_terminal_ui:
            cmd.append('--terminal-ui')
            
        process = subprocess.Popen(cmd)
        
        # Wait for the server to start
        print("Waiting for server to start...")
        time.sleep(2)
        
        # Only open browser if not using terminal UI
        if not use_terminal_ui:
            webbrowser.open('http://localhost:8080')
        
        print("SplunkVoyager is running. Press Ctrl+C to stop.")
        
        # Wait for the process to complete
        process.wait()
    except KeyboardInterrupt:
        print("\nStopping SplunkVoyager...")
        process.terminate()
        process.wait()
        print("SplunkVoyager stopped.")
    except subprocess.CalledProcessError as e:
        print(f"Error starting application: {e}")
        sys.exit(1)

def main():
    """Main setup function"""
    print("=== SplunkVoyager Setup ===")
    
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description='Set up SplunkVoyager')
    parser.add_argument('--terminal-ui', action='store_true', 
                       help='Start with terminal UI monitor instead of web interface')
    args = parser.parse_args()
    
    # Create requirements.txt file if it doesn't exist
    create_requirements_file()
    
    # Setup virtual environment
    setup_virtual_environment()
    
    # Install dependencies
    install_dependencies()
    
    # Ensure required directories exist
    ensure_directories()
    
    # Copy userscript to static directory
    copy_userscript()
    
    # Start the application (with terminal UI if requested)
    start_application(use_terminal_ui=args.terminal_ui)

if __name__ == '__main__':
    main()