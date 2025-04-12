#!/usr/bin/env python3
"""
Python script to run LMTWT (for Windows compatibility and better cross-platform support)
"""
import os
import sys
import subprocess
import argparse
import platform

def setup_environment():
    """Check and setup the virtual environment."""
    # Determine if we're on Windows
    is_windows = platform.system().lower() == "windows"
    
    # Check if virtual environment exists
    venv_dir = "venv"
    venv_python = os.path.join(venv_dir, "Scripts", "python.exe") if is_windows else os.path.join(venv_dir, "bin", "python")
    venv_pip = os.path.join(venv_dir, "Scripts", "pip.exe") if is_windows else os.path.join(venv_dir, "bin", "pip")
    
    if not os.path.exists(venv_dir):
        print("Creating virtual environment...")
        try:
            subprocess.check_call([sys.executable, "-m", "venv", venv_dir])
        except subprocess.CalledProcessError as e:
            print(f"Error creating virtual environment: {e}")
            sys.exit(1)
    
    # Install requirements if needed
    req_marker = os.path.join(venv_dir, ".requirements_installed")
    if not os.path.exists(req_marker):
        print("Installing requirements...")
        try:
            subprocess.check_call([venv_pip, "install", "-r", "requirements.txt"])
            subprocess.check_call([venv_pip, "install", "-e", "."])
            # Create marker file
            with open(req_marker, "w") as f:
                f.write("")
        except subprocess.CalledProcessError as e:
            print(f"Error installing requirements: {e}")
            sys.exit(1)
    
    return venv_python

def run_lmtwt(venv_python, args):
    """Run the LMTWT application with provided arguments."""
    cmd = [venv_python, "src/main.py"] + args
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError as e:
        print(f"Error running LMTWT: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nLMTWT terminated by user.")
        sys.exit(0)

def main():
    """Main entry point."""
    print("LMTWT - Let Me Talk With Them")
    print("-----------------------------")
    
    # Setup environment
    venv_python = setup_environment()
    
    # Get arguments (skipping script name)
    args = sys.argv[1:]
    
    # Run LMTWT
    run_lmtwt(venv_python, args)

if __name__ == "__main__":
    main() 