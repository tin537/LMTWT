#!/bin/bash

# Script to run LMTWT with default settings

# Check if virtual environment exists, create if not
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install requirements if needed
if [ ! -f "venv/.requirements_installed" ]; then
    echo "Installing requirements..."
    pip install -r requirements.txt
    pip install -e .
    touch venv/.requirements_installed
fi

# Run the application
python src/main.py "$@" 