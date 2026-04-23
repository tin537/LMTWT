#!/bin/bash

# Script to run LMTWT.
# Prefers uv (https://docs.astral.sh/uv/) when available; falls back to a
# manually-managed venv otherwise.

if command -v uv >/dev/null 2>&1; then
    exec uv run lmtwt "$@"
fi

# Fallback: classic venv workflow
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate

if [ ! -f "venv/.requirements_installed" ]; then
    echo "Installing requirements..."
    pip install -e .
    touch venv/.requirements_installed
fi

python -m lmtwt "$@"
