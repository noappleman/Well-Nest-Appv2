#!/bin/bash

# Create necessary directories
mkdir -p static

# Copy static assets from Login and Chat modules to static directory for Flask
echo "Copying static assets to static directory..."
cp -r Login/static/* static/ 2>/dev/null || true
cp -r Chat/static/* static/ 2>/dev/null || true

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Set up environment variables if .env file exists
if [ -f .env ]; then
    echo "Loading environment variables from .env file..."
    set -a
    source .env
    set +a
fi

echo "Build completed. Ready for Render deployment."
