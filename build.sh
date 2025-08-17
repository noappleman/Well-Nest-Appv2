#!/bin/bash

# Create public directory if it doesn't exist
mkdir -p public

# Copy static assets from Login and Chat modules
echo "Copying static assets to public directory..."
cp -r Login/static/* public/ 2>/dev/null || true
cp -r Chat/static/* public/ 2>/dev/null || true

# Copy templates as static HTML files (optional)
mkdir -p public/templates
cp -r Login/templates/* public/templates/ 2>/dev/null || true
cp -r Chat/templates/* public/templates/ 2>/dev/null || true

echo "Build completed. Files are in the public directory."
