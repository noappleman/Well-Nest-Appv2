# Direct import of the main Flask application
import os
import sys

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the app directly from Login/app.py
from Login.app import app

# This file serves as the entry point for Vercel
# No modifications to the original app
