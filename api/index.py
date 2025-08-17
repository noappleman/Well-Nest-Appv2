from flask import Flask, redirect, url_for
import sys
import os

# Add parent directory to path so we can import from Login module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the Flask app from Login/app.py
try:
    from Login.app import app as flask_app
except ImportError:
    # Fallback to a simple app if import fails
    flask_app = Flask(__name__)
    
    @flask_app.route('/')
    def index():
        return redirect('/login')

# This is the entry point for Vercel
app = flask_app

# If running locally
if __name__ == '__main__':
    app.run(debug=True)
