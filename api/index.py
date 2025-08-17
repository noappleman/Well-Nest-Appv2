import sys
import os

# Add parent directory to path so we can import from Login module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the Flask app from Login/app.py with error handling
try:
    from Login.app import app
    print("Successfully imported app from Login/app.py")
except Exception as e:
    from flask import Flask, jsonify
    app = Flask(__name__)
    
    @app.route('/')
    def error_page():
        return jsonify({
            "error": "Failed to import main Flask app",
            "details": str(e)
        }), 500
    
    print(f"Error importing app: {str(e)}")

# For local development
if __name__ == '__main__':
    app.run(debug=True)
