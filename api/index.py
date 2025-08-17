import sys
import os

# Add parent directory to path so we can import from Login module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the Flask app from Login/app.py
try:
    from Login.app import app
    print("Successfully imported app from Login/app.py")
except Exception as e:
    from flask import Flask
    app = Flask(__name__)
    
    @app.route('/')
    def error_page():
        return f"<h1>Error importing Flask app</h1><p>Error: {str(e)}</p>"
    
    print(f"Error importing app: {str(e)}")

# For local development
if __name__ == '__main__':
    app.run(debug=True)
