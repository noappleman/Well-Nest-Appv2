from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

def run_migration():
    """Add height, weight, and heart_rate columns to health_metrics table"""
    with app.app_context():
        # Connect to the database
        conn = db.engine.connect()
        
        # Check if columns already exist
        inspector = db.inspect(db.engine)
        columns = [col['name'] for col in inspector.get_columns('health_metrics')]
        
        # Add height column if it doesn't exist
        if 'height' not in columns:
            conn.execute('ALTER TABLE health_metrics ADD COLUMN height FLOAT')
            print("Added height column to health_metrics table")
        
        # Add weight column if it doesn't exist
        if 'weight' not in columns:
            conn.execute('ALTER TABLE health_metrics ADD COLUMN weight FLOAT')
            print("Added weight column to health_metrics table")
        
        # Add heart_rate column if it doesn't exist
        if 'heart_rate' not in columns:
            conn.execute('ALTER TABLE health_metrics ADD COLUMN heart_rate INTEGER')
            print("Added heart_rate column to health_metrics table")
        
        # Commit the transaction
        conn.close()
        print("Migration completed successfully")

if __name__ == '__main__':
    run_migration()
