"""
Migration script to add account lockout fields to the users table
"""
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os

# Create a minimal Flask app for migration
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

def run_migration():
    # Execute raw SQL to add columns if they don't exist
    with app.app_context():
        db.session.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER DEFAULT 0')
        db.session.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS account_locked_until TIMESTAMP')
        db.session.commit()
        print('Migration completed successfully')

if __name__ == '__main__':
    run_migration()
