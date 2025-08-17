"""
Migration script to add account lockout fields to the users table
"""
import os
import sys
import psycopg2
import sqlite3
from datetime import datetime

def run_migration():
    # Get database URL from environment
    database_url = os.environ.get('DATABASE_URL', '')
    
    if not database_url or database_url.startswith('sqlite'):
        # SQLite migration
        try:
            # Default SQLite path if not specified
            db_path = database_url.replace('sqlite:///', '') if database_url else 'instance/app.db'
            print(f"Running SQLite migration on {db_path}")
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Check if columns exist
            cursor.execute("PRAGMA table_info(users)")
            columns = [column[1] for column in cursor.fetchall()]
            
            # Add columns if they don't exist
            if 'failed_login_attempts' not in columns:
                cursor.execute('ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0')
                print("Added failed_login_attempts column")
                
            if 'account_locked_until' not in columns:
                cursor.execute('ALTER TABLE users ADD COLUMN account_locked_until TIMESTAMP')
                print("Added account_locked_until column")
                
            conn.commit()
            conn.close()
            print("SQLite migration completed successfully")
            
        except Exception as e:
            print(f"SQLite migration error: {str(e)}")
            return False
    else:
        # PostgreSQL migration
        try:
            # Handle Heroku-style postgres:// URLs
            if database_url.startswith('postgres://'):
                database_url = database_url.replace('postgres://', 'postgresql://', 1)
            
            print(f"Running PostgreSQL migration")
            conn = psycopg2.connect(database_url)
            cursor = conn.cursor()
            
            # Check if columns exist
            cursor.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'users'
            """)
            columns = [column[0] for column in cursor.fetchall()]
            
            # Add columns if they don't exist
            if 'failed_login_attempts' not in columns:
                cursor.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER DEFAULT 0')
                print("Added failed_login_attempts column")
                
            if 'account_locked_until' not in columns:
                cursor.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS account_locked_until TIMESTAMP')
                print("Added account_locked_until column")
                
            conn.commit()
            conn.close()
            print("PostgreSQL migration completed successfully")
            
        except Exception as e:
            print(f"PostgreSQL migration error: {str(e)}")
            return False
    
    return True

if __name__ == '__main__':
    success = run_migration()
    sys.exit(0 if success else 1)
