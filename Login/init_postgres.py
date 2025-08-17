import os
import sqlite3
from datetime import datetime
from dotenv import load_dotenv
from app import app, db, User, WebAuthnCredential

def migrate_from_sqlite(sqlite_path):
    """Migrate data from SQLite to PostgreSQL"""
    print("Starting migration from SQLite to PostgreSQL...")
    
    # Connect to SQLite database
    sqlite_conn = sqlite3.connect(sqlite_path)
    sqlite_conn.row_factory = sqlite3.Row
    sqlite_cur = sqlite_conn.cursor()
    
    with app.app_context():
        try:
            # Migrate users
            print("Migrating users...")
            sqlite_cur.execute('SELECT * FROM user')
            users_migrated = 0
            for row in sqlite_cur.fetchall():
                # Check if user already exists
                if not User.query.filter_by(id=row['id']).first():
                    user = User(
                        id=row['id'],
                        username=row['username'],
                        email=row['email'],
                        password_hash=row['password_hash'],
                        otp_secret=row['otp_secret'],
                        is_active=True,
                        created_at=datetime.now(),
                        updated_at=datetime.now()
                    )
                    db.session.add(user)
                    users_migrated += 1
            
            # Migrate WebAuthn credentials
            print("Migrating WebAuthn credentials...")
            # Check which table name exists in SQLite
            sqlite_cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%webauthn%'")
            webauthn_tables = sqlite_cur.fetchall()
            if webauthn_tables:
                webauthn_table = webauthn_tables[0][0]
                print(f"Found WebAuthn table: {webauthn_table}")
                sqlite_cur.execute(f'SELECT * FROM {webauthn_table}')
            else:
                print("No WebAuthn table found in SQLite database")
            creds_migrated = 0
            for row in sqlite_cur.fetchall():
                if not WebAuthnCredential.query.filter_by(id=row['id']).first():
                    credential = WebAuthnCredential(
                        id=row['id'],
                        user_id=row['user_id'],
                        credential_id=row['credential_id'],
                        public_key=row['public_key'],
                        sign_count=row['sign_count'],
                        transports=row['transports'],
                        created_at=datetime.now(),
                        updated_at=datetime.now()
                    )
                    db.session.add(credential)
                    creds_migrated += 1
            
            db.session.commit()
            print(f"Migration completed successfully!")
            print(f"Migrated {users_migrated} users and {creds_migrated} WebAuthn credentials.")
            
        except Exception as e:
            db.session.rollback()
            print(f"Error during migration: {str(e)}")
            raise
        finally:
            sqlite_conn.close()

def check_sqlite_db():
    """Check if SQLite database exists and has tables"""
    sqlite_path = os.path.join(os.path.dirname(__file__), 'db.sqlite3')
    if not os.path.exists(sqlite_path):
        sqlite_path = os.path.join(os.path.dirname(__file__), 'instance', 'db.sqlite3')
    
    if os.path.exists(sqlite_path):
        try:
            conn = sqlite3.connect(sqlite_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            conn.close()
            return sqlite_path, len(tables) > 0
        except Exception as e:
            print(f"Error checking SQLite database: {str(e)}")
    
    return None, False

def init_postgres():
    # Load environment variables
    load_dotenv()
    
    # Create all tables
    with app.app_context():
        print("Creating PostgreSQL database tables...")
        db.create_all()
        print("Database tables created successfully!")
        
        # Check if we need to migrate data from SQLite
        sqlite_path, has_tables = check_sqlite_db()
        if sqlite_path and has_tables:
            print(f"\nSQLite database found at {sqlite_path}.")
            print("Would you like to migrate data to PostgreSQL? (y/n)")
            if input().lower() == 'y':
                migrate_from_sqlite(sqlite_path)

if __name__ == '__main__':
    init_postgres()
