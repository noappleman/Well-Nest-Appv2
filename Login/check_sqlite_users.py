import sqlite3

def check_sqlite_users():
    """
    Check users in SQLite database
    """
    print("Checking users in SQLite database...")
    
    try:
        # Connect to SQLite database
        conn = sqlite3.connect('instance/db.sqlite3')
        cursor = conn.cursor()
        
        # Query users
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print(f"Tables in SQLite database: {tables}")
        
        try:
            cursor.execute("SELECT id, username, email FROM user")
            users = cursor.fetchall()
            
            if not users:
                print("No users found in SQLite database.")
                return
            
            print(f"Found {len(users)} user(s) in SQLite database:")
            print("-" * 50)
            
            for user in users:
                user_id, username, email = user
                print(f"ID: {user_id}")
                print(f"Username: {username}")
                print(f"Email: {email}")
                print("-" * 50)
                
        except sqlite3.OperationalError as e:
            print(f"Error querying users: {e}")
            
        # Close connection
        conn.close()
                
    except Exception as e:
        print(f"Error connecting to SQLite database: {e}")

if __name__ == "__main__":
    check_sqlite_users()
