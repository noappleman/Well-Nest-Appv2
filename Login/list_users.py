import os
from app import app, db, User

def list_users():
    """
    List all users in the database
    """
    print("Listing all users in the database...")
    
    try:
        with app.app_context():
            users = User.query.all()
            
            if not users:
                print("No users found in the database.")
                return
            
            print(f"Found {len(users)} user(s):")
            print("-" * 50)
            
            for user in users:
                print(f"ID: {user.id}")
                print(f"Username: {user.username}")
                print(f"Email: {user.email}")
                print(f"OTP Secret: {user.otp_secret}")
                print(f"Number of WebAuthn Credentials: {len(user.credentials)}")
                print("-" * 50)
                
    except Exception as e:
        print(f"Error retrieving users: {e}")

if __name__ == "__main__":
    # Set the DATABASE_URL environment variable for PostgreSQL
    os.environ['DATABASE_URL'] = 'postgresql:///login_db'
    
    # List users
    list_users()
