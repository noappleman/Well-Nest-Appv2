from app import app, db
from sqlalchemy import text
from flask.cli import with_appcontext

def add_profile_picture_column():
    """Add profile_picture column to users table."""
    with app.app_context():
        # Execute raw SQL to add the column if it doesn't exist
        db.session.execute(text('ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_picture VARCHAR(255);'))
        db.session.commit()
        print("Profile picture column added successfully.")

if __name__ == '__main__':
    add_profile_picture_column()
