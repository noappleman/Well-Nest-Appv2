from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///wellnest.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

def upgrade():
    """Add last_checkin_timestamp column to users table"""
    with app.app_context():
        with db.engine.connect() as conn:
            conn.execute(db.text('ALTER TABLE users ADD COLUMN last_checkin_timestamp DATETIME DEFAULT NULL;'))
            conn.commit()
        print("Added last_checkin_timestamp column to users table")

if __name__ == '__main__':
    upgrade()
