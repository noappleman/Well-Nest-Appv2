import os
import pyotp
import time
import re
import logging
import requests  # Add this import for making HTTP requests
import base64
import google.generativeai as genai  # Import Google Generative AI
import random  # For selecting random fallback responses
from datetime import datetime, timedelta
from threading import Thread
from flask import send_from_directory  # Add this import for making HTTP requests
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet

load_dotenv()  # Load environment variables from .env file
from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify, make_response, send_from_directory, abort
from flask_wtf.csrf import CSRFProtect
from markupsafe import escape
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json
import secrets
import string
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mailman import Mail, EmailMessage
from passlib.context import CryptContext
from itsdangerous import URLSafeTimedSerializer
import webauthn
from webauthn.helpers.structs import RegistrationCredential, AuthenticationCredential, UserVerificationRequirement, AuthenticatorSelectionCriteria, AuthenticatorAttachment
from webauthn.helpers import base64url_to_bytes
import base64
from flask_socketio import SocketIO, emit, join_room, leave_room
from jinja2 import ChoiceLoader, FileSystemLoader

def bytes_to_base64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('utf-8')

# App configuration
app = Flask(__name__)

# Generate or load Fernet key for chat encryption
def get_fernet_key():
    key_file = os.path.join(app.root_path, 'chat_key.key')
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            key = f.read()
    else:
        # Generate a new key
        key = Fernet.generate_key()
        # Save the key to a file
        with open(key_file, 'wb') as f:
            f.write(key)
    return key

# Initialize Fernet cipher
fernet_key = get_fernet_key()
cipher_suite = Fernet(fernet_key)

# Encryption and decryption functions
def encrypt_message(message):
    if not message:
        return ''
    try:
        # Convert string to bytes, encrypt, and return base64 string
        message_bytes = message.encode('utf-8')
        encrypted_bytes = cipher_suite.encrypt(message_bytes)
        return base64.b64encode(encrypted_bytes).decode('utf-8')
    except Exception as e:
        logging.error(f"Encryption error: {str(e)}")
        return message  # Return original message if encryption fails

def decrypt_message(encrypted_message):
    if not encrypted_message:
        return ''
    try:
        # Convert base64 string to bytes, decrypt, and return string
        encrypted_bytes = base64.b64decode(encrypted_message)
        decrypted_bytes = cipher_suite.decrypt(encrypted_bytes)
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        logging.error(f"Decryption error: {str(e)}")
        return encrypted_message  # Return encrypted message if decryption fails

# Configure Jinja2 to look for templates in multiple folders
app.jinja_loader = ChoiceLoader([
    app.jinja_loader,
    FileSystemLoader(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../Chat/templates'))
])

app.config['JSON_AS_ASCII'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-secret-key')

# Security configurations
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'  # Only in production
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max upload size

# PostgreSQL configuration
POSTGRES_USER = os.environ.get('POSTGRES_USER', 'isaac')
POSTGRES_PASSWORD = os.environ.get('POSTGRES_PASSWORD', '')
POSTGRES_DB = os.environ.get('POSTGRES_DB', 'login_db')
POSTGRES_HOST = os.environ.get('POSTGRES_HOST', 'localhost')
POSTGRES_PORT = os.environ.get('POSTGRES_PORT', '5432')

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', f'postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}

# Flask-Mailman configuration
app.config['MAIL_BACKEND'] = 'smtp'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587  # Port for TLS
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEFAULT_SENDER'] = 'wellnest51@gmail.com'  # Set default sender
app.config['MAIL_TIMEOUT'] = 60  # Increased timeout to allow for slower connections
app.config['MAIL_USERNAME'] = 'wellnest51@gmail.com'
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')  # Get from environment variable

# Security Logging Configuration
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '')
log_file = os.path.join(log_dir, 'security.log')

# Ensure log directory exists
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
security_logger = logging.getLogger('security')

# Input Validation Functions
def validate_username(username):
    """Validate username: only letters, numbers, and underscores, 3-20 chars"""
    if not username or len(username) < 3 or len(username) > 20:
        return False, "Username must be 3-20 characters long"
    if not re.match("^[a-zA-Z0-9_]+$", username):
        return False, "Username can only contain letters, numbers, and underscores"
    return True, "Valid"

def validate_email(email):
    """Validate email format"""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not email or not re.match(email_pattern, email):
        return False, "Invalid email format"
    if len(email) > 100:
        return False, "Email too long (max 100 characters)"
    return True, "Valid"

def validate_password(password):
    """Validate password strength"""
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if len(password) > 128:
        return False, "Password too long (max 128 characters)"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    return True, "Valid"

def sanitize_input(input_string):
    """Sanitize user input to prevent XSS"""
    if input_string is None:
        return ""
    return escape(input_string)

def allowed_file(filename, allowed_extensions=None):
    """Check if the file extension is allowed"""
    if allowed_extensions is None:
        allowed_extensions = {'png', 'jpg', 'jpeg'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions

def validate_image_mime(file_stream):
    """Validate that the file is actually an image by checking its MIME type"""
    try:
        # Read the first few bytes to determine file type
        file_stream.seek(0)
        header = file_stream.read(8)
        file_stream.seek(0)  # Reset file pointer
        
        # Check for JPEG signature (FF D8)
        if header.startswith(b'\xFF\xD8'):
            return 'image/jpeg'
        # Check for PNG signature (89 50 4E 47 0D 0A 1A 0A)
        elif header.startswith(b'\x89PNG\r\n\x1a\n'):
            return 'image/png'
        else:
            return None
    except Exception as e:
        app.logger.error(f"Error validating image MIME type: {str(e)}")
        return None

def log_security_event(event_type, username=None, ip_address=None, details=None):
    """Log security-related events"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'event_type': event_type,
        'username': username,
        'ip_address': ip_address,
        'details': details
    }
    security_logger.info(f"SECURITY_EVENT: {json.dumps(log_entry)}")

# Security headers
@app.after_request
def add_security_headers(response):
    # Only add security headers for HTML responses to avoid API issues
    if response.mimetype == 'text/html':
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Only add HSTS header in production and for HTTPS requests
        if os.environ.get('FLASK_ENV') == 'production' and request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.environ.get('REDIS_URL', 'memory://'),
    strategy="fixed-window",
    storage_options={"client": "memory"}
)

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Function to ensure database schema is up to date
def ensure_db_schema():
    try:
        with app.app_context():
            # Check if the columns exist in the users table
            inspector = db.inspect(db.engine)
            columns = [column['name'] for column in inspector.get_columns('users')]
            
            # Add failed_login_attempts column if it doesn't exist
            if 'failed_login_attempts' not in columns:
                app.logger.info("Adding failed_login_attempts column to users table")
                db.session.execute(db.text('ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0'))
            
            # Add account_locked_until column if it doesn't exist
            if 'account_locked_until' not in columns:
                app.logger.info("Adding account_locked_until column to users table")
                db.session.execute(db.text('ALTER TABLE users ADD COLUMN account_locked_until TIMESTAMP'))
            
            db.session.commit()
            app.logger.info("Database schema check completed successfully")
    except Exception as e:
        app.logger.error(f"Error during database schema check: {str(e)}")
        # Continue anyway - the error handling in the routes will handle missing columns

# Initialize CSRF protection
csrf = CSRFProtect(app)
login_manager.login_view = 'login'
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Ensure database schema is up to date
with app.app_context():
    ensure_db_schema()
    
# Secure route to serve protected JavaScript files
@app.route('/protected_js/<path:filename>')
def protected_js(filename):
    """Serve JavaScript files from protected directory with security checks"""
    # Only allow specific files to be served
    allowed_files = ['webauthn.js']
    
    if filename not in allowed_files:
        abort(404)  # Not found for any files not explicitly allowed
    
    # Check if user is authenticated or if this is a login-related request
    if not current_user.is_authenticated:
        # Check referer to ensure it's coming from our login page
        referer = request.headers.get('Referer', '')
        if not referer or not (('/login' in referer) or ('/register' in referer)):
            abort(403)  # Forbidden if not from login/register page
    
    # Set no-cache headers to prevent caching of these sensitive files
    response = send_from_directory(os.path.join(app.root_path, 'protected_assets'), filename)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# WebAuthn configuration
RP_ID = os.environ.get('WEBAUTHN_RP_ID', 'localhost')  # Domain name without protocol
RP_NAME = os.environ.get('WEBAUTHN_RP_NAME', 'Secure Login App')
ORIGIN = os.environ.get('WEBAUTHN_ORIGIN', 'http://localhost:5001')  # Full URL with protocol

# User model
class WebAuthnCredential(db.Model):
    __tablename__ = 'webauthn_credentials'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    credential_id = db.Column(db.LargeBinary, unique=True, nullable=False)
    public_key = db.Column(db.LargeBinary, nullable=False)
    sign_count = db.Column(db.Integer, nullable=False, default=0)
    transports = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    __table_args__ = (
            db.Index('idx_credential_user', 'user_id'),
        )

# Chat models
class ChatRequest(db.Model):
    __tablename__ = 'chat_requests'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_requests')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_requests')
    
    __table_args__ = (
        db.UniqueConstraint('sender_id', 'receiver_id', name='unique_chat_request'),
        db.Index('idx_chat_request_sender', 'sender_id'),
        db.Index('idx_chat_request_receiver', 'receiver_id'),
    )

class ChatMessage(db.Model):
    __tablename__ = 'chat_messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')
    
    __table_args__ = (
        db.Index('idx_chat_message_sender', 'sender_id'),
        db.Index('idx_chat_message_receiver', 'receiver_id'),
    )

class HealthMetric(db.Model):
    __tablename__ = 'health_metrics'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    systolic = db.Column(db.Integer, nullable=False)  # Systolic blood pressure
    diastolic = db.Column(db.Integer, nullable=False)  # Diastolic blood pressure
    blood_sugar = db.Column(db.Integer, nullable=False)  # Blood sugar level in mg/dL
    height = db.Column(db.Float, nullable=True)  # Height in cm
    weight = db.Column(db.Float, nullable=True)  # Weight in kg
    heart_rate = db.Column(db.Integer, nullable=True)  # Heart rate in bpm
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationship with User
    user = db.relationship('User', backref=db.backref('health_metrics', lazy=True, cascade='all, delete-orphan'))
    
    __table_args__ = (
        db.Index('idx_health_metric_user', 'user_id'),
        db.Index('idx_health_metric_date', 'created_at'),
    )
    
    @property
    def date(self):
        """Format the date for display"""
        return self.created_at.strftime('%Y-%m-%d %H:%M')


class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    title = db.Column(db.String(70), nullable=False)
    description = db.Column(db.String(150), nullable=False)
    category = db.Column(db.String(30), nullable=False)
    sessions = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, default=0.0)
    vacancy = db.Column(db.Integer, nullable=False)
    intensity = db.Column(db.String(20), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    event_date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    organizer = db.Column(db.String(50), nullable=False)
    contact = db.Column(db.String(100), nullable=False)
    image_path = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    user = db.relationship('User', backref=db.backref('events', lazy=True, cascade='all, delete-orphan'))
    # Add relationship to EventSignup
    signups = db.relationship('EventSignup', backref='event', lazy=True, cascade='all, delete-orphan')
    __table_args__ = (
        db.Index('idx_event_user', 'user_id'),
        db.Index('idx_event_date', 'event_date'),
        db.Index('idx_event_category', 'category'),
    )
    
    def formatted_date(self):
        """Format the date for display"""
        return self.event_date.strftime('%a, %d %b')
    
    def formatted_time(self):
        """Format the time range for display"""
        start = self.start_time.strftime('%I:%M %p').lower()
        end = self.end_time.strftime('%I:%M %p').lower()
        return f"{start} - {end}"
    
    def formatted_price(self):
        """Format the price for display"""
        return f"${self.price:.2f}"
    
    def get_signed_up_count(self):
        """Get the number of users signed up for this event"""
        return EventSignup.query.filter_by(event_id=self.id).count()
    
    def availability(self):
        """Format the availability for display"""
        signed_up = self.get_signed_up_count()
        available = self.vacancy - signed_up
        return f"{available} / {self.vacancy} available"
    
    def is_user_signed_up(self, user_id):
        """Check if a user is signed up for this event"""
        return EventSignup.query.filter_by(event_id=self.id, user_id=user_id).first() is not None


class EventSignup(db.Model):
    __tablename__ = 'event_signups'
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user = db.relationship('User', backref=db.backref('event_signups', lazy=True, cascade='all, delete-orphan'))
    __table_args__ = (
        db.UniqueConstraint('event_id', 'user_id', name='uq_event_signup'),
        db.Index('idx_event_signup_event', 'event_id'),
        db.Index('idx_event_signup_user', 'user_id'),
    )


# Clinic model for storing clinic information
class Clinic(db.Model):
    __tablename__ = 'clinics'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    opening_hours = db.Column(db.String(200), nullable=False)
    contact = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    specialties = db.Column(db.String(200), nullable=True)
    image_path = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    __table_args__ = (
        db.Index('idx_clinic_name', 'name'),
    )


class User(UserMixin, db.Model):
    __tablename__ = 'users'  # Explicit table name
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    email = db.Column(db.String(100), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128))
    otp_secret = db.Column(db.String(32), nullable=False, default=pyotp.random_base32)
    profile_picture = db.Column(db.String(255), nullable=True)  # Path to profile picture
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    # These columns might not exist in all environments yet
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=True)  # Track failed login attempts
    account_locked_until = db.Column(db.DateTime, nullable=True)  # Timestamp until account is locked
    
    credentials = db.relationship('WebAuthnCredential', backref=db.backref('user_ref', lazy='joined'), lazy=True,
                                cascade='all, delete-orphan', passive_deletes=True)
    
    __table_args__ = (
        db.Index('idx_user_username', 'username'),
        db.Index('idx_user_email', 'email'),
    )

    def set_password(self, password):
        self.password_hash = pwd_context.hash(password)

    def check_password(self, password):
        return pwd_context.verify(password, self.password_hash)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/check_checkin_status')
@login_required
def check_checkin_status():
    # Check for any check-ins today
    today = datetime.utcnow().date()
    log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'security.log')
    
    try:
        if os.path.exists(log_file_path):
            with open(log_file_path, 'r') as f:
                for line in reversed(list(f)):  # Read file in reverse to find most recent first
                    if 'SECURITY_EVENT' in line and 'daily_checkin' in line and f'"username": "{current_user.username}"' in line:
                        try:
                            # Extract the JSON part of the log line
                            json_str = line.split('SECURITY_EVENT: ')[1].strip()
                            log_data = json.loads(json_str)
                            
                            # Parse the timestamp from the log entry
                            log_time = datetime.fromisoformat(log_data['timestamp']).date()
                            
                            # If we found a check-in from today
                            if log_time == today:
                                return jsonify({'checked_in': True})
                            else:
                                # Found a check-in but it's from a previous day
                                return jsonify({'checked_in': False})
                        except (json.JSONDecodeError, KeyError, ValueError) as e:
                            app.logger.error(f"Error parsing log entry: {str(e)}")
                            continue
    except Exception as e:
        app.logger.error(f"Error checking check-in status: {str(e)}")
    
    return jsonify({'checked_in': False})

@app.route('/submit_feedback', methods=['POST'])
@login_required
def submit_feedback():
    try:
        data = request.get_json()
        feedback_type = data.get('type', 'daily_checkin')
        
        if feedback_type == 'daily_checkin':
            rating = data.get('rating')
            feedback = data.get('feedback', '')
            username = data.get('username', current_user.username)
            
            # Check for recent submissions (within last 5 minutes)
            five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
            log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'security.log')
            
            try:
                if os.path.exists(log_file_path):
                    with open(log_file_path, 'r') as f:
                        for line in reversed(list(f)):  # Read file in reverse to find most recent first
                            if 'SECURITY_EVENT' in line and 'daily_checkin' in line and f'"username": "{current_user.username}"' in line:
                                try:
                                    # Extract the JSON part of the log line
                                    json_str = line.split('SECURITY_EVENT: ')[1].strip()
                                    log_data = json.loads(json_str)
                                    
                                    # Parse the timestamp from the log entry
                                    log_time = datetime.fromisoformat(log_data['timestamp'])
                                    
                                    # If we found a matching log entry within the last 5 minutes, rate limit
                                    if log_time > five_minutes_ago:
                                        return jsonify({
                                            'status': 'error',
                                            'message': 'You can only submit your daily check-in once every 5 minutes.'
                                        }), 429
                                    else:
                                        # Found a log entry but it's older than 5 minutes, so we can proceed
                                        break
                                except (json.JSONDecodeError, KeyError, ValueError) as e:
                                    app.logger.error(f"Error parsing log entry: {str(e)}")
                                    continue
            except Exception as e:
                app.logger.error(f"Error checking rate limit: {str(e)}")
                # Continue with submission if there's an error checking the log file
            
            # Log the daily check-in
            log_security_event(
                event_type='daily_checkin',
                username=current_user.username,
                ip_address=request.remote_addr,
                details=f"Rating: {rating}, Feedback: {feedback}"
            )
            
            # Send email for negative feedback (rating 1-3)
            if rating and int(rating) <= 3 and feedback:
                send_feedback_email(username, rating, feedback)
            
            return jsonify({
                'status': 'success',
                'message': 'Thank you for your feedback!',
                'rating': rating
            })
            
        elif feedback_type == 'website_feedback':
            name = data.get('name', 'Anonymous')
            email = data.get('email', 'No email provided')
            message = data.get('message', '')
            
            if not message:
                return jsonify({
                    'status': 'error',
                    'message': 'Please provide a message.'
                }), 400
            
            # Log the website feedback
            log_security_event(
                event_type='website_feedback',
                username=current_user.username,
                ip_address=request.remote_addr,
                details=f"From: {name} <{email}>, Message: {message}"
            )
            
            # Send email for website feedback
            try:
                subject = f"[WellNest] Website Feedback from {name}"
                body = f"""
                <h2>New Website Feedback</h2>
                <p><strong>User Account:</strong> {current_user.username}</p>
                <p><strong>Name:</strong> {name}</p>
                <p><strong>Email:</strong> {email}</p>
                <p><strong>Message:</strong></p>
                <p>{message}</p>
                """
                
                msg = EmailMessage(
                    subject=subject,
                    body=body,
                    from_email=app.config['MAIL_USERNAME'],
                    to=['wellnest51@gmail.com']
                )
                msg.content_subtype = 'html'
                msg.send()
                
            except Exception as e:
                app.logger.error(f"Error sending feedback email: {str(e)}")
                # Don't fail the request if email fails
            
            return jsonify({
                'status': 'success',
                'message': 'Thank you for your feedback! We appreciate your input.'
            })
    except Exception as e:
        app.logger.error(f"Error submitting feedback: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'An error occurred while submitting your feedback.'
        }), 500

def send_feedback_email(username, rating, feedback):
    """Send feedback email to the support team."""
    try:
        subject = f"[WellNest] User Feedback - Rating: {rating}/5"
        body = f"""
        <h2>New User Feedback</h2>
        <p><strong>User:</strong> {username}</p>
        <p><strong>Rating:</strong> {rating}/5</p>
        <p><strong>Feedback:</strong></p>
        <p>{feedback}</p>
        """
        
        # Create a new EmailMessage with explicit settings
        msg = EmailMessage(
            subject=subject,
            body=body,
            from_email=app.config.get('MAIL_USERNAME'),
            to=['wellnest51@gmail.com']
        )
        msg.content_subtype = 'html'  # Ensure HTML content type
        
        # Send the email asynchronously with improved error handling
        def send_async_email(app, msg):
            with app.app_context():
                try:
                    msg.send()
                    app.logger.info(f"Feedback email sent successfully to wellnest51@gmail.com")
                except Exception as e:
                    app.logger.error(f"Error sending feedback email: {str(e)}")
                    # Log detailed error for debugging
                    app.logger.error(f"Email configuration: Server={app.config.get('MAIL_SERVER')}, Port={app.config.get('MAIL_PORT')}, TLS={app.config.get('MAIL_USE_TLS')}")
        
        # Start a new thread to send the email
        email_thread = Thread(target=send_async_email, args=(app._get_current_object(), msg))
        email_thread.daemon = True  # Make thread daemon so it doesn't block app shutdown
        email_thread.start()
        app.logger.info(f"Started email sending thread for feedback from {username}")
        
    except Exception as e:
        app.logger.error(f"Error preparing feedback email: {str(e)}")
        # Log the full traceback for better debugging
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")


@app.route('/health')
@login_required
def health_dashboard():
    # Get the user's health metrics, ordered by most recent first
    health_metrics = HealthMetric.query.filter_by(user_id=current_user.id).order_by(HealthMetric.created_at.desc()).limit(10).all()
    return render_template('Health/Health.html', health_metrics=health_metrics)


@app.route('/news')
@login_required
def news():
    """News page for health and wellness articles"""
    return render_template('News/news.html')

@app.route('/clinics')
def clinics():
    # Get all clinics from the database
    all_clinics = Clinic.query.all()
    return render_template('clinics.html', clinics=all_clinics)

# Admin clinic management page
@app.route('/admin/clinics')
def admin_clinics():
    if not session.get('admin_logged_in'):
        flash('Access denied. Admin login required.', 'error')
        return redirect(url_for('login'))
    
    # Get all clinics from the database
    all_clinics = Clinic.query.all()
    return render_template('admin_clinics.html', clinics=all_clinics)

# Add a new clinic (admin only)
@app.route('/admin/clinics/add', methods=['GET', 'POST'])
def admin_add_clinic():
    if not session.get('admin_logged_in'):
        flash('Access denied. Admin login required.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Get form data
        name = sanitize_input(request.form.get('name'))
        location = sanitize_input(request.form.get('location'))
        opening_hours = sanitize_input(request.form.get('opening_hours'))
        contact = sanitize_input(request.form.get('contact'))
        description = sanitize_input(request.form.get('description'))
        specialties = sanitize_input(request.form.get('specialties'))
        
        # Validate required fields
        if not name or not location or not opening_hours or not contact:
            flash('Please fill in all required fields.', 'danger')
            return redirect(url_for('admin_add_clinic'))
        
        # Handle image upload if provided
        image_path = None
        if 'image' in request.files and request.files['image'].filename:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Create unique filename to prevent overwriting
                unique_filename = f"{int(time.time())}_{filename}"
                file_path = os.path.join(app.root_path, 'static/uploads/clinics', unique_filename)
                
                # Ensure directory exists
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                
                # Save the file
                file.save(file_path)
                image_path = f"uploads/clinics/{unique_filename}"
        
        # Create new clinic
        new_clinic = Clinic(
            name=name,
            location=location,
            opening_hours=opening_hours,
            contact=contact,
            description=description,
            specialties=specialties,
            image_path=image_path
        )
        
        # Add to database
        db.session.add(new_clinic)
        db.session.commit()
        
        # Log security event
        log_security_event(
            'clinic_added',
            username='WellNestAdmin',  # Using admin username directly since we know it's an admin action
            ip_address=request.remote_addr,
            details=f"Admin added clinic: {name}"
        )
        
        flash('Clinic added successfully!', 'success')
        return redirect(url_for('admin_clinics'))
    
    return render_template('admin_add_clinic.html')

# Edit an existing clinic (admin only)
@app.route('/admin/clinics/edit/<int:clinic_id>', methods=['GET', 'POST'])
def admin_edit_clinic(clinic_id):
    if not session.get('admin_logged_in'):
        flash('Access denied. Admin login required.', 'error')
        return redirect(url_for('login'))
    
    # Get the clinic
    clinic = Clinic.query.get_or_404(clinic_id)
    
    if request.method == 'POST':
        # Get form data
        clinic.name = sanitize_input(request.form.get('name'))
        clinic.location = sanitize_input(request.form.get('location'))
        clinic.opening_hours = sanitize_input(request.form.get('opening_hours'))
        clinic.contact = sanitize_input(request.form.get('contact'))
        clinic.description = sanitize_input(request.form.get('description'))
        clinic.specialties = sanitize_input(request.form.get('specialties'))
        
        # Validate required fields
        if not clinic.name or not clinic.location or not clinic.opening_hours or not clinic.contact:
            flash('Please fill in all required fields.', 'danger')
            return redirect(url_for('admin_edit_clinic', clinic_id=clinic_id))
        
        # Handle image upload if provided
        if 'image' in request.files and request.files['image'].filename:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Create unique filename to prevent overwriting
                unique_filename = f"{int(time.time())}_{filename}"
                file_path = os.path.join(app.root_path, 'static/uploads/clinics', unique_filename)
                
                # Ensure directory exists
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                
                # Save the file
                file.save(file_path)
                
                # Delete old image if exists
                if clinic.image_path:
                    old_file_path = os.path.join(app.root_path, 'static', clinic.image_path)
                    if os.path.exists(old_file_path):
                        os.remove(old_file_path)
                
                clinic.image_path = f"uploads/clinics/{unique_filename}"
        
        # Update database
        db.session.commit()
        
        # Log security event
        log_security_event(
            'clinic_edited',
            username='WellNestAdmin',  # Using admin username directly since we know it's an admin action
            ip_address=request.remote_addr,
            details=f"Admin edited clinic: {clinic.name} (ID: {clinic_id})"
        )
        
        flash('Clinic updated successfully!', 'success')
        return redirect(url_for('admin_clinics'))
    
    return render_template('admin_edit_clinic.html', clinic=clinic)

# Delete a clinic (admin only)
@app.route('/admin/clinics/delete/<int:clinic_id>', methods=['POST'])
def admin_delete_clinic(clinic_id):
    if not session.get('admin_logged_in'):
        flash('Access denied. Admin login required.', 'error')
        return redirect(url_for('login'))
    
    # Get the clinic
    clinic = Clinic.query.get_or_404(clinic_id)
    
    # Delete image if exists
    if clinic.image_path:
        file_path = os.path.join(app.root_path, 'static', clinic.image_path)
        if os.path.exists(file_path):
            os.remove(file_path)
    
    # Store name for logging
    clinic_name = clinic.name
    
    # Delete from database
    db.session.delete(clinic)
    db.session.commit()
    
    # Log security event
    log_security_event(
        'clinic_deleted',
        username='WellNestAdmin',  # Using admin username directly since we know it's an admin action
        ip_address=request.remote_addr,
        details=f"Admin deleted clinic: {clinic_name} (ID: {clinic_id})"
    )
    
    flash('Clinic deleted successfully!', 'success')
    return redirect(url_for('admin_clinics'))

@app.route('/events')
@login_required
def events():
    """Events page for community activities and health-related events"""
    # Get all events from the database
    all_events = Event.query.order_by(Event.event_date).all()
    return render_template('Events/events.html', events=all_events)


@app.route('/event/add', methods=['GET', 'POST'])
@login_required
def event_add():
    """Add a new event page"""
    if request.method == 'POST':
        # Verify reCAPTCHA
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not recaptcha_response:
            flash('Please complete the reCAPTCHA.', 'error')
            return redirect(url_for('event_add'))
            
        # Verify reCAPTCHA with Google
        data = {
            'secret': '6Lf2VacrAAAAAOYbaV5K0KkjfSVxf67qQqUMTiCk',  # Test secret key
            'response': recaptcha_response
        }
        try:
            response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
            result = response.json()
            app.logger.info(f'reCAPTCHA verification response: {result}')  # Debug log
            if not result.get('success'):
                error_reasons = result.get('error-codes', [])
                app.logger.error(f'reCAPTCHA verification failed. Errors: {error_reasons}')
                flash('reCAPTCHA verification failed. Please try again.', 'error')
                return redirect(url_for('event_add'))
        except Exception as e:
            app.logger.error(f'reCAPTCHA verification error: {str(e)}')
            flash('Error verifying reCAPTCHA. Please try again.', 'error')
            return redirect(url_for('event_add'))
        
        try:
            # Get form data and sanitize inputs
            title = sanitize_input(request.form.get('title'))
            description = sanitize_input(request.form.get('description'))
            category = sanitize_input(request.form.get('category'))
            sessions = int(request.form.get('sessions'))
            price = float(request.form.get('price', 0))
            vacancy = int(request.form.get('vacancy'))
            intensity = sanitize_input(request.form.get('intensity'))
            location = sanitize_input(request.form.get('location'))
            event_date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()
            start_time = datetime.strptime(request.form.get('startTime'), '%H:%M').time()
            end_time = datetime.strptime(request.form.get('endTime'), '%H:%M').time()
            organizer = sanitize_input(request.form.get('organizer'))
            contact = sanitize_input(request.form.get('contact'))
            
            # Create new event
            new_event = Event(
                user_id=current_user.id,
                title=title,
                description=description,
                category=category,
                sessions=sessions,
                price=price,
                vacancy=vacancy,
                intensity=intensity,
                location=location,
                event_date=event_date,
                start_time=start_time,
                end_time=end_time,
                organizer=organizer,
                contact=contact,
                image_path='images/events/placeholder_image.jpg'  # Default image path
            )
            
            # Handle image upload if provided
            if 'image' in request.files and request.files['image'].filename:
                image = request.files['image']
                if image and allowed_file(image.filename):
                    # Generate secure filename
                    filename = secure_filename(image.filename)
                    # Create unique filename with timestamp
                    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                    filename = f"{timestamp}_{filename}"
                    # Save file
                    image_path = os.path.join('static/images/events', filename)
                    image.save(image_path)
                    new_event.image_path = f"images/events/{filename}"
            
            # Save to database
            db.session.add(new_event)
            db.session.commit()
            
            # Log security event
            log_security_event('event_created', username=current_user.username, 
                             ip_address=request.remote_addr, 
                             details=f"Event created: {title}")
            
            flash('Event created successfully!', 'success')
            return redirect(url_for('events'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating event: {str(e)}', 'error')
    
    return render_template('Events/event_add.html')


@app.route('/event/<int:event_id>/edit', methods=['GET', 'POST'])
@login_required
def event_edit(event_id):
    """Edit an existing event"""
    # Get the event
    event = Event.query.get_or_404(event_id)
    
    # Check if the current user is the owner of the event
    if event.user_id != current_user.id:
        log_security_event('unauthorized_event_edit_attempt', username=current_user.username, 
                         ip_address=request.remote_addr, 
                         details=f"Attempted to edit event {event_id} owned by user {event.user_id}")
        flash('You are not authorized to edit this event.', 'error')
        return redirect(url_for('events'))
    
    if request.method == 'POST':
        # Verify reCAPTCHA
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not recaptcha_response:
            flash('Please complete the reCAPTCHA.', 'error')
            return redirect(url_for('event_edit', event_id=event_id))
            
        # Verify reCAPTCHA with Google
        data = {
            'secret': '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe',  # Test secret key
            'response': recaptcha_response
        }
        try:
            response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
            result = response.json()
            app.logger.info(f'reCAPTCHA verification response: {result}')  # Debug log
            if not result.get('success'):
                error_reasons = result.get('error-codes', [])
                app.logger.error(f'reCAPTCHA verification failed. Errors: {error_reasons}')
                flash('reCAPTCHA verification failed. Please try again.', 'error')
                return redirect(url_for('event_edit', event_id=event_id))
        except Exception as e:
            app.logger.error(f'reCAPTCHA verification error: {str(e)}')
            flash('Error verifying reCAPTCHA. Please try again.', 'error')
            return redirect(url_for('event_edit', event_id=event_id))
            
        try:
            # Get form data and sanitize inputs
            event.title = sanitize_input(request.form.get('title'))
            event.description = sanitize_input(request.form.get('description'))
            event.category = sanitize_input(request.form.get('category'))
            event.sessions = int(request.form.get('sessions'))
            event.price = float(request.form.get('price', 0))
            event.vacancy = int(request.form.get('vacancy'))
            event.intensity = sanitize_input(request.form.get('intensity'))
            event.location = sanitize_input(request.form.get('location'))
            event.event_date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()
            event.start_time = datetime.strptime(request.form.get('startTime'), '%H:%M').time()
            event.end_time = datetime.strptime(request.form.get('endTime'), '%H:%M').time()
            event.organizer = sanitize_input(request.form.get('organizer'))
            event.contact = sanitize_input(request.form.get('contact'))
            
            # Handle image upload if provided
            if 'image' in request.files and request.files['image'].filename:
                image = request.files['image']
                if image and allowed_file(image.filename):
                    # Generate secure filename
                    filename = secure_filename(image.filename)
                    # Create unique filename with timestamp
                    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                    filename = f"{timestamp}_{filename}"
                    # Save file
                    image_path = os.path.join('static/images/events', filename)
                    image.save(image_path)
                    event.image_path = f"images/events/{filename}"
            
            # Save to database
            db.session.commit()
            
            # Log security event
            log_security_event('event_updated', username=current_user.username, 
                             ip_address=request.remote_addr, 
                             details=f"Event updated: {event.title} (ID: {event_id})")
            
            flash('Event updated successfully!', 'success')
            return redirect(url_for('events'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating event: {str(e)}', 'error')
    
    return render_template('Events/event_edit.html', event=event)


@app.route('/event/<int:event_id>/delete', methods=['POST'])
@login_required
def event_delete(event_id):
    """Delete an event"""
    event = Event.query.get_or_404(event_id)
    
    # Check if the current user is the owner of the event
    if event.user_id != current_user.id:
        log_security_event('unauthorized_event_delete_attempt', username=current_user.username, 
                         ip_address=request.remote_addr, 
                         details=f"Attempted to delete event {event_id} owned by user {event.user_id}")
        flash('You are not authorized to delete this event.', 'error')
        return redirect(url_for('events'))
    
    try:
        # Delete the event
        db.session.delete(event)
        db.session.commit()
        
        # Log security event
        log_security_event('event_deleted', username=current_user.username, 
                         ip_address=request.remote_addr, 
                         details=f"Event deleted: {event.title} (ID: {event_id})")
        
        flash('Event deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting event: {str(e)}', 'error')
    
    return redirect(url_for('events'))


@app.route('/api/events')
@login_required
def api_events():
    """API endpoint to get all events"""
    events = Event.query.order_by(Event.event_date).all()
    event_list = []
    
    for event in events:
        event_data = {
            'id': event.id,
            'title': event.title,
            'category': event.category,
            'price': event.formatted_price(),
            'sessions': event.sessions,
            'availability': event.availability(),
            'intensity': event.intensity,
            'location': event.location,
            'date': event.formatted_date(),
            'time': event.formatted_time(),
            'image': url_for('static', filename=event.image_path),
            'user_id': event.user_id,
            'is_owner': event.user_id == current_user.id,
            'is_signed_up': event.is_user_signed_up(current_user.id),
            'signed_up_count': event.get_signed_up_count(),
            'vacancy': event.vacancy
        }
        event_list.append(event_data)
    
    return jsonify(events=event_list)


@app.route('/event/<int:event_id>/signup', methods=['POST'])
@login_required
def event_signup(event_id):
    """Sign up for an event"""
    event = Event.query.get_or_404(event_id)
    
    # Check if the event is full
    if event.get_signed_up_count() >= event.vacancy:
        flash('Sorry, this event is already full.', 'error')
        return redirect(url_for('events'))
    
    # Check if the user is already signed up
    if event.is_user_signed_up(current_user.id):
        flash('You are already signed up for this event.', 'info')
        return redirect(url_for('events'))
    
    # Create new signup
    signup = EventSignup(event_id=event_id, user_id=current_user.id)
    
    try:
        db.session.add(signup)
        db.session.commit()
        
        # Log security event
        log_security_event('event_signup', username=current_user.username, 
                         ip_address=request.remote_addr, 
                         details=f"Signed up for event: {event.title} (ID: {event_id})")
        
        flash('You have successfully signed up for this event!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error signing up for event: {str(e)}', 'error')
    
    return redirect(url_for('events'))


@app.route('/event/<int:event_id>/cancel', methods=['POST'])
@login_required
def event_cancel(event_id):
    """Cancel signup for an event"""
    event = Event.query.get_or_404(event_id)
    
    # Check if the user is signed up
    signup = EventSignup.query.filter_by(event_id=event_id, user_id=current_user.id).first()
    if not signup:
        flash('You are not signed up for this event.', 'info')
        return redirect(url_for('events'))
    
    try:
        db.session.delete(signup)
        db.session.commit()
        
        # Log security event
        log_security_event('event_signup_cancel', username=current_user.username, 
                         ip_address=request.remote_addr, 
                         details=f"Canceled signup for event: {event.title} (ID: {event_id})")
        
        flash('You have successfully canceled your signup for this event.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error canceling signup: {str(e)}', 'error')
    
    return redirect(url_for('events'))


@app.route('/submit_health_metrics', methods=['POST'])
@login_required
def submit_health_metrics():
    try:
        # Get form data
        systolic = request.form.get('systolic', type=int)
        diastolic = request.form.get('diastolic', type=int)
        blood_sugar = request.form.get('bloodSugar', type=int)
        height = request.form.get('height', type=float)
        weight = request.form.get('weight', type=float)
        heart_rate = request.form.get('heartRate', type=int)
        
        # Validate that at least one field is provided
        if not any([systolic, diastolic, blood_sugar, height, weight, heart_rate]):
            flash('Please provide at least one health metric', 'danger')
            return redirect(url_for('health_dashboard'))
            
        # Get the most recent health metric for this user to use as baseline
        last_metric = HealthMetric.query.filter_by(user_id=current_user.id).order_by(HealthMetric.created_at.desc()).first()
        
        # Use previous values for any fields not provided
        if last_metric:
            systolic = systolic if systolic is not None else last_metric.systolic
            diastolic = diastolic if diastolic is not None else last_metric.diastolic
            blood_sugar = blood_sugar if blood_sugar is not None else last_metric.blood_sugar
            height = height if height is not None else last_metric.height
            weight = weight if weight is not None else last_metric.weight
            heart_rate = heart_rate if heart_rate is not None else last_metric.heart_rate
        
        # Create new health metric
        new_metric = HealthMetric(
            user_id=current_user.id,
            systolic=systolic,
            diastolic=diastolic,
            blood_sugar=blood_sugar,
            height=height,
            weight=weight,
            heart_rate=heart_rate
        )
        
        # Save to database
        db.session.add(new_metric)
        db.session.commit()
        
        # Log the event
        app.logger.info(f"User {current_user.username} recorded new health metrics")
        
        flash('Health metrics saved successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error saving health metrics: {str(e)}")
        flash('An error occurred while saving your health metrics', 'danger')
    
    return redirect(url_for('health_dashboard'))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('homepage'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('homepage'))
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        email = sanitize_input(request.form.get('email', ''))
        password = request.form.get('password', '')
        
        # Input validation
        username_valid, username_msg = validate_username(username)
        email_valid, email_msg = validate_email(email)
        password_valid, password_msg = validate_password(password)
        
        if not username_valid:
            flash(username_msg, 'error')
            log_security_event('REGISTRATION_FAILED', username, request.remote_addr, f'Invalid username: {username_msg}')
            return redirect(url_for('register'))
            
        if not email_valid:
            flash(email_msg, 'error')
            log_security_event('REGISTRATION_FAILED', username, request.remote_addr, f'Invalid email: {email_msg}')
            return redirect(url_for('register'))
            
        if not password_valid:
            flash(password_msg, 'error')
            log_security_event('REGISTRATION_FAILED', username, request.remote_addr, f'Weak password attempt')
            return redirect(url_for('register'))
        
        # Check for existing users
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username or email already exists.', 'error')
            log_security_event('REGISTRATION_FAILED', username, request.remote_addr, 'Username or email already exists')
            return redirect(url_for('register'))
            
        # Create new user
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        log_security_event('REGISTRATION_SUCCESS', username, request.remote_addr, 'New user registered')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('homepage'))
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')
        
        # Basic input validation
        if not username or not password:
            flash('Username and password are required.', 'error')
            log_security_event('LOGIN_FAILED', username, request.remote_addr, 'Missing username or password')
            return redirect(url_for('login'))
        
        # Check for admin login first
        if username == 'WellNestAdmin' and password == 'WellNestAdmin123!':
            session['admin_logged_in'] = True
            flash('Welcome, Administrator!', 'success')
            log_security_event('ADMIN_LOGIN_SUCCESS', username, request.remote_addr, 'Admin login successful')
            return redirect(url_for('admin_dashboard'))
        
        # Regular user login
        user = User.query.filter_by(username=username).first()
        
        # Check if account is locked - safely handle missing columns
        try:
            if user and hasattr(user, 'account_locked_until') and user.account_locked_until and user.account_locked_until > datetime.now():
                remaining_time = (user.account_locked_until - datetime.now()).total_seconds() / 60
                flash(f'Account temporarily locked due to too many failed attempts. Try again in {int(remaining_time)} minutes.', 'error')
                log_security_event('LOGIN_BLOCKED', username, request.remote_addr, 'Account temporarily locked')
                return redirect(url_for('login'))
        except Exception as e:
            app.logger.error(f"Error checking account lock: {str(e)}")
            # Continue with login process if there's an error with the new columns
            
        if user and user.check_password(password):
            # Reset failed login attempts on successful login - safely handle missing columns
            try:
                if hasattr(user, 'failed_login_attempts'):
                    user.failed_login_attempts = 0
                if hasattr(user, 'account_locked_until'):
                    user.account_locked_until = None
                db.session.commit()
            except Exception as e:
                app.logger.error(f"Error resetting login attempts: {str(e)}")
            session['username_for_otp'] = user.username
            totp = pyotp.TOTP(user.otp_secret)
            otp = totp.now()
            # Send email with OTP
            try:
                msg = EmailMessage(
                    'Your OTP Code',
                    f'Your one-time password is: {otp}',
                    app.config['MAIL_DEFAULT_SENDER'],
                    [user.email]
                )
                msg.send()
                flash('An OTP has been sent to your email.', 'info')
                log_security_event('OTP_SENT', username, request.remote_addr, 'OTP email sent successfully')
            except Exception as e:
                import traceback
                print("--- EMAIL SENDING FAILED ---")
                traceback.print_exc() # Print the full, detailed error to the terminal
                print("----------------------------")
                flash('Failed to send OTP email. Please check your internet connection and .env file credentials.', 'danger')
                log_security_event('OTP_SEND_FAILED', username, request.remote_addr, f'Email sending failed: {str(e)}')
                return redirect(url_for('login'))

            return redirect(url_for('verify_otp'))

        # Log failed login attempts
        log_security_event('LOGIN_FAILED', username, request.remote_addr, 'Invalid username or password')
        
        # Increment failed login attempts and potentially lock account - safely handle missing columns
        if user:
            try:
                if hasattr(user, 'failed_login_attempts'):
                    # Initialize to 0 if None
                    if user.failed_login_attempts is None:
                        user.failed_login_attempts = 0
                    
                    user.failed_login_attempts += 1
                    if user.failed_login_attempts >= 5 and hasattr(user, 'account_locked_until'):  # Lock account after 5 failed attempts
                        user.account_locked_until = datetime.now() + timedelta(minutes=15)  # Lock for 15 minutes
                        log_security_event('ACCOUNT_LOCKED', username, request.remote_addr, f'Account locked for 15 minutes after {user.failed_login_attempts} failed attempts')
                db.session.commit()
            except Exception as e:
                app.logger.error(f"Error tracking failed login attempts: {str(e)}")
            
        flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp = sanitize_input(request.form.get('otp', ''))
        username = session.get('username_for_otp')
        
        if not username:
            flash('Session expired. Please log in again.', 'error')
            log_security_event('OTP_VERIFY_FAILED', None, request.remote_addr, 'No username in session')
            return redirect(url_for('login'))
            
        if not otp or not otp.isdigit() or len(otp) != 6:
            flash('Please enter a valid 6-digit OTP.', 'error')
            log_security_event('OTP_VERIFY_FAILED', username, request.remote_addr, 'Invalid OTP format')
            return render_template('verify_otp.html')
        
        user = User.query.filter_by(username=username).first()
        if not user:
            flash('User not found. Please log in again.', 'error')
            log_security_event('OTP_VERIFY_FAILED', username, request.remote_addr, 'User not found')
            return redirect(url_for('login'))
            
        totp = pyotp.TOTP(user.otp_secret)
        # Check current time window and previous/next windows for better usability
        current_time = int(time.time())
        valid_otp = False
        
        # Check current window and 2 windows before/after (±2 minutes tolerance)
        for i in range(-2, 3):
            test_time = current_time + (i * 30)  # 30 seconds per window
            if totp.verify(otp, for_time=test_time):
                valid_otp = True
                break
        
        if valid_otp:
            login_user(user)
            session.pop('username_for_otp', None)  # Clean up session
            flash('You have successfully logged in.', 'success')
            log_security_event('OTP_VERIFY_SUCCESS', username, request.remote_addr, 'OTP verification successful')
            # Force direct redirect to homepage with cache control
            response = make_response(redirect('/homepage?t=' + str(int(time.time()))))
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            return response
        else:
            flash('Invalid OTP.', 'error')
            log_security_event('OTP_VERIFY_FAILED', username, request.remote_addr, 'Invalid OTP provided')
    return render_template('verify_otp.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Force direct redirect to homepage with no caching
    response = make_response(redirect('/homepage'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/homepage')
@login_required
def homepage():
    # Add cache control headers to prevent caching
    response = make_response(render_template('homepage.html'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        email = sanitize_input(request.form.get('email', ''))
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        current_password = request.form.get('current_password', '')
        
        # Handle profile picture upload
        profile_picture = request.files.get('profile_picture')
        profile_picture_filename = None
        
        if profile_picture and profile_picture.filename:
            # Check if file extension is allowed
            if not allowed_file(profile_picture.filename, ['jpg', 'jpeg', 'png']):
                flash('Only JPEG, JPG, and PNG files are allowed for profile pictures.', 'error')
                log_security_event('PROFILE_EDIT_FAILED', current_user.username, request.remote_addr, 'Invalid profile picture extension')
                return render_template('edit_profile.html')
                
            # Verify the actual file content using MIME type
            mime_type = validate_image_mime(profile_picture)
            if mime_type not in ['image/jpeg', 'image/png']:
                flash('The uploaded file is not a valid image. Only JPEG and PNG files are allowed.', 'error')
                log_security_event('PROFILE_EDIT_FAILED', current_user.username, request.remote_addr, f'Invalid image content type: {mime_type}')
                return render_template('edit_profile.html')
                
            # Secure the filename and save the file
            filename = secure_filename(profile_picture.filename)
            # Add timestamp to filename to prevent overwriting
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            profile_picture_filename = f"{current_user.id}_{timestamp}_{filename}"
            
            # Save the file
            profile_picture.save(os.path.join(app.root_path, 'static/uploads', profile_picture_filename))
        
        # Input validation
        username_valid, username_msg = validate_username(username)
        email_valid, email_msg = validate_email(email)
        
        if not username_valid:
            flash(username_msg, 'error')
            return render_template('edit_profile.html')
            
        if not email_valid:
            flash(email_msg, 'error')
            return render_template('edit_profile.html')
        
        # Check if current password is correct
        if not current_user.check_password(current_password):
            flash('Current password is incorrect.', 'error')
            log_security_event('PROFILE_EDIT_FAILED', current_user.username, request.remote_addr, 'Incorrect current password')
            return render_template('edit_profile.html')
        
        # Check if new password is provided and valid
        if new_password:
            if new_password != confirm_password:
                flash('New passwords do not match.', 'error')
                log_security_event('PROFILE_EDIT_FAILED', current_user.username, request.remote_addr, 'New passwords do not match')
                return render_template('edit_profile.html')
                
            password_valid, password_msg = validate_password(new_password)
            if not password_valid:
                flash(password_msg, 'error')
                log_security_event('PROFILE_EDIT_FAILED', current_user.username, request.remote_addr, f'Invalid new password: {password_msg}')
                return render_template('edit_profile.html')
        
        # Check if username or email already exists (excluding current user)
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email),
            User.id != current_user.id
        ).first()
        
        if existing_user:
            flash('Username or email already exists.', 'error')
            log_security_event('PROFILE_EDIT_FAILED', current_user.username, request.remote_addr, 'Username or email already exists')
            return render_template('edit_profile.html')
        
        # Update user information
        changes = []
        if current_user.username != username:
            changes.append(f'username: {current_user.username} -> {username}')
            current_user.username = username
            
        if current_user.email != email:
            changes.append(f'email: {current_user.email} -> {email}')
            current_user.email = email
            
        if new_password:
            changes.append('password updated')
            current_user.set_password(new_password)
            
        # Update profile picture if uploaded
        if profile_picture_filename:
            old_picture = current_user.profile_picture
            changes.append('profile picture updated')
            current_user.profile_picture = profile_picture_filename
            
            # Delete old profile picture if it exists
            if old_picture:
                try:
                    old_picture_path = os.path.join(app.root_path, 'static/uploads', old_picture)
                    if os.path.exists(old_picture_path):
                        os.remove(old_picture_path)
                except Exception as e:
                    app.logger.error(f"Error removing old profile picture: {e}")
        
        db.session.commit()
        
        flash('Profile updated successfully.', 'success')
        log_security_event('PROFILE_EDIT_SUCCESS', current_user.username, request.remote_addr, f'Profile updated: {", ".join(changes)}')
        return redirect(url_for('homepage'))
    
    return render_template('edit_profile.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Admin routes
@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        flash('Access denied. Admin login required.', 'error')
        return redirect(url_for('login'))
    
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/events')
def admin_events():
    if not session.get('admin_logged_in'):
        flash('Access denied. Admin login required.', 'error')
        return redirect(url_for('login'))
    
    # Get all events with their creators
    events = Event.query.join(User).all()
    return render_template('admin_events.html', events=events)

@app.route('/admin/events/create', methods=['GET', 'POST'])
def admin_create_event():
    if not session.get('admin_logged_in'):
        flash('Access denied. Admin login required.', 'error')
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        # Get admin user (for event ownership)
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            flash('Admin user not found', 'danger')
            return redirect(url_for('admin_events'))
            
        # Process form data
        try:
            title = sanitize_input(request.form.get('title'))
            description = sanitize_input(request.form.get('description'))
            category = sanitize_input(request.form.get('category'))
            sessions = int(request.form.get('sessions'))
            price = float(request.form.get('price'))
            vacancy = int(request.form.get('vacancy'))
            intensity = sanitize_input(request.form.get('intensity'))
            location = sanitize_input(request.form.get('location'))
            event_date = datetime.strptime(request.form.get('event_date'), '%Y-%m-%d').date()
            start_time = datetime.strptime(request.form.get('start_time'), '%H:%M').time()
            end_time = datetime.strptime(request.form.get('end_time'), '%H:%M').time()
            organizer = sanitize_input(request.form.get('organizer'))
            contact = sanitize_input(request.form.get('contact'))
            image_path = sanitize_input(request.form.get('image_path'))
            
            # Create new event
            new_event = Event(
                user_id=admin_user.id,
                title=title,
                description=description,
                category=category,
                sessions=sessions,
                price=price,
                vacancy=vacancy,
                intensity=intensity,
                location=location,
                event_date=event_date,
                start_time=start_time,
                end_time=end_time,
                organizer=organizer,
                contact=contact,
                image_path=image_path
            )
            
            db.session.add(new_event)
            db.session.commit()
            
            # Log the event creation
            log_security_event(
                'admin_event_created',
                username='admin',
                ip_address=request.remote_addr,
                details=f'Admin created event: {title}'
            )
            
            flash('Admin event created successfully', 'success')
            return redirect(url_for('admin_events'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating event: {str(e)}', 'danger')
            return redirect(url_for('admin_create_event'))
    
    return render_template('admin_create_event.html')

@app.route('/admin/events/edit/<int:event_id>', methods=['GET', 'POST'])
def admin_edit_event(event_id):
    if not session.get('admin_logged_in'):
        flash('Access denied. Admin login required.', 'error')
        return redirect(url_for('login'))
        
    event = Event.query.get_or_404(event_id)
    
    if request.method == 'POST':
        try:
            # Update event with form data
            event.title = sanitize_input(request.form.get('title'))
            event.description = sanitize_input(request.form.get('description'))
            event.category = sanitize_input(request.form.get('category'))
            event.sessions = int(request.form.get('sessions'))
            event.price = float(request.form.get('price'))
            event.vacancy = int(request.form.get('vacancy'))
            event.intensity = sanitize_input(request.form.get('intensity'))
            event.location = sanitize_input(request.form.get('location'))
            event.event_date = datetime.strptime(request.form.get('event_date'), '%Y-%m-%d').date()
            event.start_time = datetime.strptime(request.form.get('start_time'), '%H:%M').time()
            event.end_time = datetime.strptime(request.form.get('end_time'), '%H:%M').time()
            event.organizer = sanitize_input(request.form.get('organizer'))
            event.contact = sanitize_input(request.form.get('contact'))
            event.image_path = sanitize_input(request.form.get('image_path'))
            event.updated_at = datetime.utcnow()
            
            db.session.commit()
            
            # Log the event update
            log_security_event(
                'admin_event_updated',
                username='admin',
                ip_address=request.remote_addr,
                details=f'Admin updated event ID {event_id}: {event.title}'
            )
            
            flash('Event updated successfully', 'success')
            return redirect(url_for('admin_events'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating event: {str(e)}', 'danger')
            
    return render_template('admin_edit_event.html', event=event)

@app.route('/admin/events/delete/<int:event_id>', methods=['POST'])
def admin_delete_event(event_id):
    if not session.get('admin_logged_in'):
        flash('Access denied. Admin login required.', 'error')
        return redirect(url_for('login'))
        
    event = Event.query.get_or_404(event_id)
    event_title = event.title
    
    try:
        db.session.delete(event)
        db.session.commit()
        
        # Log the event deletion
        log_security_event(
            'admin_event_deleted',
            username='admin',
            ip_address=request.remote_addr,
            details=f'Admin deleted event ID {event_id}: {event_title}'
        )
        
        flash('Event deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting event: {str(e)}', 'danger')
        
    return redirect(url_for('admin_events'))

@app.route('/admin/security-logs')
def admin_security_logs():
    if not session.get('admin_logged_in'):
        flash('Access denied. Admin login required.', 'error')
        return redirect(url_for('login'))
        
    # Get page number and event type filter
    page = request.args.get('page', 1, type=int)
    selected_type = request.args.get('event_type', '')
    per_page = 20  # Number of logs per page
    
    try:
        # Read security log file using the same path as defined in the logging setup
        log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'security.log')
        app.logger.info(f"Looking for security log at: {log_file}")
        
        # Create a test log entry if the file doesn't exist or is empty
        if not os.path.exists(log_file) or os.path.getsize(log_file) == 0:
            # Create a test security log entry
            log_security_event(
                event_type='ADMIN_SECURITY_LOG_VIEW',
                username='admin',
                ip_address=request.remote_addr,
                details='Initial security log view - test entry'
            )
            app.logger.info(f"Created test security log entry at {log_file}")
            
        if not os.path.exists(log_file):
            flash(f'Security log file not found at {log_file}', 'warning')
            return render_template('admin_security_logs.html', logs=[], page=1, total_pages=1, event_types=[], selected_type='')
            
        with open(log_file, 'r') as f:
            log_lines = f.readlines()
            
        # Parse log entries
        logs = []
        event_types = set()
        
        for line in log_lines:
            if 'SECURITY_EVENT:' in line:
                # Extract JSON part
                json_str = line.split('SECURITY_EVENT:', 1)[1].strip()
                try:
                    log_entry = json.loads(json_str)
                    event_types.add(log_entry['event_type'])
                    
                    # Apply event type filter if specified
                    if selected_type and log_entry['event_type'] != selected_type:
                        continue
                        
                    # Add styling classes based on event type
                    if 'SUCCESS' in log_entry['event_type'] or 'success' in log_entry['event_type']:
                        log_entry['event_class'] = 'event-success'
                        log_entry['event_badge'] = 'bg-success'
                    elif 'FAILED' in log_entry['event_type'] or 'failed' in log_entry['event_type'] or 'unauthorized' in log_entry['event_type']:
                        log_entry['event_class'] = 'event-danger'
                        log_entry['event_badge'] = 'bg-danger'
                    elif 'attempt' in log_entry['event_type']:
                        log_entry['event_class'] = 'event-warning'
                        log_entry['event_badge'] = 'bg-warning'
                    else:
                        log_entry['event_class'] = ''
                        log_entry['event_badge'] = 'bg-secondary'
                        
                    logs.append(log_entry)
                except json.JSONDecodeError:
                    continue
        
        # Sort logs by timestamp (newest first)
        logs.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Paginate results
        total_logs = len(logs)
        total_pages = (total_logs + per_page - 1) // per_page
        start_idx = (page - 1) * per_page
        end_idx = min(start_idx + per_page, total_logs)
        paginated_logs = logs[start_idx:end_idx]
        
        return render_template(
            'admin_security_logs.html',
            logs=paginated_logs,
            page=page,
            total_pages=total_pages,
            event_types=sorted(event_types),
            selected_type=selected_type
        )
        
    except Exception as e:
        flash(f'Error reading security logs: {str(e)}', 'danger')
        return render_template('admin_security_logs.html', logs=[], page=1, total_pages=1, event_types=[], selected_type='')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Admin logged out successfully.', 'info')
    return redirect(url_for('index'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@csrf.exempt
def admin_delete_user(user_id):
    if not session.get('admin_logged_in'):
        flash('Access denied. Admin login required.', 'error')
        log_security_event('ADMIN_ACCESS_DENIED', None, request.remote_addr, f'Unauthorized admin delete attempt for user_id: {user_id}')
        return redirect(url_for('login'))
    
    user = User.query.get_or_404(user_id)
    username = user.username
    credential_count = len(user.credentials)
    
    # Delete associated WebAuthn credentials first
    for credential in user.credentials:
        db.session.delete(credential)
    
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User "{username}" has been deleted successfully.', 'success')
    log_security_event('ADMIN_DELETE_SUCCESS', username, request.remote_addr, f'User deleted with {credential_count} WebAuthn credentials')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
def admin_edit_user(user_id):
    if not session.get('admin_logged_in'):
        flash('Access denied. Admin login required.', 'error')
        log_security_event('ADMIN_ACCESS_DENIED', None, request.remote_addr, f'Unauthorized admin edit attempt for user_id: {user_id}')
        return redirect(url_for('login'))
    
    user = User.query.get_or_404(user_id)
    original_username = user.username
    
    if request.method == 'POST':
        new_username = sanitize_input(request.form.get('username', ''))
        new_email = sanitize_input(request.form.get('email', ''))
        new_password = request.form.get('password', '')
        
        # Input validation
        username_valid, username_msg = validate_username(new_username)
        email_valid, email_msg = validate_email(new_email)
        
        if not username_valid:
            flash(username_msg, 'error')
            log_security_event('ADMIN_EDIT_FAILED', original_username, request.remote_addr, f'Invalid username: {username_msg}')
            return render_template('admin_edit_user.html', user=user)
            
        if not email_valid:
            flash(email_msg, 'error')
            log_security_event('ADMIN_EDIT_FAILED', original_username, request.remote_addr, f'Invalid email: {email_msg}')
            return render_template('admin_edit_user.html', user=user)
        
        # Validate password if provided
        if new_password:
            password_valid, password_msg = validate_password(new_password)
            if not password_valid:
                flash(password_msg, 'error')
                log_security_event('ADMIN_EDIT_FAILED', original_username, request.remote_addr, f'Weak password: {password_msg}')
                return render_template('admin_edit_user.html', user=user)
        
        # Check if username or email already exists (excluding current user)
        existing_user = User.query.filter(
            (User.username == new_username) | (User.email == new_email),
            User.id != user_id
        ).first()
        
        if existing_user:
            flash('Username or email already exists.', 'error')
            log_security_event('ADMIN_EDIT_FAILED', original_username, request.remote_addr, 'Username or email already exists')
        else:
            # Track changes for logging
            changes = []
            if user.username != new_username:
                changes.append(f'username: {user.username} -> {new_username}')
            if user.email != new_email:
                changes.append(f'email: {user.email} -> {new_email}')
            if new_password:
                changes.append('password updated')
            
            user.username = new_username
            user.email = new_email
            if new_password:  # Only update password if provided
                user.set_password(new_password)
            
            db.session.commit()
            flash(f'User "{user.username}" has been updated successfully.', 'success')
            log_security_event('ADMIN_EDIT_SUCCESS', new_username, request.remote_addr, f"User updated: {', '.join(changes)}")
            return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_edit_user.html', user=user)


@app.route('/webauthn/register/begin', methods=['POST'])
@login_required
def webauthn_register_begin():
    user = current_user

    registration_options = webauthn.generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=str(user.id).encode(),
        user_name=user.username,
        user_display_name=user.username,
        exclude_credentials=[
            {
                'id': cred.credential_id,
                'type': 'public-key',
                'transports': cred.transports.split(',') if cred.transports else None,
            }
            for cred in user.credentials
        ],
        # More permissive configuration for macOS Touch ID compatibility
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED,  # Prefer user verification
            # Remove authenticator_attachment to allow both platform and cross-platform
        ),
    )

    session['challenge'] = bytes_to_base64url(registration_options.challenge)

    return jsonify(json.loads(webauthn.options_to_json(registration_options)))


@app.route('/webauthn/login/check', methods=['POST'])
def webauthn_login_check():
    username = request.json.get('username')
    user = User.query.filter_by(username=username).first()
    if user and user.credentials:
        return jsonify({'is_registered': True})
    return jsonify({'is_registered': False})


@app.route('/webauthn/login/begin', methods=['POST'])
def webauthn_login_begin():
    username = request.json.get('username')
    user = User.query.filter_by(username=username).first()

    if not user or not user.credentials:
        return jsonify({'error': 'User not found or no credentials registered'}), 404

    # Import the proper credential descriptor struct, type enum, and transport enum
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor, PublicKeyCredentialType, AuthenticatorTransport
    
    # Helper function to convert transport strings to enums
    def get_transport_enum(transport_str):
        transport_map = {
            'usb': AuthenticatorTransport.USB,
            'nfc': AuthenticatorTransport.NFC,
            'ble': AuthenticatorTransport.BLE,
            'internal': AuthenticatorTransport.INTERNAL,
            'hybrid': AuthenticatorTransport.HYBRID,
        }
        return transport_map.get(transport_str.lower(), AuthenticatorTransport.INTERNAL)
    
    authentication_options = webauthn.generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                id=cred.credential_id,
                type=PublicKeyCredentialType.PUBLIC_KEY,
                transports=[get_transport_enum(t.strip()) for t in cred.transports.split(',')] if cred.transports else [AuthenticatorTransport.INTERNAL]
            )
            for cred in user.credentials
        ],
        user_verification=UserVerificationRequirement.DISCOURAGED,
    )

    session['challenge'] = bytes_to_base64url(authentication_options.challenge)
    session['user_id_for_webauthn'] = user.id

    return jsonify(json.loads(webauthn.options_to_json(authentication_options)))


@app.route('/webauthn/login/complete', methods=['POST'])
def webauthn_login_complete():
    challenge = base64url_to_bytes(session.pop('challenge', ''))
    user_id = session.pop('user_id_for_webauthn', None)
    user = User.query.get(user_id)

    if not user:
        return jsonify({'verified': False, 'error': 'User not found'}), 404

    body = request.get_json()
    # Create AuthenticationCredential object with properly structured response
    from webauthn.helpers.structs import AuthenticatorAssertionResponse
    
    credential = AuthenticationCredential(
        id=body['id'],
        raw_id=base64url_to_bytes(body['rawId']),
        response=AuthenticatorAssertionResponse(
            client_data_json=base64url_to_bytes(body['response']['clientDataJSON']),
            authenticator_data=base64url_to_bytes(body['response']['authenticatorData']),
            signature=base64url_to_bytes(body['response']['signature']),
            user_handle=base64url_to_bytes(body['response']['userHandle']) if body['response'].get('userHandle') else None
        ),
        type=body['type']
    )

    try:
        verified_credential = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=user.credentials[0].public_key, # Simplified for one credential
            credential_current_sign_count=user.credentials[0].sign_count,
            require_user_verification=False,
        )
    except Exception as e:
        return jsonify({'verified': False, 'error': str(e)})

    # Update the sign count
    cred_to_update = WebAuthnCredential.query.filter_by(credential_id=verified_credential.credential_id).first()
    cred_to_update.sign_count = verified_credential.new_sign_count
    db.session.commit()

    login_user(user)
    flash('You have successfully logged in with your security key.', 'success')
    log_security_event('WEBAUTHN_LOGIN_SUCCESS', user.username, request.remote_addr, f'WebAuthn login successful')
    # Use direct path for redirect to avoid any routing issues
    return jsonify({'verified': True, 'redirect': '/homepage?t=' + str(int(time.time()))})


@app.route('/webauthn/register/complete', methods=['POST'])
@login_required
def webauthn_register_complete():
    user = current_user
    challenge = base64url_to_bytes(session.pop('challenge', ''))

    body = request.get_json()
    # Create RegistrationCredential object with properly structured response
    from webauthn.helpers.structs import AuthenticatorAttestationResponse
    
    credential = RegistrationCredential(
        id=body['id'],
        raw_id=base64url_to_bytes(body['rawId']),
        response=AuthenticatorAttestationResponse(
            client_data_json=base64url_to_bytes(body['response']['clientDataJSON']),
            attestation_object=base64url_to_bytes(body['response']['attestationObject'])
        ),
        type=body['type']
    )

    try:
        verified_credential = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            require_user_verification=False,  # For simplicity
        )
    except Exception as e:
        return jsonify({'verified': False, 'error': str(e)})

    # Debug: Print available attributes
    print("VerifiedRegistration attributes:", dir(verified_credential))
    print("VerifiedRegistration object:", verified_credential)
    
    # Use correct attributes from VerifiedRegistration object
    new_credential = WebAuthnCredential(
        user_id=user.id,
        credential_id=verified_credential.credential_id,
        public_key=verified_credential.credential_public_key,  # Correct attribute name
        sign_count=verified_credential.sign_count,
        transports=','.join(verified_credential.credential_device_type) if hasattr(verified_credential, 'credential_device_type') and verified_credential.credential_device_type else None,
    )
    db.session.add(new_credential)
    db.session.commit()

    return jsonify({'verified': True})

# Command to create the database
@app.cli.command('init-db')
def init_db_command():
    """Creates the database tables."""
    with app.app_context():
        db.create_all()
    print('Initialized the database.')

# Chat functionality
# Store active users and chat history in memory
# In a production environment, you would use a database
active_users = {}
chat_history = {}
MAX_HISTORY = 100  # Maximum number of messages to store per room

@app.route('/chat')
@login_required
def chat():
    """Main chat page with sidebar of conversations"""
    # Get all accepted chat requests for the current user
    sent_requests = ChatRequest.query.filter_by(
        sender_id=current_user.id, 
        status='accepted'
    ).all()
    
    received_requests = ChatRequest.query.filter_by(
        receiver_id=current_user.id, 
        status='accepted'
    ).all()
    
    # Get all pending requests
    pending_requests = ChatRequest.query.filter_by(
        receiver_id=current_user.id, 
        status='pending'
    ).all()
    
    # Combine contacts from sent and received requests
    contacts = []
    for req in sent_requests:
        contacts.append({
            'user_id': req.receiver_id,
            'username': req.receiver.username,
            'chat_id': req.id
        })
    
    for req in received_requests:
        contacts.append({
            'user_id': req.sender_id,
            'username': req.sender.username,
            'chat_id': req.id
        })
    
    # Log user accessing chat
    log_security_event(
        'chat_access', 
        username=current_user.username,
        ip_address=request.remote_addr,
        details={'action': 'view_chat_page'}
    )
    
    return render_template('chat.html', 
                           username=current_user.username,
                           contacts=contacts,
                           pending_requests=pending_requests)

@app.route('/chat/search', methods=['POST'])
@login_required
def search_users():
    """Search for users to chat with"""
    search_term = sanitize_input(request.form.get('search_term', ''))
    
    if not search_term or len(search_term) < 3:
        return jsonify({'error': 'Search term must be at least 3 characters'}), 400
    
    # Search for users with similar username
    users = User.query.filter(
        User.username.ilike(f'%{search_term}%'),
        User.id != current_user.id  # Exclude current user
    ).limit(10).all()
    
    # Format results
    results = []
    for user in users:
        # Check if a chat request already exists
        existing_request = ChatRequest.query.filter(
            ((ChatRequest.sender_id == current_user.id) & (ChatRequest.receiver_id == user.id)) |
            ((ChatRequest.sender_id == user.id) & (ChatRequest.receiver_id == current_user.id))
        ).first()
        
        status = None
        if existing_request:
            status = existing_request.status
        
        results.append({
            'id': user.id,
            'username': user.username,
            'status': status
        })
    
    # Log search action
    log_security_event(
        'chat_search', 
        username=current_user.username,
        ip_address=request.remote_addr,
        details={'search_term': search_term, 'results_count': len(results)}
    )
    
    return jsonify({'users': results})

@app.route('/chat/request', methods=['POST'])
@login_required
def send_chat_request():
    """Send a chat request to another user"""
    receiver_id = request.form.get('receiver_id')
    
    if not receiver_id:
        return jsonify({'error': 'Receiver ID is required'}), 400
    
    try:
        receiver_id = int(receiver_id)
    except ValueError:
        return jsonify({'error': 'Invalid receiver ID'}), 400
    
    # Check if receiver exists
    receiver = User.query.get(receiver_id)
    if not receiver:
        return jsonify({'error': 'User not found'}), 404
    
    # Check if a request already exists
    existing_request = ChatRequest.query.filter(
        ((ChatRequest.sender_id == current_user.id) & (ChatRequest.receiver_id == receiver_id)) |
        ((ChatRequest.sender_id == receiver_id) & (ChatRequest.receiver_id == current_user.id))
    ).first()
    
    if existing_request:
        return jsonify({
            'error': 'A chat request already exists',
            'status': existing_request.status
        }), 400
    
    # Create new chat request
    chat_request = ChatRequest(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        status='pending'
    )
    
    db.session.add(chat_request)
    
    try:
        db.session.commit()
        
        # Log chat request
        log_security_event(
            'chat_request_sent', 
            username=current_user.username,
            ip_address=request.remote_addr,
            details={'receiver_id': receiver_id, 'receiver_username': receiver.username}
        )
        
        return jsonify({
            'success': True,
            'message': f'Chat request sent to {receiver.username}'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/chat/request/<int:request_id>', methods=['POST'])
@login_required
def handle_chat_request(request_id):
    """Accept or reject a chat request"""
    action = request.form.get('action')
    
    if action not in ['accept', 'reject']:
        return jsonify({'error': 'Invalid action'}), 400
    
    # Find the chat request
    chat_request = ChatRequest.query.filter_by(
        id=request_id,
        receiver_id=current_user.id,  # Ensure the current user is the receiver
        status='pending'
    ).first()
    
    if not chat_request:
        return jsonify({'error': 'Chat request not found or already processed'}), 404
    
    # Update request status
    chat_request.status = 'accepted' if action == 'accept' else 'rejected'
    
    try:
        db.session.commit()
        
        # Log action
        log_security_event(
            f'chat_request_{action}ed', 
            username=current_user.username,
            ip_address=request.remote_addr,
            details={'request_id': request_id, 'sender_username': chat_request.sender.username}
        )
        
        return jsonify({
            'success': True,
            'message': f'Chat request {action}ed'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/chat/<int:user_id>')
@login_required
def private_chat(user_id):
    """Private chat with a specific user"""
    # Check if the user exists
    chat_partner = User.query.get(user_id)
    if not chat_partner:
        flash('User not found', 'error')
        return redirect(url_for('chat'))
    
    # Check if there's an accepted chat request between the users
    chat_request = ChatRequest.query.filter(
        ((ChatRequest.sender_id == current_user.id) & (ChatRequest.receiver_id == user_id) & (ChatRequest.status == 'accepted')) |
        ((ChatRequest.sender_id == user_id) & (ChatRequest.receiver_id == current_user.id) & (ChatRequest.status == 'accepted'))
    ).first()
    
    if not chat_request:
        flash('You do not have permission to chat with this user', 'error')
        return redirect(url_for('chat'))
    
    # Get chat history
    messages = ChatMessage.query.filter(
        ((ChatMessage.sender_id == current_user.id) & (ChatMessage.receiver_id == user_id)) |
        ((ChatMessage.sender_id == user_id) & (ChatMessage.receiver_id == current_user.id))
    ).order_by(ChatMessage.created_at).all()
    
    # Decrypt messages for display
    for msg in messages:
        # Store the encrypted message for reference
        msg.encrypted_message = msg.message
        # Decrypt the message for display
        msg.message = decrypt_message(msg.message)
    
    # Mark unread messages as read
    unread_messages = ChatMessage.query.filter_by(
        sender_id=user_id,
        receiver_id=current_user.id,
        read=False
    ).all()
    
    for msg in unread_messages:
        msg.read = True
    
    db.session.commit()
    
    # Log chat access
    log_security_event(
        'private_chat_access', 
        username=current_user.username,
        ip_address=request.remote_addr,
        details={'partner_id': user_id, 'partner_username': chat_partner.username}
    )
    
    return render_template('private_chat.html',
                           username=current_user.username,
                           partner=chat_partner,
                           messages=messages)

# Track online users
online_users = {}

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('status', {'message': 'Connected to server'})
    
@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    if 'user_id' in session:
        user_id = session['user_id']
        
        # Remove user from online users
        if user_id in online_users:
            del online_users[user_id]
        
        # Notify all users that this user is offline
        emit('user_offline', {'user_id': user_id}, broadcast=True)
        
        # Log user disconnection
        log_security_event(
            'chat_disconnect', 
            username=current_user.username if current_user.is_authenticated else None,
            ip_address=request.remote_addr,
            details={'user_id': user_id}
        )

@socketio.on('user_online')
def handle_user_online(data):
    """Handle user coming online"""
    if not current_user.is_authenticated:
        return
    
    user_id = current_user.id
    
    # Store user session data
    session['user_id'] = user_id
    
    # Mark user as online
    online_users[user_id] = request.sid
    
    # Notify all users that this user is online
    emit('user_online', {'user_id': user_id, 'username': current_user.username}, broadcast=True)
    
    # Log user coming online
    log_security_event(
        'chat_online', 
        username=current_user.username,
        ip_address=request.remote_addr,
        details={'user_id': user_id}
    )

@socketio.on('join_private_chat')
def handle_join_private_chat(data):
    """Handle user joining a private chat"""
    if not current_user.is_authenticated:
        return
    
    partner_id = data.get('partner_id')
    
    if not partner_id:
        return
    
    try:
        partner_id = int(partner_id)
    except ValueError:
        return
    
    # Create a unique room name for these two users
    # Sort the IDs to ensure the same room name regardless of who initiates
    user_ids = sorted([current_user.id, partner_id])
    room = f"private_{user_ids[0]}_{user_ids[1]}"
    
    # Join the room
    join_room(room)
    
    # Store the room in session
    session['current_room'] = room
    
    # Log joining private chat
    log_security_event(
        'join_private_chat', 
        username=current_user.username,
        ip_address=request.remote_addr,
        details={'partner_id': partner_id, 'room': room}
    )

@socketio.on('leave_private_chat')
def handle_leave_private_chat():
    """Handle user leaving a private chat"""
    if not current_user.is_authenticated or 'current_room' not in session:
        return
    
    room = session['current_room']
    
    # Leave the room
    leave_room(room)
    
    # Remove room from session
    session.pop('current_room', None)
    
    # Log leaving private chat
    log_security_event(
        'leave_private_chat', 
        username=current_user.username,
        ip_address=request.remote_addr,
        details={'room': room}
    )

@socketio.on('send_private_message')
def handle_private_message(data):
    """Handle new private chat message"""
    if not current_user.is_authenticated:
        return
    
    receiver_id = data.get('receiver_id')
    message_text = sanitize_input(data.get('message', '').strip())
    
    if not receiver_id or not message_text:
        return
    
    try:
        receiver_id = int(receiver_id)
    except ValueError:
        return
    
    # Check if there's an accepted chat request between the users
    chat_request = ChatRequest.query.filter(
        ((ChatRequest.sender_id == current_user.id) & (ChatRequest.receiver_id == receiver_id) & (ChatRequest.status == 'accepted')) |
        ((ChatRequest.sender_id == receiver_id) & (ChatRequest.receiver_id == current_user.id) & (ChatRequest.status == 'accepted'))
    ).first()
    
    if not chat_request:
        emit('error', {'message': 'You do not have permission to message this user'})
        return
    
    # Create new message in database - encrypt the message before storing
    encrypted_message = encrypt_message(message_text)
    new_message = ChatMessage(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        message=encrypted_message,
        read=False
    )
    
    db.session.add(new_message)
    
    try:
        db.session.commit()
        
        # Create message object for Socket.IO
        timestamp = new_message.created_at.strftime('%Y-%m-%d %H:%M:%S')
        msg_obj = {
            'id': new_message.id,
            'sender_id': current_user.id,
            'sender_username': current_user.username,
            'receiver_id': receiver_id,
            'message': message_text,  # Send original message to client
            'encrypted': encrypted_message,  # Also send encrypted version for verification
            'timestamp': timestamp,
            'read': False
        }
        
        # Create a unique room name for these two users
        user_ids = sorted([current_user.id, receiver_id])
        room = f"private_{user_ids[0]}_{user_ids[1]}"
        
        # Send to the room (both sender and receiver if they're in the room)
        emit('private_message', msg_obj, room=room)
        
        # If receiver is online but not in the room, notify them about new message
        if receiver_id in online_users:
            receiver_sid = online_users[receiver_id]
            emit('new_message_notification', {
                'from_id': current_user.id,
                'from_username': current_user.username,
                'message_preview': message_text[:30] + '...' if len(message_text) > 30 else message_text
            }, room=receiver_sid)
        
        # Log message sent
        log_security_event(
            'private_message_sent', 
            username=current_user.username,
            ip_address=request.remote_addr,
            details={
                'receiver_id': receiver_id,
                'message_length': len(message_text),
                'message_id': new_message.id
            }
        )
    except Exception as e:
        db.session.rollback()
        emit('error', {'message': 'Failed to send message'})

@socketio.on('mark_messages_read')
def handle_mark_read(data):
    """Mark messages as read"""
    if not current_user.is_authenticated:
        return
    
    sender_id = data.get('sender_id')
    
    if not sender_id:
        return
    
    try:
        sender_id = int(sender_id)
    except ValueError:
        return
    
    # Mark all unread messages from this sender as read
    unread_messages = ChatMessage.query.filter_by(
        sender_id=sender_id,
        receiver_id=current_user.id,
        read=False
    ).all()
    
    if not unread_messages:
        return
    
    message_ids = []
    for msg in unread_messages:
        msg.read = True
        message_ids.append(msg.id)
    
    try:
        db.session.commit()
        
        # Create a unique room name for these two users
        user_ids = sorted([current_user.id, sender_id])
        room = f"private_{user_ids[0]}_{user_ids[1]}"
        
        # Notify the room that messages were read
        emit('messages_read', {
            'reader_id': current_user.id,
            'message_ids': message_ids
        }, room=room)
        
        # Log messages read
        log_security_event(
            'messages_marked_read', 
            username=current_user.username,
            ip_address=request.remote_addr,
            details={
                'sender_id': sender_id,
                'message_count': len(message_ids)
            }
        )
    except Exception as e:
        db.session.rollback()

@socketio.on('get_online_status')
def handle_get_online_status(data):
    """Get online status of users"""
    if not current_user.is_authenticated:
        return
    
    user_ids = data.get('user_ids', [])
    
    if not user_ids or not isinstance(user_ids, list):
        return
    
    # Check which users are online
    online_statuses = {}
    for user_id in user_ids:
        try:
            user_id = int(user_id)
            online_statuses[user_id] = user_id in online_users
        except ValueError:
            continue
    
    emit('online_status', {'statuses': online_statuses})

# Chatbot routes
@app.route('/chatbot')
@login_required
def chatbot():
    """Render the chatbot page"""
    return render_template('Chatbot/chatbot.html')

@app.route('/chatbot/message', methods=['POST'])
@login_required
def chatbot_message():
    """Handle chat messages and return AI responses"""
    try:
        # Ensure the request has JSON data
        if not request.is_json:
            app.logger.error("Chatbot error: Request is not JSON")
            return jsonify({'error': True, 'response': 'Invalid request format'}), 400
            
        # Get message from request
        data = request.get_json()
        if not data or 'message' not in data:
            app.logger.error("Chatbot error: No message in request")
            return jsonify({'error': True, 'response': 'No message provided'}), 400
            
        # CSRF token is now handled by Flask-WTF via the X-CSRFToken header
            
        user_message = sanitize_input(data.get('message', ''))
        
        if not user_message or not user_message.strip():
            return jsonify({'error': True, 'response': 'Please enter a message.'}), 400
        
        # Log the chat request for security monitoring
        log_security_event('CHATBOT_MESSAGE', current_user.username, request.remote_addr, 
                         f'Message length: {len(user_message)}')
        
        try:
            # Generate a response using the AI
            response = generate_ai_response(user_message, current_user.username)
            return jsonify({'response': response})
            
        except Exception as ai_error:
            app.logger.error(f"AI generation error: {str(ai_error)}", exc_info=True)
            return jsonify({
                'error': True, 
                'response': 'I had trouble generating a response. Please try again.'
            }), 500
            
    except Exception as e:
        app.logger.error(f"Chatbot error: {str(e)}", exc_info=True)
        return jsonify({
            'error': True, 
            'response': 'Sorry, I encountered an error processing your request.'
        }), 500

@app.route('/chat', methods=['POST'])
@login_required
def chat_message():
    """Handle chat messages and return AI responses"""
    try:
        # Get message from request
        data = request.get_json()
        user_message = sanitize_input(data.get('message', ''))
        
        if not user_message:
            return jsonify({'error': True, 'response': 'Please enter a message.'})
        
        # Log the chat request for security monitoring
        log_security_event('CHATBOT_MESSAGE', current_user.username, request.remote_addr, 
                          f'Message length: {len(user_message)}')
        
        # Simple response logic - in a real app, this would call an AI service
        # For now, we'll implement a simple rule-based response system
        response = generate_ai_response(user_message, current_user.username)
        
        return jsonify({'response': response})
        
    except Exception as e:
        app.logger.error(f"Chat error: {str(e)}")
        return jsonify({'error': True, 'response': 'Sorry, I encountered an error processing your request.'})

def generate_ai_response(message, username):
    """Generate a response to the user's message using Google's Gemini AI with fallback responses"""
    # Define fallback responses for when the API is unavailable
    FALLBACK_RESPONSES = [
        "I'm currently experiencing high demand. Here's a helpful tip: Remember to stay hydrated and take regular breaks! 🚰",
        f"Hi {username}! I'm currently at capacity, but I can still help with general wellness tips. Have you taken a moment to stretch today?",
        "Thanks for your message! I'm temporarily unavailable, but here's a quick health tip: A 5-minute walk can boost your mood and energy levels! 🚶‍♂️",
        f"Hello {username}! While I'm unable to process your request right now, I recommend checking out our health resources in the dashboard.",
        "I'm currently unavailable, but I'd love to help! In the meantime, have you tried our daily check-in feature?"
    ]
    
    # Select a random fallback response
    fallback_response = random.choice(FALLBACK_RESPONSES)
    
    try:
        # These imports are now at the top of the file
        import socket
        from dotenv import load_dotenv
        import time
        
        # Debug: Check network connectivity
        try:
            socket.create_connection(("www.google.com", 80), timeout=5)
            app.logger.info("Network connectivity check passed")
        except OSError:
            app.logger.error("No internet connection detected")
            return "I'm having trouble connecting to the internet. Please check your network connection and try again."
        
        # Try to get API key directly from environment first (for cloud environments like Render)
        api_key = os.environ.get('GEMINI_API_KEY')
        
        # If not found, try loading from local .env file as fallback (for local development)
        if not api_key:
            env_path = os.path.join(os.path.dirname(__file__), '.env')
            app.logger.info(f"API key not found in environment, trying to load from: {env_path}")
            load_dotenv(dotenv_path=env_path, override=False)
            api_key = os.environ.get('GEMINI_API_KEY')
            
        # Log first 5 characters of API key for verification (if found)
        if not api_key:
            app.logger.error("GEMINI_API_KEY not found in environment variables")
            return "I'm having trouble connecting to the AI service. (Error: API key not configured)"
            
        app.logger.info(f"Found GEMINI_API_KEY (starts with: {api_key[:5]}...)")
        
        try:
            # Try a direct API test first
            test_url = "https://generativelanguage.googleapis.com/v1beta/models"
            params = {'key': api_key}
            app.logger.info(f"Testing API connectivity to {test_url}")
            try:
                response = requests.get(test_url, params=params, timeout=10)
                app.logger.info(f"API test response status: {response.status_code}")
                
                if response.status_code != 200:
                    app.logger.error(f"API test failed with status {response.status_code}: {response.text}")
                    return f"I'm having trouble connecting to the AI service. (API Error: {response.status_code}: {response.text[:100]})"
            except requests.exceptions.RequestException as req_err:
                app.logger.error(f"API test request failed: {str(req_err)}")
                return f"I'm having trouble connecting to the AI service. (Request Error: {str(req_err)})"
            
            # If API test passed, try using the SDK
            genai.configure(api_key=api_key)
            
            # Use the Flash model for faster responses
            model_name = 'gemini-1.5-flash'
            app.logger.info(f"Using model: {model_name}")
            
            # Initialize the model with a timeout
            model = genai.GenerativeModel(model_name)
            
            # Create a prompt with context
            prompt = f"""You are a helpful and friendly AI assistant for WellNest, a health and wellness platform. 
            The user's name is {username}. Provide a concise, helpful response to their message.
            
            User's message: {message}
            
            Response:"""
            
            # Generate response with timeout
            try:
                app.logger.info(f"Sending prompt to Gemini API (length: {len(prompt)})")
                response = model.generate_content(prompt)
                app.logger.info("Received response from Gemini API")
                
                if response and hasattr(response, 'text'):
                    app.logger.info(f"Successful response received (length: {len(response.text)})")
                    return response.text
                else:
                    app.logger.warning(f"Unexpected response format from Gemini API: {type(response)} - {str(response)[:200]}")
                    return fallback_response
                    
            except Exception as api_error:
                error_msg = str(api_error)
                app.logger.error(f"Gemini API call failed: {error_msg}", exc_info=True)
                
                # Detailed error diagnostics
                error_type = type(api_error).__name__
                app.logger.error(f"Error type: {error_type}")
                
                # Check for common error patterns
                if "quota" in error_msg.lower() or "rate limit" in error_msg.lower():
                    app.logger.error("API quota or rate limit exceeded")
                    return "I'm currently at capacity. Please try again in a little while. In the meantime, here's a health tip: Taking deep breaths can help reduce stress!"
                elif "timed out" in error_msg.lower():
                    app.logger.error("API request timed out")
                    return "The AI service is taking too long to respond. Please try again in a moment."
                elif "authentication" in error_msg.lower() or "auth" in error_msg.lower() or "key" in error_msg.lower():
                    app.logger.error("API authentication error - likely invalid API key")
                    return "I'm having trouble authenticating with the AI service. Please check the API key configuration."
                elif "model" in error_msg.lower() and ("not found" in error_msg.lower() or "invalid" in error_msg.lower()):
                    app.logger.error(f"Invalid model name: {model_name}")
                    return "I'm having trouble with the AI model configuration. Please try again later."
                
                return fallback_response
            
        except requests.exceptions.RequestException as req_err:
            app.logger.error(f"Network error during API request: {str(req_err)}")
            return "I'm having trouble connecting to the AI service. Please check your internet connection and try again."
            
        except Exception as ai_error:
            app.logger.error(f"AI service error: {str(ai_error)}", exc_info=True)
            return fallback_response
        
    except Exception as e:
        app.logger.error(f"Unexpected error in generate_ai_response: {str(e)}", exc_info=True)
        return fallback_response

@app.route('/debug/routes')
def list_routes():
    """Debug endpoint to list all registered routes"""
    import urllib.parse
    output = []
    for rule in app.url_map.iter_rules():
        methods = ','.join(rule.methods)
        line = urllib.parse.unquote(f"{rule.endpoint:50s} {methods:20s} {rule}")
        output.append(line)
    return '<pre>' + '\n'.join(sorted(output)) + '</pre>'

if __name__ == '__main__':
    # For better WebAuthn support, try HTTPS
    # socketio.run(app, debug=True, ssl_context='adhoc', port=5001)  # Uncomment for HTTPS
    socketio.run(app, debug=True, port=5001)
