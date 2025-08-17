#!/usr/bin/env python3
"""
Test script to verify Gmail SMTP configuration
Run this to test your email setup before using the main app
"""

import os
from dotenv import load_dotenv
from flask import Flask
from flask_mailman import Mail, EmailMessage

# Load environment variables
load_dotenv()

# Create a minimal Flask app for testing
app = Flask(__name__)

# Configure Flask-Mailman with your settings
app.config['MAIL_BACKEND'] = 'smtp'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_TIMEOUT'] = 20

def test_email_config():
    """Test the email configuration"""
    print("Testing email configuration...")
    print(f"MAIL_USERNAME: {app.config['MAIL_USERNAME']}")
    print(f"MAIL_PASSWORD: {'*' * len(app.config['MAIL_PASSWORD']) if app.config['MAIL_PASSWORD'] else 'NOT SET'}")
    
    if not app.config['MAIL_USERNAME']:
        print("❌ ERROR: MAIL_USERNAME not found in .env file")
        return False
    
    if not app.config['MAIL_PASSWORD']:
        print("❌ ERROR: MAIL_PASSWORD not found in .env file")
        return False
    
    return True

def send_test_email():
    """Send a test email"""
    with app.app_context():
        mail = Mail(app)
        
        try:
            # Replace with your email for testing
            test_recipient = input("Enter your email address to test: ").strip()
            
            msg = EmailMessage(
                'Test Email from OTP App',
                'This is a test email to verify your Gmail SMTP configuration is working.',
                app.config['MAIL_DEFAULT_SENDER'],
                [test_recipient]
            )
            
            print("Sending test email...")
            msg.send()
            print("✅ SUCCESS: Test email sent successfully!")
            return True
            
        except Exception as e:
            print(f"❌ ERROR: Failed to send email")
            print(f"Error details: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

if __name__ == "__main__":
    print("=== Gmail SMTP Configuration Test ===")
    
    if test_email_config():
        print("\n✅ Configuration looks good!")
        print("\nAttempting to send test email...")
        send_test_email()
    else:
        print("\n❌ Configuration issues found. Please check your .env file.")
        print("\nYour .env file should contain:")
        print("MAIL_USERNAME=your_gmail@gmail.com")
        print("MAIL_PASSWORD=your_app_password_here")
        print("\nRemember: Use an App Password, not your regular Gmail password!")
