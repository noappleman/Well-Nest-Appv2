import os
from flask import Flask

def configure_recaptcha(app):
    """Configure reCAPTCHA for the Flask app using environment variables"""
    # Set reCAPTCHA configuration from environment variables
    app.config['RECAPTCHA_SITE_KEY'] = os.environ.get('RECAPTCHA_SITE_KEY')
    app.config['RECAPTCHA_SECRET_KEY'] = os.environ.get('RECAPTCHA_SECRET_KEY')
    
    return app
