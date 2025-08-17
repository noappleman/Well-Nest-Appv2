from flask import Flask, render_template_string, redirect
import sys
import os

# Create a simple Flask app for Vercel
app = Flask(__name__)

@app.route('/')
def home():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Well-Nest Application</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                margin: 0;
                padding: 20px;
                max-width: 800px;
                margin: 0 auto;
            }
            h1 {
                color: #333;
            }
            .container {
                border: 1px solid #ddd;
                padding: 20px;
                border-radius: 5px;
                background-color: #f9f9f9;
            }
            .info {
                color: #666;
            }
            .note {
                background-color: #fffacd;
                padding: 10px;
                border-left: 4px solid #ffd700;
                margin: 20px 0;
            }
        </style>
    </head>
    <body>
        <h1>Well-Nest Application</h1>
        <div class="container">
            <p>Welcome to the Well-Nest Application.</p>
            <p>This application is currently deployed on Vercel as a serverless function.</p>
            <div class="note">
                <p><strong>Note:</strong> Flask applications with complex dependencies may require additional configuration to run properly in a serverless environment.</p>
                <p>For the full application experience, you may need to deploy to a platform that better supports Flask applications with their full dependencies.</p>
            </div>
            <p class="info">This is a simplified version of the application running on Vercel.</p>
        </div>
    </body>
    </html>
    """)

@app.route('/login')
def login():
    return redirect('/')

# For local development
if __name__ == '__main__':
    app.run(debug=True)
