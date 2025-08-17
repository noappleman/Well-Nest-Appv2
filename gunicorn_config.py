import multiprocessing

# Gunicorn configuration for Render deployment
bind = "0.0.0.0:$PORT"
workers = multiprocessing.cpu_count() * 2 + 1
threads = 2
timeout = 120
worker_class = "eventlet"  # Using eventlet for WebSocket support
accesslog = "-"
errorlog = "-"
loglevel = "info"
