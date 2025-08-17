import multiprocessing

# Gunicorn configuration for Render deployment
bind = "0.0.0.0:$PORT"
workers = multiprocessing.cpu_count() * 2 + 1
threads = 2
timeout = 120

# Use gevent instead of eventlet to avoid compatibility issues
worker_class = "gevent"

accesslog = "-"
errorlog = "-"
loglevel = "info"
