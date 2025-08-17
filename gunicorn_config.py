import multiprocessing

# Gunicorn configuration for Render deployment
bind = "0.0.0.0:$PORT"
workers = multiprocessing.cpu_count() * 2 + 1
threads = 4  # Increased threads since we're using thread-based workers
timeout = 120

# Use threads instead of gevent/eventlet to avoid Cython compilation issues
worker_class = "gthread"

accesslog = "-"
errorlog = "-"
loglevel = "info"
