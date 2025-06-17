import os

# Core configuration
workers = 4
bind = '0.0.0.0:' + os.getenv('PORT', '8000')
timeout = 120
keepalive = 5
worker_class = 'geventwebsocket.gunicorn.workers.GeventWebSocketWorker'
