web: waitress-serve --host=0.0.0.0 --port=${PORT:-5000} app:app
worker: python3 manage.py judge-worker
