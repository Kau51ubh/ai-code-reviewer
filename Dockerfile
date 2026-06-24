# Explicit container build for Cloud Run. Having this file makes
# `gcloud run deploy --source .` use Docker instead of buildpack auto-detection
# (which failed with "no buildpacks participating").
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /app

# Install deps first for layer caching.
COPY requirements.txt .
RUN pip install -r requirements.txt

# App code + data files (templates/, rules_*.txt, linter_rules.json, *.py).
COPY . .

# Cloud Run sends $PORT; bind to it. Same command as the Procfile.
ENV PORT=8080
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 main:app

