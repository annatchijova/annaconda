# VIGIA live purple-team backend for Google Cloud Run.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

WORKDIR /app

# Dependencies first, for layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code. The forensic core is stdlib-only; the bundled demo
# evidence (tests/fixtures/velociraptor) lets the service run without a live
# Velociraptor endpoint until the lab is wired.
COPY . .

# Cloud Run sends traffic to $PORT. Shell form so the variable expands.
CMD exec uvicorn service.app:app --host 0.0.0.0 --port ${PORT}
