# syntax=docker/dockerfile:1

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first so layer cache survives source-only changes.
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the package and install it editable so `python -m analyzer.run`
# works from any working directory inside the container.
COPY src/ ./src/
RUN pip install --no-cache-dir -e .

# Runtime files: config, dashboard, generator, ground truth.
COPY config/ ./config/
COPY dashboard/ ./dashboard/
COPY scripts/ ./scripts/
COPY sample_logs/expected_alerts.json ./sample_logs/expected_alerts.json

# Directories the runtime writes into. Created here so the volume mount
# at /app/data has somewhere to attach.
RUN mkdir -p /app/data /app/sample_logs

EXPOSE 8501

# Default CMD is the dashboard; docker-compose overrides it for the
# one-shot pipeline service.
CMD ["streamlit", "run", "dashboard/app.py", \
     "--server.address=0.0.0.0", \
     "--server.port=8501", \
     "--server.headless=true"]