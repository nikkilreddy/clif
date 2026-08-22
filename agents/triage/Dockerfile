# =============================================================================
# CLIF Triage Agent v8.3 — Production Dockerfile
# =============================================================================
# LightGBM-only ML inference with 60-feature stateless extraction,
# EWMA rate tracking, kill-chain state machine,
# and parallel feature extraction.
#
# Input:  raw-logs, security-events, process-events, network-events (Kafka)
# Output: triage-scores, anomaly-alerts, hunter-tasks (Kafka)
# =============================================================================
FROM python:3.11-slim AS base

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System dependencies required by confluent-kafka (librdkafka)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        librdkafka-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --timeout 300 --retries 5 -r requirements.txt && \
    pip cache purge

# Copy application code
COPY config.py .
COPY ewma_tracker.py .
COPY kill_chain.py .
COPY feature_extractor.py .
COPY model_ensemble.py .
COPY score_fusion.py .
COPY shap_explainer.py .
COPY app.py .

# Models are mounted as a read-only volume at /models
# (see docker-compose.pc2.yml: ./agents/triage/models:/models:ro)
# Expected files:
#   /models/lgbm_v8.onnx
#   /models/feature_scaler_v8.json
#   /models/manifest_v8.json

EXPOSE 8300

HEALTHCHECK --interval=30s --timeout=10s --retries=5 --start-period=45s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8300/health')"

CMD ["python", "app.py"]
