# backend/Dockerfile
# Build context is the PROJECT ROOT (docker-compose.yml -> context: .)
# so all COPY paths below are relative to the repo root, not backend/.

# ---------- Stage 1: Build the React frontend ----------
FROM node:20-slim AS frontend-builder

WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
ARG REACT_APP_CARTO_KEY
ENV REACT_APP_CARTO_KEY=$REACT_APP_CARTO_KEY
RUN npm run build

# ---------- Stage 2: Python backend that serves the built frontend ----------
FROM python:3.11-slim

WORKDIR /app

# tcpdump / libpcap-dev are required by Scapy for raw packet capture.
# --no-install-recommends keeps the image lean.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tcpdump libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .

# compileall fails the build on a syntax error. main.py's setup_environment() creates
# logs/, data/preprocessed/ and models/ at every start, and .dockerignore keeps them out
# of the build context -- so create them here and hand them to the unprivileged user,
# otherwise the container dies with PermissionError on boot.
RUN python -m compileall -q . \
    && mkdir -p logs data/preprocessed models \
    && useradd --system --uid 10001 --no-create-home ids \
    && chown -R ids:ids logs data models

# Pull in the compiled React build from Stage 1.
# main.py resolves FRONTEND_DIR as os.path.join(BASE_DIR, '..', 'frontend', 'build')
# which equals /frontend/build inside the container (/app/../frontend/build).
COPY --from=frontend-builder /frontend/build /frontend/build

# The web/API process needs no privileges: it runs as an unprivileged user and binds
# 0.0.0.0 only inside the container (compose publishes the port on 127.0.0.1).
# Packet capture needs root + NET_RAW, so it lives in the separate `sniffer` service
# (docker-compose.yml, profile "capture"), which overrides `user:`.
ENV IDS_BIND=0.0.0.0
USER ids

EXPOSE 5000

CMD ["python", "main.py"]
