# backend/Dockerfile
# Build context is the PROJECT ROOT (docker-compose.yml -> context: .)

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

COPY backend/requirements.txt .

RUN python -m compileall -q .

# tcpdump / libpcap-dev are required by Scapy for raw packet capture.
# --no-install-recommends keeps the image lean.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tcpdump libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .
RUN python -m compileall -q .
RUN mkdir -p logs

# logs/ is excluded from the build context (.dockerignore) so stale local
# logs never get baked into the image, but main.py's FileHandler needs the
# directory to exist at startup.
RUN mkdir -p logs

# Pull in the compiled React build from Stage 1.
# main.py resolves FRONTEND_DIR as os.path.join(BASE_DIR, '..', 'frontend', 'build')
# which equals /frontend/build inside the container (/app/../frontend/build).
COPY --from=frontend-builder /frontend/build /frontend/build

EXPOSE 5000

CMD ["python", "main.py"]
