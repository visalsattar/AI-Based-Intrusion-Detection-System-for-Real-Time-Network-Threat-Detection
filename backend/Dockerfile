# backend/Dockerfile
# Build context is the PROJECT ROOT (docker-compose.yml -> context: .)
# so all COPY paths below are relative to the repo root, not backend/.

# ---------- Stage 1: Build the React frontend ----------
FROM node:20-slim AS frontend-builder

# Match the npm version that generated package-lock.json so `npm ci`
# doesn't misread the lockfile on a different npm version.
RUN npm install -g npm@latest

WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---------- Stage 2: Python backend that serves the built frontend ----------
FROM python:3.11-slim

WORKDIR /app

COPY backend/requirements.txt .

# tcpdump / libpcap-dev are required by Scapy for raw packet capture.
# --no-install-recommends keeps the image lean.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tcpdump libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .

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
