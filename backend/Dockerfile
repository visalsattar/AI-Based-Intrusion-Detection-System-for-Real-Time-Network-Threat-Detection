# backend/Dockerfile
# Multi-stage build: compiles the React frontend AND runs the Python
# backend in one image. Build context is the PROJECT ROOT (see
# docker-compose.yml's `context: .`), so this file can see both
# frontend/ and backend/.
#
# Why: previously the React app had to be built manually on the host
# (`npm run build`) and bind-mounted into the container via
# docker-compose volumes. That meant "npm start" / "npm run build"
# were manual prerequisites, and the dashboard would 404 if you forgot.
# Now the image builds the frontend itself -- `docker-compose up --build`
# is the only command you ever need to run.

# ---------- Stage 1: build the React frontend ----------
FROM node:20-slim AS frontend-builder
RUN npm install -g npm@latest
WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---------- Stage 2: Python backend, serving the built frontend ----------
FROM python:3.11-slim
WORKDIR /app

# Copy requirements first (Docker layer caching: only reinstalls if
# requirements.txt actually changes)
COPY backend/requirements.txt .

# tcpdump: Linux network tools Scapy needs for real packet capture
RUN apt-get update && apt-get install -y tcpdump
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the backend code
COPY backend/ .

# logs/ is excluded from the build context (.dockerignore) so stale
# local logs never get baked into the image -- but main.py's
# FileHandler('logs/ids.log') needs the directory to exist regardless.
RUN mkdir -p logs

# Bring in the frontend build output from Stage 1. main.py's
# FRONTEND_DIR resolves to ../frontend/build relative to WORKDIR
# (/app), i.e. /frontend/build -- matching this exactly.
COPY --from=frontend-builder /frontend/build /frontend/build

EXPOSE 5000

CMD ["python", "main.py", "--mode", "dashboard"]
