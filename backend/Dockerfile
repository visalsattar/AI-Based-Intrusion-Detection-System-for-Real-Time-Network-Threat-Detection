# backend/Dockerfile

# ---------- Stage 1: build the React frontend ----------
FROM node:20-slim AS frontend-builder

# Match the npm version that generated package-lock.json (the base image's
# bundled npm can otherwise misread the lock file and fail `npm ci`).
RUN npm install -g npm@latest

WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---------- Stage 2: Python backend, serving the built frontend ----------
FROM python:3.11-slim

WORKDIR /app

COPY backend/requirements.txt .

# Install dependencies (and some Linux network tools Scapy might need)
RUN apt-get update && apt-get install -y tcpdump
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .

# logs/ is excluded from the build context (.dockerignore) so stale
# local logs never get baked into the image -- but main.py's
# FileHandler('logs/ids.log') needs the directory to exist regardless.
RUN mkdir -p logs

# Pull in the compiled React build from the frontend-builder stage --
# main.py serves this directly as Flask's static folder, so there is no
# separate frontend container or dev server needed at runtime.
COPY --from=frontend-builder /frontend/build /frontend/build

EXPOSE 5000

CMD ["python", "main.py", "--mode", "dashboard"]