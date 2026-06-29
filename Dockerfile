# backend/Dockerfile
# Use official Python image
FROM python:3.11-slim

# Set the working directory inside the container
WORKDIR /app

# Copy your requirements first (for caching)
COPY requirements.txt .

# Install dependencies (and some Linux network tools Scapy might need)
RUN apt-get update && apt-get install -y tcpdump
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your backend code into the container
COPY . .

# logs/ is excluded from the build context (.dockerignore) so stale
# local logs never get baked into the image -- but main.py's
# FileHandler('logs/ids.log') needs the directory to exist regardless.
RUN mkdir -p logs

# Expose the port Flask runs on
EXPOSE 5000

# The default command when the container starts (Starts the dashboard by default)
CMD ["python", "main.py", "--mode", "dashboard"]