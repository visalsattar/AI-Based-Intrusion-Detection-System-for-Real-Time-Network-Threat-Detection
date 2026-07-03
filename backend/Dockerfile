# backend/Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (tcpdump/libpcap for network capture)
RUN apt-get update && apt-get install -y tcpdump libpcap-dev

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create logs directory
RUN mkdir -p logs

EXPOSE 5000

# Run the standard backend
CMD ["python", "main.py"]
