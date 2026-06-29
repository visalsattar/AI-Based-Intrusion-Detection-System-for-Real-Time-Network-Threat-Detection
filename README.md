# A-IDS Command Center

An AI-Based Intrusion Detection System (IDS) engineered for real-time network traffic analysis, anomaly detection, and automated threat intelligence. Developed as a Final Year Project (FYP-II).

## 🏗️ System Architecture

This project is a fully containerized, full-stack application divided into three core microservices:

* **Frontend (User Interface):** Built with **React.js**. Provides a live, real-time command center dashboard to monitor network traffic, view geographic threat origins, and configure detection thresholds.
* **Backend (AI & Orchestration):** Built with **Python (Flask)**. Handles API routing, WebSocket bridging (via Flask-SocketIO), and network packet capture.
* **Database & Caching:** Powered by **Redis** (utilizing RedisJSON and RedisTimeSeries) for high-speed, in-memory alert queuing and state management.

The entire environment is orchestrated using **Docker** and **Docker Compose**, ensuring seamless deployment and complete environment isolation.

## 🧠 How the AI Intrusion Detection Works

The core of the IDS is powered by a **TensorFlow Deep Learning Autoencoder**.

Instead of relying on outdated signature-based detection (which only catches known viruses), this AI is trained purely on *normal* network traffic.
1. **Traffic Capture:** The backend sniffs live network packets.
2. **Feature Extraction:** Packet metadata (sizes, intervals, protocols) is fed into the neural network.
3. **Reconstruction & Scoring:** The autoencoder attempts to reconstruct the traffic pattern. If the traffic is normal, the reconstruction error is extremely low. If the traffic behaves like a cyberattack (e.g., a DDoS attempt, port scan, or payload injection), the AI struggles to reconstruct it, resulting in a high anomaly score.
4. **Threat Intelligence:** High-scoring anomalies are instantly cross-referenced with the **AbuseIPDB API** to check for known malicious actor reputations before alerting the dashboard.

## 🚀 Quick Start (Local Development)

To run the system locally with both the frontend and backend synced:

1. Clone the repository.
2. Ensure Docker Desktop is running.
3. Install the unified task runner:
   ```bash
   npm instalL