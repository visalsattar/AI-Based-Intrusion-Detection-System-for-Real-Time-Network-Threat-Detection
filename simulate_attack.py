import socket
import threading
import time

# Target your own local machine
TARGET_IP = '127.0.0.1' 
TARGET_PORT = 5000      

def simulate_attack_burst():
    """Spams rapid TCP connections to simulate a DoS / Port Scan anomaly."""
    for _ in range(200):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect((TARGET_IP, TARGET_PORT))
            s.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            s.close()
        except:
            pass

print(f"[*] Launching simulated attack against {TARGET_IP}:{TARGET_PORT}...")
print("[*] Generating high-frequency traffic to trigger AI anomaly detection...")

# Spawn 20 simultaneous attack threads to flood the network adapter
threads = []
for i in range(20):
    t = threading.Thread(target=simulate_attack_burst)
    t.start()
    threads.append(t)

for t in threads:
    t.join()

print("[+] Attack simulation complete. Check your dashboard!")