"""LAB ONLY: human-paced requests (about 1 every 2 s) to the demo listener, to show that
normal traffic does NOT raise a flood alert.  python lab_benign.py <laptop-ip> --seconds 60"""
import argparse, random, socket, time

ap = argparse.ArgumentParser()
ap.add_argument("target")
ap.add_argument("--port", type=int, default=8080)
ap.add_argument("--seconds", type=float, default=60)
a = ap.parse_args()
end, n = time.time() + a.seconds, 0
while time.time() < end:
    try:
        with socket.create_connection((a.target, a.port), timeout=2) as s:
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            s.recv(1024)
        n += 1
    except OSError:
        pass
    time.sleep(random.uniform(1, 3))
print(f"done: {n} requests")
