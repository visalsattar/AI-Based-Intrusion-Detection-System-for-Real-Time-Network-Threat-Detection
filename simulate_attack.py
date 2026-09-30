"""Generate a small amount of HTTP test traffic to an explicitly chosen lab host.

This is not a DoS tool. Localhost and dashboard traffic do not test the NIC capture
path. Only point this at a lab service you control.
"""
import os
import socket

target = os.environ.get("IDS_TEST_TARGET")
port = int(os.environ.get("IDS_TEST_PORT", "8080"))
count = min(max(int(os.environ.get("IDS_TEST_REQUESTS", "20")), 1), 100)
if not target:
    raise SystemExit("Set IDS_TEST_TARGET to an IP address of a lab host you control.")
if port in {5000, 6379, 6380}:
    raise SystemExit("Choose a lab service port other than dashboard/Redis ports 5000, 6379, or 6380.")

print(f"Sending {count} low-rate HTTP requests to {target}:{port}.")
print("This creates traffic but does not guarantee an IDS alert.")
connected = 0
for _ in range(count):
    try:
        with socket.create_connection((target, port), timeout=1) as sock:
            request = f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
            sock.sendall(request.encode())
            connected += 1
    except OSError as exc:
        print(f"Connection failed: {exc}")
print(f"Completed: {connected}/{count} connections.")
