"""LAB ONLY: opens many short TCP connections to YOUR OWN demo listener to trigger the
connection-rate rule. Private (LAN) targets only; rate and duration are capped.
Termux:  python lab_flood.py <laptop-ip> --seconds 60 --rate 220"""
import argparse, ipaddress, socket, time

ap = argparse.ArgumentParser()
ap.add_argument("target")
ap.add_argument("--port", type=int, default=8080)
ap.add_argument("--seconds", type=float, default=60)
ap.add_argument("--rate", type=float, default=220, help="connections per second (max 500)")
a = ap.parse_args()
if not ipaddress.ip_address(a.target).is_private:
    raise SystemExit("Refusing: target must be a private LAN address you own.")
rate, secs = min(a.rate, 500), min(a.seconds, 300)
print(f"Flooding {a.target}:{a.port} at ~{rate:.0f} conn/s for {secs:.0f} s")
end, gap, n, nxt = time.time() + secs, 1.0 / rate, 0, time.time()
while time.time() < end:
    try:
        with socket.create_connection((a.target, a.port), timeout=1) as s:
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        n += 1
    except OSError:
        pass
    nxt += gap
    d = nxt - time.time()
    if d > 0:
        time.sleep(d)
print(f"done: {n} connections")
