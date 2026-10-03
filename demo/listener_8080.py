"""Tiny HTTP target for the lab demo: serves on 0.0.0.0:8080 so another device (phone) can connect.
Run on the laptop that runs the capture:  python demo\listener_8080.py"""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print("Demo target listening on 0.0.0.0:8080 (Ctrl+C to stop)")
    ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
