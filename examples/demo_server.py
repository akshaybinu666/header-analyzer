"""A deliberately misconfigured local server for trying header-analyzer safely.

    python examples/demo_server.py          # serves on http://127.0.0.1:8099
    header-analyzer http://127.0.0.1:8099
"""
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'")
        self.send_header("Referrer-Policy", "unsafe-url")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("X-Powered-By", "PHP/7.4")
        self.send_header("Set-Cookie", "sid=abc123; Path=/")
        self.end_headers()
        self.wfile.write(b"demo")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("Demo server on http://127.0.0.1:8099 (Ctrl+C to stop)")
    HTTPServer(("127.0.0.1", 8099), Handler).serve_forever()
