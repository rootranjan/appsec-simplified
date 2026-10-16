"""Mass assignment demo. Local only, stdlib only, in-memory data.

Run server:  python3 examples/mass-assignment/app.py
Self-test:   python3 examples/mass-assignment/app.py --selftest

Endpoints (POST JSON):
  /vuln/register   binds ALL fields from the request  -> vulnerable
  /safe/register   binds only allow-listed fields     -> fixed
"""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import Request, urlopen

ALLOWED_FIELDS = {"userid", "email", "password"}  # what a user may set at signup


class User:
    def __init__(self):
        self.userid = None
        self.email = None
        self.password = None
        self.is_admin = False          # server-controlled
        self.wallet_balance = 0        # server-controlled


def bind_all(obj, data):
    """What auto-binding frameworks effectively do: copy every key onto the object."""
    for key, value in data.items():
        setattr(obj, key, value)
    return obj


def bind_allowlisted(obj, data):
    """Fix: copy only fields the caller is allowed to set."""
    for key in ALLOWED_FIELDS & data.keys():
        setattr(obj, key, data[key])
    return obj


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        binder = {"/vuln/register": bind_all, "/safe/register": bind_allowlisted}.get(self.path)
        if binder is None:
            self.send_response(404); self.end_headers(); return
        user = binder(User(), body)
        out = json.dumps({k: v for k, v in vars(user).items() if k != "password"}).encode()
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


def post(port, path, payload):
    req = Request(f"http://127.0.0.1:{port}{path}", json.dumps(payload).encode(),
                  {"Content-Type": "application/json"})
    return json.load(urlopen(req))


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8000), Handler)  # localhost only
    if "--selftest" in sys.argv:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        attack = {"userid": "bobby", "email": "b@x.in", "password": "p",
                  "is_admin": True, "wallet_balance": 100000}
        print("vuln:", post(8000, "/vuln/register", attack))   # is_admin True, balance 100000
        print("safe:", post(8000, "/safe/register", attack))   # is_admin False, balance 0
    else:
        print("Listening on http://127.0.0.1:8000")
        server.serve_forever()
