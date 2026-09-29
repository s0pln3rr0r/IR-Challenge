#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler,HTTPServer
from pathlib import Path
import os
out=Path(os.environ.get("SIXWAYS_RUNTIME","./runtime"))/"received"
try: out.mkdir(parents=True)
except FileExistsError: pass
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get("Content-Length","0")); b=self.rfile.read(n)
        with open(str(out/"http_payload.b64"),'wb') as f: f.write(b)
        self.send_response(200); self.end_headers(); self.wfile.write(b"OK")
    def log_message(self,*x): print(*x)
HTTPServer(("0.0.0.0",80),H).serve_forever()
