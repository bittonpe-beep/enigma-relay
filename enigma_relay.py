#!/usr/bin/env python3
"""
ENIGMA-X RELAY  -  the tiny post office for ENIGMA-X messages.

Run it on any machine both people can reach (your own PC for testing, or a free
host like Render for the real internet):

    python enigma_relay.py              # listens on port 8765 (or $PORT)

What it does:
  * Each ENIGMA-X app has a computer code + a secret token. The first time a
    code connects, the relay remembers its token, so nobody else can read that
    inbox or send pretending to be that code.
  * POST /send  - drop a Morse message into another computer's inbox
  * GET  /poll  - the app waits here (long-poll) and gets messages instantly

The relay only ever sees Morse of ENCRYPTED text plus who is talking to whom.
It never sees your plain text or your Enigma key. Messages live in memory only:
if the relay restarts, anything not yet delivered is gone. Standard library only.
"""
import hashlib
import json
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

COND = threading.Condition()
TOKENS = {}      # code -> sha256(token)
QUEUES = {}      # code -> [messages]
LAST_SEND = {}   # code -> time of last send (tiny rate limit)
MAX_QUEUE = 100
MAX_MORSE = 12000
TTL = 24 * 3600
OK_MORSE = set(".-| ")


def canon(s):
    return re.sub(r"[^A-Z0-9]", "", str(s).upper())


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep the console quiet
        pass

    def _reply(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth(self):
        cid = canon(self.headers.get("X-Id", ""))
        tok = self.headers.get("X-Token", "")
        if not (3 <= len(cid) <= 16) or not (16 <= len(tok) <= 64):
            self._reply(400, {"error": "bad credentials"})
            return None
        h = hashlib.sha256(tok.encode()).hexdigest()
        with COND:
            if cid not in TOKENS:
                TOKENS[cid] = h
                QUEUES[cid] = []
                ok = True
            else:
                ok = TOKENS[cid] == h
        if not ok:
            self._reply(403, {"error": "code already in use"})
            return None
        return cid

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            return self._reply(200, {"ok": True, "service": "ENIGMA-X relay"})
        if u.path == "/poll":
            cid = self._auth()
            if not cid:
                return
            try:
                wait = min(max(int(parse_qs(u.query).get("wait", ["20"])[0]), 0), 25)
            except ValueError:
                wait = 20
            end = time.time() + wait
            with COND:
                while not QUEUES[cid]:
                    left = end - time.time()
                    if left <= 0:
                        break
                    COND.wait(left)
                now = time.time()
                msgs = [m for m in QUEUES[cid] if now - m["ts"] < TTL]
                QUEUES[cid] = []
            return self._reply(200, {"messages": msgs})
        self._reply(404, {"error": "not found"})

    def do_POST(self):
        if urlparse(self.path).path != "/send":
            return self._reply(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
            if n > 40000:
                return self._reply(413, {"error": "too big"})
            data = json.loads(self.rfile.read(n))
            to = canon(data.get("to", ""))
            morse = data.get("morse", "")
            wpm = int(data.get("wpm", 15))
            mk = data.get("mk") or [0, 0, 0]
            key = data.get("key", "")
            key_ok = (key == "" or
                      (isinstance(key, str) and 6 <= len(key) <= 2048
                       and key.startswith("ENX1-")
                       and re.fullmatch(r"ENX1-[A-Za-z0-9_-]+", key)))
            ok = (isinstance(morse, str) and 0 < len(morse) <= MAX_MORSE
                  and set(morse) <= OK_MORSE and 5 <= wpm <= 40
                  and isinstance(mk, list) and len(mk) == 3
                  and all(isinstance(x, int) and 0 <= x < 256 for x in mk)
                  and key_ok)
        except Exception:
            ok = False
        if not ok:
            return self._reply(400, {"error": "bad message"})
        cid = self._auth()
        if not cid:
            return
        code, obj = 200, {"ok": True}
        with COND:
            now = time.time()
            if to not in TOKENS:
                code, obj = 404, {"error": "No computer with that code has connected yet"}
            elif now - LAST_SEND.get(cid, 0) < 0.25:
                code, obj = 429, {"error": "Slow down"}
            elif len(QUEUES[to]) >= MAX_QUEUE:
                code, obj = 429, {"error": "Their inbox is full"}
            else:
                LAST_SEND[cid] = now
                message = {"from": cid, "morse": morse, "wpm": wpm,
                           "mk": mk, "ts": now}
                if key:
                    message["key"] = key
                QUEUES[to].append(message)
                COND.notify_all()
        self._reply(code, obj)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8765"))
    print(f"ENIGMA-X relay listening on port {port}  (Ctrl+C to stop)")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
