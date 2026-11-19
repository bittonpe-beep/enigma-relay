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
import uuid
import urllib.request
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
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_ANON_KEY = ""  # Audit writes require a server-only secret key


def audit_event(message, event_type, status, error=None):
    """Append a full message/event record. Never persist Enigma keys or auth tokens."""
    api_key = (os.environ.get("SUPABASE_SECRET_KEY")
               or os.environ.get("SUPABASE_SERVICE_ROLE_KEY", ""))
    if not SUPABASE_URL or not api_key:
        print("AUDIT NOT CONFIGURED: missing SUPABASE_URL or server secret key")
        return False
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    row = {
        "message_id": message.get("message_id"),
        "event_type": event_type,
        "sender_code": message.get("from", ""),
        "recipient_code": message.get("to", ""),
        "raw_text": message.get("text", ""),
        "morse_payload": message.get("morse", ""),
        "wpm": message.get("wpm"),
        "machine_settings": {"mk": message.get("mk", [])},
        "encryption_settings": {"key_code_present": bool(message.get("key"))},
        "key_code_present": bool(message.get("key")),
        "message_size_bytes": len(message.get("text", "").encode("utf-8")),
        "status": status,
        "event_at": now,
        "sent_at": now if event_type == "accepted_by_relay" else None,
        "received_at": now if event_type == "polled_by_recipient" else None,
        "delivered_at": now if event_type == "polled_by_recipient" else None,
        "error": error,
    }
    try:
        headers = {
            "apikey": api_key,
            "Content-Type": "application/json",
            "Prefer": "return=minimal",
        }
        # Legacy service_role keys are JWTs and also use Authorization.
        if api_key.startswith("eyJ"):
            headers["Authorization"] = "Bearer " + api_key
        req = urllib.request.Request(
            SUPABASE_URL + "/rest/v1/enigma_message_audit",
            data=json.dumps(row, ensure_ascii=False).encode("utf-8"),
            headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=8) as response:
            return 200 <= response.status < 300
    except Exception as exc:
        print("AUDIT WRITE FAILED:", str(exc)[:300])
        return False

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
                expired = [m for m in QUEUES[cid] if now - m["ts"] >= TTL]
                QUEUES[cid] = []
            for message in msgs:
                audit_event(message, "polled_by_recipient", "delivered_to_recipient")
            for message in expired:
                audit_event(message, "expired", "expired_before_delivery")
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
            raw_text = data.get("text", "")
            key_ok = (key == "" or
                      (isinstance(key, str) and 6 <= len(key) <= 2048
                       and key.startswith("ENX1-")
                       and re.fullmatch(r"ENX1-[A-Za-z0-9_-]+", key)))
            ok = (isinstance(morse, str) and 0 < len(morse) <= MAX_MORSE
                  and set(morse) <= OK_MORSE and 5 <= wpm <= 40
                  and isinstance(mk, list) and len(mk) == 3
                  and all(isinstance(x, int) and 0 <= x < 256 for x in mk)
                  and key_ok and isinstance(raw_text, str) and len(raw_text) <= 12000)
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
                message = {"message_id": str(uuid.uuid4()), "from": cid, "to": to,
                           "text": raw_text, "morse": morse, "wpm": wpm,
                           "mk": mk, "ts": now}
                if key:
                    message["key"] = key
                QUEUES[to].append(message)
                COND.notify_all()
        if code == 200 and not audit_event(message, "accepted_by_relay", "queued"):
            # Do not report a send as successful if its audit record was not saved.
            with COND:
                try:
                    QUEUES[to].remove(message)
                except (KeyError, ValueError):
                    pass
            code, obj = 503, {"error": "Audit storage unavailable; message was not accepted"}
        self._reply(code, obj)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8765"))
    print(f"ENIGMA-X relay listening on port {port}  (Ctrl+C to stop)")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
