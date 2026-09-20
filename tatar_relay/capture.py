"""Session key capture server — Tatar Relay.

The companion JS hook (examples/js-hooks/session_key_capture.js) intercepts
the target page's crypto library at login time and GETs this endpoint with
the derived AES key.

Standalone:
    relay capture --port 9091

Integrated with the bridge (bridge starts it automatically):
    relay bridge myprofile.yaml --capture --capture-port 9091

JS hook sends:
    GET http://127.0.0.1:9091/key?v=<64-hex-chars>
    POST http://127.0.0.1:9091/key   body: hex or {"v":"hex"}

Status check:
    GET http://127.0.0.1:9091/status
"""
from __future__ import annotations

import json
import threading
from typing import Optional


# ---------------------------------------------------------------------------
# Core capture state — thread-safe, one-shot (resets on each new session)
# ---------------------------------------------------------------------------

class KeyCapture:
    """Thread-safe key receiver.  One instance per bridge session."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._key: Optional[bytes] = None
        self._lock = threading.Lock()

    def receive(self, key_hex: str) -> bool:
        """Accept a hex-encoded AES key string.

        Returns True and signals all waiters if the value is a valid
        16/24/32-byte hex string; False otherwise.
        """
        cleaned = (key_hex or "").strip().lower()
        try:
            key = bytes.fromhex(cleaned)
        except ValueError:
            return False
        if len(key) not in (16, 24, 32):   # must be a valid AES key size
            return False
        with self._lock:
            self._key = key
        self._event.set()
        return True

    def get(self) -> Optional[bytes]:
        """Return the captured key bytes (or None if not yet received)."""
        with self._lock:
            return self._key

    def hex(self) -> Optional[str]:
        k = self.get()
        return k.hex() if k else None

    def wait(self, timeout: float = 120.0) -> Optional[bytes]:
        """Block until a key arrives (or timeout expires).

        Returns the key bytes, or None on timeout.
        """
        self._event.wait(timeout)
        return self.get()

    def reset(self) -> None:
        """Clear the captured key; subsequent calls to wait() block again."""
        self._event.clear()
        with self._lock:
            self._key = None

    @property
    def ready(self) -> bool:
        return self._event.is_set()


# ---------------------------------------------------------------------------
# Crypto observation log (fingerprints from the JS observer hook)
# ---------------------------------------------------------------------------

class ObservationLog:
    """Thread-safe log of crypto observations sent by the JS observer hook.

    Each observation is a fingerprint of one crypto call, e.g.::

        {"lib":"WebCrypto","api":"encrypt","algorithm":"AES-GCM",
         "mode":"GCM","keyLen":32,"ivLen":12,"tagLen":16,
         "ct_sample":"6dc94b82…","direction":"encrypt"}

    Dedupes by scheme signature so an unchanged scheme is reported once; a new
    signature is flagged (the algorithm changed). Optionally appends every raw
    observation to a JSONL file for ``relay inspect`` to consume later.
    """

    _SIG_KEYS = ("lib", "api", "algorithm", "mode", "keyLen", "ivLen", "tagLen")

    def __init__(self, path: Optional[str] = None) -> None:
        self._lock = threading.Lock()
        self._seen: dict = {}      # signature -> summary
        self._records: list = []
        self.path = path

    @classmethod
    def _signature(cls, obs: dict) -> str:
        return "|".join(f"{k}={obs.get(k)}" for k in cls._SIG_KEYS)

    @staticmethod
    def summary(obs: dict) -> str:
        algo = obs.get("algorithm") or obs.get("api") or "?"
        bits = []
        if obs.get("mode"):   bits.append(str(obs["mode"]))
        if obs.get("ivLen"):  bits.append(f"{obs['ivLen']}B nonce")
        if obs.get("tagLen"): bits.append(f"{obs['tagLen']}B tag")
        if obs.get("keyLen"): bits.append(f"{obs['keyLen']}B key")
        return algo + (" · " + " · ".join(bits) if bits else "")

    def record(self, obs: dict) -> tuple:
        """Store one observation. Returns (is_new_scheme: bool, summary: str)."""
        sig = self._signature(obs)
        summ = self.summary(obs)
        with self._lock:
            is_new = sig not in self._seen
            self._seen[sig] = summ
            self._records.append(obs)
            if self.path:
                try:
                    with open(self.path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(obs, ensure_ascii=False) + "\n")
                except OSError:
                    pass
        return is_new, summ

    def schemes(self) -> list:
        with self._lock:
            return list(self._seen.values())

    def records(self) -> list:
        with self._lock:
            return list(self._records)


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

def serve_capture(
    capture: KeyCapture,
    host: str = "127.0.0.1",
    port: int = 9091,
    *,
    block: bool = True,
    on_key: Optional[callable] = None,
    observations: Optional["ObservationLog"] = None,
    on_observe: Optional[callable] = None,
) -> None:
    """Start the capture HTTP server.

    Parameters
    ----------
    capture:  KeyCapture instance to receive into.
    host/port: bind address.
    block:    If True, run in this thread (serve_forever).
              If False, start a daemon thread and return immediately.
    on_key:   Optional callback(key_hex: str) called when a valid key arrives.
    """
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import urlparse, parse_qs

    _on_key = on_key          # closure
    _on_observe = on_observe  # closure

    class _Handler(BaseHTTPRequestHandler):
        def _cors(self) -> None:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")

        def _send_json(self, code: int, body: bytes) -> None:
            self.send_response(code)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self) -> None:   # noqa: N802  preflight
            self.send_response(200)
            self._cors()
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/key":
                params = parse_qs(parsed.query)
                # accept ?v= or ?k= or ?key=
                key_hex = (params.get("v") or params.get("k") or
                           params.get("key") or [""])[0]
                self._handle_key(key_hex)
            elif parsed.path == "/status":
                kh = capture.hex()
                body = (json.dumps({"ok": True,  "ready": True,  "key": kh})
                        if kh else
                        json.dumps({"ok": True,  "ready": False, "key": None})
                        ).encode()
                self._send_json(200, body)
            elif parsed.path == "/reset":
                capture.reset()
                self._send_json(200, b'{"ok":true,"message":"reset"}')
            elif parsed.path == "/schemes":
                schemes = observations.schemes() if observations else []
                self._send_json(200, json.dumps({"ok": True, "schemes": schemes}).encode())
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/key":
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length).decode("utf-8", "replace").strip()
                if raw.startswith("{"):
                    try:
                        d = json.loads(raw)
                        key_hex = d.get("v") or d.get("key") or d.get("k") or ""
                    except Exception:  # noqa: BLE001
                        key_hex = ""
                else:
                    key_hex = raw   # plain hex body
                self._handle_key(key_hex)
            elif parsed.path == "/observe":
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length).decode("utf-8", "replace").strip()
                try:
                    obs = json.loads(raw) if raw.startswith("{") else {}
                except Exception:  # noqa: BLE001
                    obs = {}
                if observations is not None and obs:
                    is_new, summ = observations.record(obs)
                    if _on_observe:
                        try:
                            _on_observe(obs, is_new, summ)
                        except Exception:  # noqa: BLE001
                            pass
                    self._send_json(200, b'{"ok":true}')
                else:
                    self._send_json(400, b'{"ok":false,"error":"no observation"}')
            else:
                self.send_response(404)
                self.end_headers()

        def _handle_key(self, key_hex: str) -> None:
            ok = capture.receive(key_hex) if key_hex else False
            if ok and _on_key:
                try:
                    _on_key(key_hex.strip().lower())
                except Exception:  # noqa: BLE001
                    pass
            body = b'{"ok":true}' if ok else b'{"ok":false,"error":"invalid key"}'
            self._send_json(200 if ok else 400, body)

        def log_message(self, *_):  # silence default stderr logging
            pass

    srv = HTTPServer((host, port), _Handler)
    if block:
        srv.serve_forever()
    else:
        t = threading.Thread(target=srv.serve_forever, daemon=True, name="tatar-capture")
        t.start()
