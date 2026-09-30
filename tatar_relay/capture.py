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

Status check (readiness only — never the key itself):
    GET http://127.0.0.1:9091/status   -> {"ok":true,"ready":true|false}

Exposure note: this sidecar deliberately allows cross-origin requests so the
injected page hook can reach ``/key`` and ``/observe``. It therefore must not
hand anything secret back: ``/status`` reports readiness only, and CORS is sent
on ``/key``/``/observe`` alone. ``/reset`` and ``/schemes`` change or read
capture state, so they honour an optional ``token`` (``X-Relay-Token``).
"""
from __future__ import annotations

import hmac
import json
import threading
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    # serve_capture imports http.server lazily — the sidecar is optional and
    # importing a server module at package import time is not free. The name
    # still has to be visible here or its "HTTPServer" return annotation is a
    # dangling forward reference (get_type_hints and linters both flag it).
    from http.server import HTTPServer


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
    token: Optional[str] = None,
) -> "HTTPServer":
    """Start the capture HTTP server; returns the HTTPServer.

    Parameters
    ----------
    capture:  KeyCapture instance to receive into.
    host/port: bind address.
    block:    If True, run in this thread (serve_forever).
              If False, start a daemon thread and return immediately.
    on_key:   Optional callback(key_hex: str) called when a valid key arrives.
    token:    Optional shared secret required (as ``X-Relay-Token``) on the
              control endpoints ``/reset`` and ``/schemes``. Default None keeps
              the previous behaviour. The sidecar holds no BridgeService, so the
              secret is passed in rather than read off one.

    Returns the ``HTTPServer`` so a caller (or a test) can shut it down; the
    existing callers ignore it and are unaffected.
    """
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import urlparse, parse_qs

    _on_key = on_key          # closure
    _on_observe = on_observe  # closure
    _token = token or None    # closure

    class _Handler(BaseHTTPRequestHandler):
        # The only two endpoints the injected page hook calls cross-origin, and
        # so the only two that may advertise CORS — on the preflight as well as
        # on the response, or the preflight promises what the response denies.
        _CORS_PATHS = frozenset({"/key", "/observe"})

        def _cors(self) -> None:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")

        def _send_json(self, code: int, body: bytes, *, cors: bool = False) -> None:
            """``cors`` only for the two endpoints a target page must reach.

            Wildcard CORS on every response is what let any page in the
            operator's browser read this server's answers; only /key and
            /observe are called cross-origin, so only they advertise it.
            """
            self.send_response(code)
            if cors:
                self._cors()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self) -> bool:
            """Constant-time check for the control endpoints; open if unset."""
            if not _token:
                return True
            provided = self.headers.get("X-Relay-Token")
            return bool(provided) and hmac.compare_digest(provided, _token)

        def _deny(self) -> None:
            self._send_json(401, b'{"ok":false,"error":"unauthorized: missing or '
                                 b'bad X-Relay-Token"}')

        def do_OPTIONS(self) -> None:   # noqa: N802  preflight
            self.send_response(200)
            if urlparse(self.path).path in self._CORS_PATHS:
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
                # Readiness ONLY. This body used to carry the live session key,
                # which wildcard CORS then served to any origin; `relay capture`
                # prints the key locally (cli.py cmd_capture) instead.
                body = json.dumps({"ok": True,
                                   "ready": bool(capture.hex())}).encode()
                self._send_json(200, body)
            elif parsed.path == "/reset":
                if not self._authorized():
                    return self._deny()
                capture.reset()
                self._send_json(200, b'{"ok":true,"message":"reset"}')
            elif parsed.path == "/schemes":
                if not self._authorized():
                    return self._deny()
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
                    self._send_json(200, b'{"ok":true}', cors=True)
                else:
                    self._send_json(400, b'{"ok":false,"error":"no observation"}',
                                    cors=True)
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
            self._send_json(200 if ok else 400, body, cors=True)

        def log_message(self, *_):  # silence default stderr logging
            pass

    srv = HTTPServer((host, port), _Handler)
    if block:
        srv.serve_forever()
    else:
        t = threading.Thread(target=srv.serve_forever, daemon=True, name="tatar-capture")
        t.start()
    return srv
