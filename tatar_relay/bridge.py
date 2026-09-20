"""Local-service bridge — Frozen Contract #5 (JSON-RPC).

The Python core stays authoritative; non-Python frontends (Burp/Java) talk to
it over this contract. v0.1 uses localhost HTTP JSON for easy debugging; a
Unix-domain-socket / Named-Pipe transport is a drop-in later optimization for
high-volume (Intruder) traffic.

Message shapes (contract):
  Burp → Core   {"method":"decrypt","channel":"request","profile":"acme",
                 "wire":"<base64>","flow_id":"a1","vars":{"session_key":"<hex>"}}
  Core → Burp   {"ok":true,"plaintext":<json>,"ctx_token":"t-9f"}
  Burp → Core   {"method":"encrypt","channel":"request","plaintext":<json>,"ctx_token":"t-9f"}
  Core → Burp   {"ok":true,"wire":"<base64>","diff":{"changed_bytes":14}}

Key capture (v0.3):
  When the bridge is started with capture=True it also serves
  GET /key?v=<hex>  on capture_port (default 9091).  The JS hook in
  examples/js-hooks/session_key_capture.js calls this endpoint after
  deriving the ECDH session key; the bridge then injects the key into
  captured_vars so every subsequent decrypt call can use it automatically.
"""
from __future__ import annotations

import base64
import hmac
import json
import secrets
from typing import Dict, Optional

from .context import Context, HttpMessage
from .engine import Engine
from .errors import RelayError, DecryptError
from .profile import Profile


class BridgeService:
    def __init__(self, profiles: Dict[str, Profile] | None = None,
                 default_vars: Dict[str, str] | None = None,
                 token: str | None = None):
        self.profiles: Dict[str, Profile] = profiles or {}
        # Optional shared-secret. When set, the HTTP transport requires a
        # matching X-Relay-Token header. Default None -> no auth (unchanged
        # behavior). The JSON-RPC message contract (#5) is untouched: auth is
        # a transport concern, checked before handle().
        self.token: str | None = token or None
        # default vars (name -> hex) applied to every flow; message "vars" override.
        # v0.2: the operator supplies the session key here; live extraction is v0.3.
        self.default_vars: Dict[str, str] = default_vars or {}
        # captured_vars: populated by the JS capture hook at runtime (v0.3).
        # These override default_vars but are overridden by per-message "vars".
        self.captured_vars: Dict[str, str] = {}
        self._ctx: Dict[str, tuple] = {}   # ctx_token -> (ctx, engine, channel, orig_wire)

    def add_profile(self, profile: Profile) -> None:
        self.profiles[profile.name] = profile

    def authorize(self, provided: str | None) -> bool:
        """Transport-layer auth check. True if no token is configured, or the
        provided value matches (constant-time). Used by serve_http."""
        if not self.token:
            return True
        return bool(provided) and hmac.compare_digest(provided, self.token)

    def set_captured_key(self, var_name: str, key_hex: str) -> None:
        """Called by the key capture server when the JS hook delivers a key."""
        self.captured_vars[var_name] = key_hex.strip().lower()
        print(f"[tatar-relay] captured_vars['{var_name}'] updated  "
              f"({len(key_hex)//2*8}-bit key)")

    def handle(self, msg: dict) -> dict:
        try:
            method = msg.get("method")
            if method == "decrypt":
                return self._decrypt(msg)
            if method == "encrypt":
                return self._encrypt(msg)
            return {"ok": False, "error": {"category": "config_error",
                                           "message": f"unknown method {method!r}"}}
        except DecryptError as e:
            return {"ok": False, "error": e.as_dict()}
        except RelayError as e:
            return {"ok": False, "error": {"category": "internal", "message": str(e)}}

    def _profile(self, name: str | None) -> Profile:
        if not name:
            if len(self.profiles) == 1:
                return next(iter(self.profiles.values()))
            raise DecryptError(category="config_error",
                               message="profile name required (multiple loaded)")
        if name not in self.profiles:
            raise DecryptError(category="config_error", message=f"unknown profile {name!r}")
        return self.profiles[name]

    def _decrypt(self, msg: dict) -> dict:
        profile = self._profile(msg.get("profile"))
        channel = msg.get("channel", "request")
        ctx = Context(request=HttpMessage(host=profile.scope.hosts[0]))
        vs = profile.new_varstore(ctx)
        merged = {**self.default_vars, **self.captured_vars, **(msg.get("vars") or {})}
        for k, v in merged.items():
            # var values default to HEX (session keys); prefix str:/b64:/hex:
            # to pass a passphrase (e.g. an ecode) or other encodings.
            if isinstance(v, (bytes, bytearray)):
                vv = bytes(v)
            elif isinstance(v, str) and v.startswith("str:"):
                vv = v[4:].encode("utf-8")
            elif isinstance(v, str) and v.startswith("b64:"):
                vv = base64.b64decode(v[4:])
            elif isinstance(v, str) and v.startswith("hex:"):
                vv = bytes.fromhex(v[4:])
            else:
                vv = bytes.fromhex(v)
            vs.set(k, vv)
        ctx.vars = vs
        eng = Engine(profile)
        wire = base64.b64decode(msg["wire"])
        plain = eng.decrypt(channel, wire, ctx)
        token = "t-" + secrets.token_hex(4)
        self._ctx[token] = (ctx, eng, channel, wire)
        return {"ok": True, "plaintext": plain, "ctx_token": token}

    def _encrypt(self, msg: dict) -> dict:
        token = msg.get("ctx_token")
        if token not in self._ctx:
            raise DecryptError(category="config_error", message="unknown or expired ctx_token")
        ctx, eng, channel, orig = self._ctx[token]
        wire = eng.encrypt(channel, msg["plaintext"], ctx)
        return {"ok": True, "wire": base64.b64encode(wire).decode("ascii"),
                "diff": {"changed_bytes": _byte_diff(orig, wire), "out_len": len(wire)}}


def _byte_diff(a: bytes, b: bytes) -> int:
    n = sum(1 for x, y in zip(a, b) if x != y) + abs(len(a) - len(b))
    return n


def serve_http(service: BridgeService, host: str = "127.0.0.1", port: int = 8799,
               capture_port: Optional[int] = None,
               capture_key_var: str = "session_key",
               observe_path: Optional[str] = "observations.jsonl") -> None:
    """Minimal localhost JSON-RPC server (debug transport).

    If capture_port is set, also starts the JS key-capture server on that port.
    The captured key is stored in service.captured_vars[capture_key_var]. The
    same sidecar receives crypto observations on /observe: each distinct scheme
    is printed once, a changed scheme is flagged NEW, and every observation is
    appended to ``observe_path`` (JSONL) for ``relay inspect`` to merge.
    """
    from http.server import BaseHTTPRequestHandler, HTTPServer

    # Optionally start the key-capture + observer sidecar
    if capture_port:
        from .capture import KeyCapture, serve_capture, ObservationLog
        cap = KeyCapture()
        obs_log = ObservationLog(path=observe_path)

        def _on_key(hex_key: str) -> None:
            service.set_captured_key(capture_key_var, hex_key)

        def _on_observe(obs: dict, is_new: bool, summ: str) -> None:
            tag = "⚠ NEW SCHEME" if is_new else "scheme"
            print(f"[tatar-relay] {tag}: {summ}")

        serve_capture(cap, host=host, port=capture_port, block=False,
                      on_key=_on_key, observations=obs_log, on_observe=_on_observe)
        print(f"tatar-relay capture  on http://{host}:{capture_port}/key  "
              f"(var={capture_key_var!r})")
        print(f"tatar-relay observe  on http://{host}:{capture_port}/observe  "
              f"-> {observe_path}")

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            if not service.authorize(self.headers.get("X-Relay-Token")):
                body = b'{"ok":false,"error":{"category":"config_error",' \
                       b'"message":"unauthorized: missing or bad X-Relay-Token"}}'
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            length = int(self.headers.get("Content-Length", 0))
            try:
                msg = json.loads(self.rfile.read(length) or b"{}")
                resp = service.handle(msg)
                code = 200
            except Exception as e:  # noqa: BLE001
                resp, code = {"ok": False, "error": {"category": "internal", "message": str(e)}}, 400
            body = json.dumps(resp).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):  # silence
            pass

    srv = HTTPServer((host, port), Handler)
    print(f"tatar-relay bridge   on http://{host}:{port}  profiles={list(service.profiles)}")
    srv.serve_forever()
