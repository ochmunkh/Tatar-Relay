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
"""
from __future__ import annotations

import base64
import json
import secrets
from typing import Dict

from .context import Context, HttpMessage
from .engine import Engine
from .errors import RelayError, DecryptError
from .profile import Profile


class BridgeService:
    def __init__(self, profiles: Dict[str, Profile] | None = None,
                 default_vars: Dict[str, str] | None = None):
        self.profiles: Dict[str, Profile] = profiles or {}
        # default vars (name -> hex) applied to every flow; message "vars" override.
        # v0.2: the operator supplies the session key here; live extraction is v0.3.
        self.default_vars: Dict[str, str] = default_vars or {}
        self._ctx: Dict[str, tuple] = {}   # ctx_token -> (ctx, engine, channel, orig_wire)

    def add_profile(self, profile: Profile) -> None:
        self.profiles[profile.name] = profile

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
        merged = {**self.default_vars, **(msg.get("vars") or {})}
        for k, v in merged.items():
            vs.set(k, bytes.fromhex(v))
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


def serve_http(service: BridgeService, host: str = "127.0.0.1", port: int = 8799):
    """Minimal localhost JSON-RPC server (debug transport)."""
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
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
    print(f"tatar-relay bridge on http://{host}:{port}  profiles={list(service.profiles)}")
    srv.serve_forever()
