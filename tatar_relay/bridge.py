"""Local-service bridge — Frozen Contract #5 (JSON-RPC).

The Python core stays authoritative; non-Python frontends (Burp/Java) talk to
it over this contract. v0.1 uses localhost HTTP JSON for easy debugging; a
Unix-domain-socket / Named-Pipe transport is a drop-in later optimization for
high-volume (Intruder) traffic.

Message shapes (contract):
  Burp → Core   {"method":"decrypt","channel":"request","profile":"acme",
                 "wire":"<base64>","flow_id":"a1","vars":{"session_key":"<hex>"},
                 "host":"api.example.com","path":"/v2/pay"}
  Core → Burp   {"ok":true,"plaintext":<json>,"ctx_token":"t-9f"}
  Burp → Core   {"method":"encrypt","channel":"request","plaintext":<json>,"ctx_token":"t-9f"}
  Core → Burp   {"ok":true,"wire":"<base64>","diff":{"changed_bytes":14}}

Key capture (v0.3):
  When the bridge is started with capture=True it also serves
  GET /key?v=<hex>  on capture_port (default 9091).  The JS hook in
  examples/js-hooks/session_key_capture.js calls this endpoint after
  deriving the ECDH session key; the bridge then injects the key into
  captured_vars so every subsequent decrypt call can use it automatically.

Scope:
  "host" and "path" are OPTIONAL and additive. When a frontend supplies "host",
  the profile's fail-closed scope is enforced per request before anything is
  decrypted (ScopeViolation -> the normal {"ok":false,"error":{...}} shape).
  A frontend that sends no host is NOT scope-checked — cmd_bridge warns about
  that at startup.
"""
from __future__ import annotations

import base64
import hmac
import ipaddress
import json
import secrets
import threading
from collections import OrderedDict
from typing import Dict, Optional, Tuple


# Default per-request execution budget for the bridge (seconds). A decrypt or
# encrypt that exceeds it returns a fail-closed ``timeout`` error instead of
# hanging the Burp extension; a runaway Python hook can no longer wedge the
# bridge. 0/None disables the guard.
DEFAULT_TIMEOUT = 30.0

# Largest JSON-RPC request body the bridge will read. A decrypt request carries
# one captured message, so 16 MiB is generous; anything bigger is refused (413)
# before it is read into memory.
MAX_REQUEST_BYTES = 16 * 1024 * 1024

# decrypt() hands out a ctx_token per flow so a later encrypt() can reseal it.
# The store is bounded (least-recently-used entries are evicted) so a long
# session cannot grow it without limit.
MAX_CTX_ENTRIES = 1024


def is_loopback(host: str) -> bool:
    """True for 127.0.0.0/8, ::1 and the name ``localhost``."""
    host = (host or "").strip().strip("[]")
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def require_safe_bind(host: str, token: Optional[str]) -> None:
    """Fail closed: never expose an unauthenticated bridge beyond loopback.

    The bridge decrypts and reseals with whatever keys the operator loaded, so
    binding it to a LAN-reachable address without a shared token would turn it
    into a decryption/encryption oracle for anyone on the network.
    """
    if not is_loopback(host) and not token:
        raise RelayError(
            f"refusing to bind the bridge to non-loopback address {host!r} "
            f"without a token — set --token / TATAR_RELAY_TOKEN, or bind to "
            f"127.0.0.1")


def capture_bind_host(bridge_host: str) -> str:
    """Where the key-capture sidecar binds.

    The sidecar's ``/key`` and ``/observe`` are deliberately reachable from the
    testing browser's page (CORS ``*``), and that browser runs on the operator's
    own machine — so the sidecar never needs to be reachable from the network.
    Even when the bridge itself is bound beyond loopback (with a token), the
    sidecar stays on loopback so nobody on the LAN can inject a key.
    """
    return bridge_host if is_loopback(bridge_host) else "127.0.0.1"


def _host_only(value: str) -> str:
    """Strip the port from a Host header value ("[::1]:8799" -> "::1")."""
    v = (value or "").strip()
    if v.startswith("["):
        end = v.find("]")
        return v[1:end] if end != -1 else v
    if v.count(":") == 1:
        return v.split(":", 1)[0]
    return v


def screen_request(headers, *, bind_host: str,
                   max_bytes: int = MAX_REQUEST_BYTES) -> Optional[Tuple[int, str]]:
    """Transport checks run before a request body is read.

    Returns ``(status, message)`` to reject, or ``None`` to accept.

    * An ``Origin`` header means a web browser sent the request (the Burp
      extension never sets one). Refusing it stops a page open in the testing
      browser from driving the bridge (cross-site request forgery).
    * When the bridge is bound to loopback, the ``Host`` header must name a
      loopback host too; anything else is a DNS-rebinding attempt.
    * The declared body size must be sane and within ``max_bytes``.
    """
    if headers.get("Origin"):
        return 403, "browser-originated request refused (Origin header present)"
    if is_loopback(bind_host):
        host = _host_only(headers.get("Host") or "")
        if host and not is_loopback(host):
            return 403, f"Host header {host!r} is not loopback (possible DNS rebinding)"
    raw = headers.get("Content-Length", "0") or "0"
    try:
        length = int(raw)
    except ValueError:
        return 400, "bad Content-Length"
    if length < 0:
        return 400, "bad Content-Length"
    if length > max_bytes:
        return 413, f"request body exceeds {max_bytes} bytes"
    return None


def _call_with_timeout(fn, timeout):
    """Run ``fn()`` with a wall-clock budget. Raises TimeoutError if exceeded.

    The worker is a daemon thread: Python cannot forcibly kill it, so on a
    timeout we return control to the caller (which fails closed) and let the
    stuck thread die with the process. This keeps the transport responsive on
    both POSIX and Windows, where signal-based timeouts are not available.
    """
    box = {}

    def run():
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised in caller
            box["error"] = exc

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise TimeoutError(f"operation exceeded {timeout:g}s budget")
    if "error" in box:
        raise box["error"]
    return box.get("value")

from .context import Context, HttpMessage
from .engine import Engine
from .errors import RelayError, DecryptError
from .profile import Profile
from .variables import coerce_key


class BridgeService:
    def __init__(self, profiles: Dict[str, Profile] | None = None,
                 default_vars: Dict[str, str] | None = None,
                 token: str | None = None,
                 timeout: float | None = DEFAULT_TIMEOUT,
                 max_ctx: int = MAX_CTX_ENTRIES):
        self.profiles: Dict[str, Profile] = profiles or {}
        # Optional shared-secret. When set, the HTTP transport requires a
        # matching X-Relay-Token header. Default None -> no auth (unchanged
        # behavior). The JSON-RPC message contract (#5) is untouched: auth is
        # a transport concern, checked before handle().
        self.token: str | None = token or None
        # Per-request execution budget (seconds); see DEFAULT_TIMEOUT.
        self.timeout: float | None = timeout
        # default vars (name -> hex) applied to every flow; message "vars" override.
        # v0.2: the operator supplies the session key here; live extraction is v0.3.
        self.default_vars: Dict[str, str] = default_vars or {}
        # captured_vars: populated by the JS capture hook at runtime (v0.3).
        # These override default_vars but are overridden by per-message "vars".
        self.captured_vars: Dict[str, str] = {}
        # ctx_token -> (ctx, engine, channel, orig_wire); bounded LRU.
        self._ctx: "OrderedDict[str, tuple]" = OrderedDict()
        self.max_ctx = max(1, int(max_ctx))

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
            # ScopeViolation/ProfileError carry a Contract #4 category; only a
            # genuinely unclassified RelayError falls back to "internal".
            return {"ok": False,
                    "error": {"category": getattr(e, "category", "internal"),
                              "message": str(e)}}

    def handle_timed(self, msg: dict, timeout: float | None = None) -> dict:
        """Like ``handle`` but bounded by a wall-clock budget (fail-closed).

        A decrypt/encrypt that overruns returns a structured ``timeout`` error
        rather than blocking the transport. ``timeout`` overrides the service
        default for this call; 0/None disables the guard.
        """
        budget = self.timeout if timeout is None else timeout
        if not budget or budget <= 0:
            return self.handle(msg)
        try:
            return _call_with_timeout(lambda: self.handle(msg), budget)
        except TimeoutError as e:
            return {"ok": False,
                    "error": {"category": "timeout", "message": str(e)}}

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
        # Scope is fail-closed, but only a frontend that tells us WHERE the flow
        # is going can be checked; the host used to be fabricated from the
        # profile's own scope list, so the check could never fail.
        host = msg.get("host") or ""
        path = msg.get("path") or None
        if host:
            profile.authorize(host, path)
        ctx = Context(request=HttpMessage(
            host=host or (profile.scope.hosts[0] if profile.scope.hosts else ""),
            path=path or ""))
        vs = profile.new_varstore(ctx)
        merged = {**self.default_vars, **self.captured_vars, **(msg.get("vars") or {})}
        for k, v in merged.items():
            # var values default to HEX (session keys); prefix str:/b64:/hex:
            # to pass a passphrase (e.g. an ecode) or other encodings.
            vs.set(k, coerce_key(v, f"var {k!r}", bare="hex"))
        ctx.vars = vs
        eng = Engine(profile)
        wire = base64.b64decode(msg["wire"])
        plain = eng.decrypt(channel, wire, ctx)
        token = self._remember((ctx, eng, channel, wire))
        return {"ok": True, "plaintext": plain, "ctx_token": token}

    def _remember(self, entry: tuple) -> str:
        """Store a flow for a later encrypt(); evict the oldest past max_ctx."""
        token = "t-" + secrets.token_hex(16)   # 128-bit, unguessable
        self._ctx[token] = entry
        while len(self._ctx) > self.max_ctx:
            self._ctx.popitem(last=False)
        return token

    def _encrypt(self, msg: dict) -> dict:
        token = msg.get("ctx_token")
        if token not in self._ctx:
            raise DecryptError(category="config_error", message="unknown or expired ctx_token")
        self._ctx.move_to_end(token)           # recently used -> keep longer
        ctx, eng, channel, orig = self._ctx[token]
        # A token can be reused to seal many plaintexts (the Burp Intruder
        # workflow), possibly after the request was re-pointed. When the
        # frontend says where the sealed message is going, hold it to the same
        # fail-closed scope as decrypt.
        host = msg.get("host") or ""
        if host:
            eng.profile.authorize(host, msg.get("path") or None)
        wire = eng.encrypt(channel, msg["plaintext"], ctx)
        return {"ok": True, "wire": base64.b64encode(wire).decode("ascii"),
                "diff": {"changed_bytes": _byte_diff(orig, wire), "out_len": len(wire)}}


def _byte_diff(a: bytes, b: bytes) -> int:
    n = sum(1 for x, y in zip(a, b) if x != y) + abs(len(a) - len(b))
    return n


def serve_http(service: BridgeService, host: str = "127.0.0.1", port: int = 8799,
               capture_port: Optional[int] = None,
               capture_key_var: str = "session_key",
               observe_path: Optional[str] = "observations.jsonl",
               capture_token: Optional[str] = None) -> None:
    """Minimal localhost JSON-RPC server (debug transport).

    If capture_port is set, also starts the JS key-capture server on that port.
    The captured key is stored in service.captured_vars[capture_key_var]. The
    same sidecar receives crypto observations on /observe: each distinct scheme
    is printed once, a changed scheme is flagged NEW, and every observation is
    appended to ``observe_path`` (JSONL) for ``relay inspect`` to merge.
    """
    # Fail closed before anything (bridge or capture sidecar) binds a socket.
    require_safe_bind(host, service.token)

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

        cap_host = capture_bind_host(host)
        serve_capture(cap, host=cap_host, port=capture_port, block=False,
                      on_key=_on_key, observations=obs_log, on_observe=_on_observe,
                      token=capture_token)
        print(f"tatar-relay capture  on http://{cap_host}:{capture_port}/key  "
              f"(var={capture_key_var!r})")
        print(f"tatar-relay observe  on http://{cap_host}:{capture_port}/observe  "
              f"-> {observe_path}")

    srv = make_server(service, host=host, port=port)
    print(f"tatar-relay bridge   on http://{host}:{port}  profiles={list(service.profiles)}")
    srv.serve_forever()


def make_server(service: BridgeService, host: str = "127.0.0.1", port: int = 8799):
    """Build (but do not start) the JSON-RPC HTTP server.

    Every request passes, in order: ``screen_request`` (Origin / Host / size),
    the optional token check, then the timed handler. Rejections never read
    the body and always use the normal ``{"ok": false, "error": {...}}`` shape.
    """
    from http.server import BaseHTTPRequestHandler, HTTPServer

    require_safe_bind(host, service.token)

    class Handler(BaseHTTPRequestHandler):
        def _reply(self, code: int, payload: dict) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _reject(self, code: int, message: str) -> None:
            self._reply(code, {"ok": False, "error": {"category": "config_error",
                                                      "message": message}})

        def do_POST(self):  # noqa: N802
            verdict = screen_request(self.headers, bind_host=host)
            if verdict:
                self._reject(*verdict)
                return
            if not service.authorize(self.headers.get("X-Relay-Token")):
                self._reject(401, "unauthorized: missing or bad X-Relay-Token")
                return
            length = int(self.headers.get("Content-Length", 0) or 0)
            try:
                msg = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(msg, dict):
                    raise ValueError("request must be a JSON object")
                resp, code = service.handle_timed(msg), 200
            except Exception as e:  # noqa: BLE001
                resp, code = {"ok": False, "error": {"category": "internal",
                                                     "message": str(e)}}, 400
            self._reply(code, resp)

        def log_message(self, *a):  # silence
            pass

    return HTTPServer((host, port), Handler)
