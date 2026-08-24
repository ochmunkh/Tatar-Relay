"""mitmproxy addon — the v0.1 reference frontend.

Usage:
    TATAR_RELAY_PROFILE=examples/acme-bank-mobile.yaml \\
    mitmdump -s tatar_relay/frontends/mitmproxy_addon.py

For each in-scope request it decrypts the body (logged as plaintext), applies
optional match/replace rules, re-encrypts, and forwards. On any pipeline error
it logs a structured reason and passes the ORIGINAL message through untouched —
the proxy never breaks the connection.

Interactive edit-in-place is the job of the Burp frontend (v0.2); mitmproxy here
proves the core on live traffic and supports scripted rewrites.

Rewrites (optional): TATAR_RELAY_REWRITE='{"amount": 90000}' applies to the
decrypted top-level JSON before re-encryption.
"""
from __future__ import annotations

import json
import os

from mitmproxy import ctx as mitm_ctx  # type: ignore
from mitmproxy import http  # type: ignore

from tatar_relay.context import Context, HttpMessage
from tatar_relay.engine import Engine
from tatar_relay.errors import RelayError, DecryptError
from tatar_relay.profile import Profile


class TatarRelay:
    def __init__(self) -> None:
        path = os.environ.get("TATAR_RELAY_PROFILE")
        if not path:
            raise RuntimeError("set TATAR_RELAY_PROFILE=path/to/profile.yaml")
        self.profile = Profile.load(path)
        self.engine = Engine(self.profile)
        self.rewrites = json.loads(os.environ.get("TATAR_RELAY_REWRITE", "{}"))
        # one shared session for the demo (session_key etc.)
        self._ctx = Context(request=HttpMessage(host=self.profile.scope.hosts[0]))
        self._vars = self.profile.new_varstore(self._ctx)
        self._ctx.vars = self._vars

    def _in_scope(self, flow: "http.HTTPFlow") -> bool:
        return self.profile.scope.matches(flow.request.host, flow.request.path)

    def _mkctx(self, flow) -> Context:
        req = HttpMessage(
            method=flow.request.method, url=flow.request.url,
            host=flow.request.host, path=flow.request.path,
            headers=dict(flow.request.headers), body=flow.request.raw_content or b"",
        )
        c = Context(request=req, variables=self._vars)
        c.session = self._ctx.session
        return c

    def request(self, flow: "http.HTTPFlow") -> None:
        if not self._in_scope(flow) or not flow.request.raw_content:
            return
        c = self._mkctx(flow)
        try:
            plain = self.engine.decrypt("request", flow.request.raw_content, c)
        except DecryptError as e:
            mitm_ctx.log.warn(f"[tatar-relay] decrypt skipped: {e}")
            return
        mitm_ctx.log.info(f"[tatar-relay] plaintext: {json.dumps(plain, ensure_ascii=False)[:400]}")
        if self.rewrites and isinstance(plain, dict):
            for k, v in self.rewrites.items():
                plain[k] = v
            try:
                wire = self.engine.encrypt("request", plain, c)
                flow.request.raw_content = wire
                mitm_ctx.log.info(f"[tatar-relay] re-encrypted ({len(wire)} bytes) with rewrites")
            except RelayError as e:
                mitm_ctx.log.warn(f"[tatar-relay] re-encrypt failed, sending original: {e}")

    def response(self, flow: "http.HTTPFlow") -> None:
        # feed extraction vars (e.g. session_key from a handshake response)
        if not self._in_scope(flow) or not flow.response or not flow.response.raw_content:
            return
        msg = HttpMessage(path=flow.request.path, headers=dict(flow.response.headers),
                          body=flow.response.raw_content)
        try:
            self.profile.feed(msg, "response", self._vars)
        except RelayError:
            pass


addons = [TatarRelay()]
