"""Reseal phase — integrity/authentication, applied on the way back out.

Runs only in the backward (encrypt) direction, after the envelope is rebuilt.
Typical order: ``set`` (add ts/nonce) → ``sign`` (HMAC) → ``serialize`` (dict →
bytes, terminal). The canonical-serialization modes exist because re-serializing
JSON can reorder keys and silently break a signature even with the right key.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

from .context import Context
from .errors import DecryptError
from .variables import Renderer

_SERIALIZE_MODES = ("preserve", "canonical", "compact")

# Supported HMAC sign algorithms (backward-compatible: hmac_sha256 stays default).
_SIGN_ALGOS = {
    "hmac_sha256": hashlib.sha256,
    "hmac_sha512": hashlib.sha512,
    "hmac_sha1": hashlib.sha1,
}


def _to_bytes(v) -> bytes:
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    return str(v).encode("utf-8")


class Reseal:
    def __init__(self, specs: list | None):
        self.specs = list(specs or [])

    def _extras(self, payload, ctx: Context) -> dict:
        payload_bytes = _to_bytes(payload)
        extras = {
            "payload": payload if isinstance(payload, str) else payload_bytes.decode("latin-1"),
            "payload_b64": base64.b64encode(payload_bytes).decode("ascii"),
        }
        msg = ctx.response if ctx.channel == "response" else ctx.request
        for k, v in msg.headers.items():
            extras[f"header.{k}"] = v
        return extras

    def apply(self, carrier, payload, ctx: Context) -> bytes:
        """Run reseal steps; always returns the final wire bytes."""
        rnd = Renderer(ctx.vars, self._extras(payload, ctx))
        serialized = False
        for spec in self.specs:
            name, params = _split(spec)
            if name == "set":
                _require_dict(carrier, "set")
                carrier[params["field"]] = rnd.render(params["value"])
            elif name == "sign":
                carrier = self._sign(carrier, params, rnd)
            elif name == "serialize":
                carrier = self._serialize(carrier, params)
                serialized = True
            else:
                raise DecryptError(category="config_error",
                                   message=f"unknown reseal step: {name}")
        if not serialized:
            carrier = self._serialize(carrier, {"mode": "preserve"})
        return carrier

    def _sign(self, carrier, params, rnd: Renderer):
        _require_dict(carrier, "sign")
        algo = params.get("algo", "hmac_sha256")
        hashfn = _SIGN_ALGOS.get(algo)
        if hashfn is None:
            raise DecryptError(
                category="config_error",
                message=f"unsupported sign algo: {algo} "
                        f"(supported: {', '.join(_SIGN_ALGOS)})")
        key = _to_bytes(rnd.render(params["key"]))
        msg = rnd.render_bytes(params["input"])
        mac = hmac.new(key, msg, hashfn).digest()
        enc = params.get("encoding", "hex")
        carrier[params["into"]] = mac.hex() if enc == "hex" else base64.b64encode(mac).decode("ascii")
        return carrier

    def _serialize(self, carrier, params) -> bytes:
        if isinstance(carrier, (bytes, bytearray)):
            return bytes(carrier)
        if isinstance(carrier, str):
            return carrier.encode("utf-8")
        mode = params.get("mode", "preserve")
        if mode not in _SERIALIZE_MODES:
            raise DecryptError(category="config_error", message=f"bad serialize mode: {mode}")
        if mode == "canonical":
            return json.dumps(carrier, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False).encode("utf-8")
        if mode == "compact":
            return json.dumps(carrier, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        # preserve: keep insertion order with standard spacing (", " / ": "),
        # distinct from compact — matches servers that emit spaced JSON.
        return json.dumps(carrier, separators=(", ", ": "), ensure_ascii=False).encode("utf-8")


def _split(spec):
    if isinstance(spec, str):
        return spec, {}
    if isinstance(spec, dict) and len(spec) == 1:
        k, v = next(iter(spec.items()))
        return k, (v or {})
    raise DecryptError(category="config_error", message=f"bad reseal spec: {spec!r}")


def _require_dict(carrier, step):
    if not isinstance(carrier, dict):
        raise DecryptError(category="config_error",
                           message=f"reseal '{step}' needs a JSON object, "
                                   f"but the payload was already serialized")
