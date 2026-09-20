"""The pipeline engine: Envelope → Transform → Reseal, with fail-safe.

The engine knows nothing about proxies. It turns wire bytes into plaintext and
plaintext back into wire bytes for one channel (request/response) of one flow.

Beyond the body payload, a channel may also carry independently-encrypted
*headers* (the "full envelope" class). Each such header is decrypted in place on
the message during decrypt and re-encrypted during encrypt, so the operator sees
readable headers and an edit to one reseals.
"""
from __future__ import annotations

import json
from typing import List, Tuple

from .context import Context
from .datatypes import DataType
from .envelope import Envelope
from .errors import DecryptError, ProfileError
from .reseal import Reseal
from .steps.base import Step, build_step


def _stringify(v) -> str:
    if isinstance(v, str):
        return v
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).decode("utf-8", "replace")
    return json.dumps(v, separators=(",", ":"), ensure_ascii=False)


class ChannelPipeline:
    """Envelope + ordered transform steps + reseal, for one channel."""

    def __init__(self, spec: dict | None, base_dir: str = "."):
        spec = spec or {}
        env_spec = spec.get("envelope") or {}
        self.envelope = Envelope(env_spec)
        self.transform: List[Step] = [build_step(s, base_dir) for s in (spec.get("transform") or [])]
        self.reseal = Reseal(spec.get("reseal"))
        # Optional per-header sub-pipelines (the full-envelope class).
        self.header_pipes: List[Tuple[str, List[Step]]] = []
        for h in (env_spec.get("headers") or []):
            if "name" not in h:
                raise ProfileError("envelope.headers[] entry needs a 'name'")
            steps = [build_step(s, base_dir) for s in (h.get("transform") or [])]
            self._check_types(steps)
            self.header_pipes.append((h["name"], steps))
        self._check_types(self.transform)

    def _check_types(self, steps: List[Step]) -> None:
        prev = None
        for step in steps:
            if prev is not None and not step.in_type.accepts(prev.out_type):
                raise ProfileError(
                    f"type mismatch: step '{step.name}' expects {step.in_type.value} "
                    f"but '{prev.name}' produced {prev.out_type.value}"
                )
            prev = step

    # -- forward: wire → plaintext ---------------------------------------
    def decrypt(self, body: bytes, ctx: Context):
        ctx.direction = "forward"
        payload = self.envelope.locate(body, ctx)
        for step in self.transform:
            payload = _run(step.forward, payload, ctx, step.name, "forward")
        self._decrypt_headers(ctx)
        return payload

    # -- backward: plaintext → wire --------------------------------------
    def encrypt(self, plaintext, ctx: Context) -> bytes:
        ctx.direction = "backward"
        data = plaintext
        for step in reversed(self.transform):
            data = _run(step.backward, data, ctx, step.name, "backward")
        carrier = self.envelope.rebuild(data, ctx)
        self._encrypt_headers(ctx)
        return self.reseal.apply(carrier, data, ctx)

    # -- encrypted headers (full-envelope class) -------------------------
    def _msg(self, ctx: Context):
        return ctx.response if ctx.channel == "response" else ctx.request

    def _decrypt_headers(self, ctx: Context) -> None:
        if not self.header_pipes:
            return
        msg = self._msg(ctx)
        for name, steps in self.header_pipes:
            raw = msg.header(name)
            if not raw:
                continue
            value = raw
            for step in steps:
                value = _run(step.forward, value, ctx, step.name, "forward")
            msg.set_header(name, _stringify(value))

    def _encrypt_headers(self, ctx: Context) -> None:
        if not self.header_pipes:
            return
        msg = self._msg(ctx)
        for name, steps in self.header_pipes:
            cur = msg.header(name)
            if not cur:
                continue
            value = cur
            for step in reversed(steps):
                value = _run(step.backward, value, ctx, step.name, "backward")
            msg.set_header(name, _stringify(value))


def _run(fn, data, ctx, step_name, direction):
    """Fail-safe wrapper: structured errors, never a bare crash."""
    try:
        return fn(data, ctx)
    except DecryptError as e:
        e.step = e.step or step_name
        e.direction = e.direction or direction
        e.channel = e.channel or ctx.channel
        raise
    except Exception as e:  # noqa: BLE001 - convert anything into a structured error
        raise DecryptError(category="internal", message=f"{type(e).__name__}: {e}",
                           step=step_name, direction=direction, channel=ctx.channel)


class Engine:
    """Bind a loaded profile to decrypt/encrypt operations."""

    def __init__(self, profile):
        self.profile = profile

    def _pipeline(self, channel: str) -> ChannelPipeline:
        pipe = self.profile.pipeline(channel)
        if pipe is None:
            raise DecryptError(category="config_error",
                               message=f"profile has no '{channel}' pipeline")
        return pipe

    def decrypt(self, channel: str, body: bytes, ctx: Context):
        ctx.channel = channel
        return self._pipeline(channel).decrypt(body, ctx)

    def encrypt(self, channel: str, plaintext, ctx: Context) -> bytes:
        ctx.channel = channel
        return self._pipeline(channel).encrypt(plaintext, ctx)
