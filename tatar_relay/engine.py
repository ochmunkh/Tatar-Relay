"""The pipeline engine: Envelope → Transform → Reseal, with fail-safe.

The engine knows nothing about proxies. It turns wire bytes into plaintext and
plaintext back into wire bytes for one channel (request/response) of one flow.
"""
from __future__ import annotations

from typing import List

from .context import Context
from .datatypes import DataType
from .envelope import Envelope
from .errors import DecryptError, ProfileError
from .reseal import Reseal
from .steps.base import Step, build_step


class ChannelPipeline:
    """Envelope + ordered transform steps + reseal, for one channel."""

    def __init__(self, spec: dict | None):
        spec = spec or {}
        self.envelope = Envelope(spec.get("envelope"))
        self.transform: List[Step] = [build_step(s) for s in (spec.get("transform") or [])]
        self.reseal = Reseal(spec.get("reseal"))
        self._check_types()

    def _check_types(self) -> None:
        prev = None
        for step in self.transform:
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
        return payload

    # -- backward: plaintext → wire --------------------------------------
    def encrypt(self, plaintext, ctx: Context) -> bytes:
        ctx.direction = "backward"
        data = plaintext
        for step in reversed(self.transform):
            data = _run(step.backward, data, ctx, step.name, "backward")
        carrier = self.envelope.rebuild(data, ctx)
        return self.reseal.apply(carrier, data, ctx)


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
