"""Context — Frozen Contract #2.

The single object every step and every user hook receives. Its shape is a
public contract: once frozen, fields are only ever added, never renamed or
removed within a major version.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .errors import DecryptError


@dataclass
class HttpMessage:
    """A minimal, frontend-agnostic view of one HTTP message."""

    method: str = ""
    url: str = ""
    host: str = ""
    path: str = ""
    headers: dict = field(default_factory=dict)
    body: bytes = b""

    def header(self, name: str, default: str = "") -> str:
        # case-insensitive lookup
        low = name.lower()
        for k, v in self.headers.items():
            if k.lower() == low:
                return v
        return default


class Context:
    """Carried through one decrypt→edit→encrypt cycle for a single flow."""

    def __init__(
        self,
        *,
        direction: str = "forward",
        channel: str = "request",
        request: Optional[HttpMessage] = None,
        response: Optional[HttpMessage] = None,
        matched: Optional[dict] = None,
        variables: Optional["object"] = None,   # VarStore (avoid import cycle)
        session: Optional[dict] = None,
    ) -> None:
        self.direction = direction
        self.channel = channel
        self.request = request or HttpMessage()
        self.response = response
        self.matched = matched or {}
        self.vars = variables
        # Per-flow state. Counters, key rotation, etc. live HERE, never in
        # module-level globals — otherwise concurrent Intruder requests collide.
        self.session: dict = session if session is not None else {}
        # Engine-internal scratch (envelope skeleton, located payload …).
        # Not part of the public contract; hooks should ignore it.
        self._scratch: dict = {}
        self._logs: list = []

    # -- public API -------------------------------------------------------
    def log(self, msg: str, level: str = "info") -> None:
        self._logs.append((level, msg))

    def fail(self, reason: str, category: str = "hook_error", **detail) -> "None":
        raise DecryptError(
            category=category,
            message=reason,
            direction=self.direction,
            channel=self.channel,
            detail=detail,
        )

    @property
    def logs(self):
        return list(self._logs)
