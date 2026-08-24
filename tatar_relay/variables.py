"""Variable engine + safe ``${...}`` template rendering + extraction.

Templates are intentionally NOT a programming language. Only a fixed set of
tokens is understood; anything more complex belongs in a Python hook. No eval,
ever.
"""
from __future__ import annotations

import os
import re
import time
from typing import Any, Callable, Dict, Optional

from .errors import DecryptError

_TOKEN = re.compile(r"\$\{([^}]+)\}")
_RANDOM_HEX = re.compile(r"^random_hex\((\d+)\)$")


class VarStore:
    """Resolved variables for one flow.

    A value may be static (extracted once, cached) or ``live`` (recomputed for
    every message, e.g. a counter or nonce). Live values are produced by a
    callable registered under the name.
    """

    def __init__(self) -> None:
        self._static: Dict[str, Any] = {}
        self._live: Dict[str, Callable[[], Any]] = {}

    def set(self, name: str, value: Any) -> None:
        self._static[name] = value

    def set_live(self, name: str, producer: Callable[[], Any]) -> None:
        self._live[name] = producer

    def has(self, name: str) -> bool:
        return name in self._static or name in self._live

    def get(self, name: str) -> Any:
        if name in self._live:
            return self._live[name]()
        if name in self._static:
            return self._static[name]
        raise KeyError(name)

    def as_dict(self) -> Dict[str, Any]:
        out = dict(self._static)
        for k, prod in self._live.items():
            out[k] = prod()
        return out


class Renderer:
    """Resolves ``${...}`` templates against vars + reseal-time extras.

    ``extras`` supplies reseal values like ``payload``, ``payload_b64`` and
    envelope fields (``header.X-Ts`` etc.).
    """

    def __init__(self, varstore: Optional[VarStore] = None, extras: Optional[dict] = None):
        self.vars = varstore
        self.extras = extras or {}

    def _resolve_token(self, token: str) -> Any:
        token = token.strip()
        if token == "now_ms":
            return str(int(time.time() * 1000))
        m = _RANDOM_HEX.match(token)
        if m:
            return os.urandom(int(m.group(1))).hex()
        if token in self.extras:
            return self.extras[token]
        if self.vars is not None and self.vars.has(token):
            return self.vars.get(token)
        raise DecryptError(
            category="config_error",
            message=f"unknown template variable: ${{{token}}}",
        )

    def render(self, template: str) -> Any:
        """Render a template.

        If the whole template is a single token (``"${session_key}"``) the raw
        value is returned (so keys can stay ``bytes``). Otherwise the result is a
        string with each token substituted.
        """
        if not isinstance(template, str):
            return template
        m = _TOKEN.fullmatch(template.strip())
        if m:
            return self._resolve_token(m.group(1))

        def repl(match: "re.Match") -> str:
            val = self._resolve_token(match.group(1))
            if isinstance(val, (bytes, bytearray)):
                return val.decode("latin-1")
            return str(val)

        return _TOKEN.sub(repl, template)

    def render_bytes(self, template: str) -> bytes:
        val = self.render(template)
        if isinstance(val, (bytes, bytearray)):
            return bytes(val)
        return str(val).encode("utf-8")


# -- extraction -----------------------------------------------------------

def json_path_get(obj: Any, path: str) -> Any:
    """Tiny ``$.a.b.c`` JSON-path subset (no wildcards/filters).

    Anything fancier should use a hook.
    """
    if not path.startswith("$"):
        raise DecryptError(category="config_error", message=f"bad json_path: {path}")
    cur = obj
    for part in path[1:].split("."):
        if part == "":
            continue
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            raise KeyError(part)
    return cur
