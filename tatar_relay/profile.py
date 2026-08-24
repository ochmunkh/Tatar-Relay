"""Profile v1 — Frozen Contract #1.

Loads and validates a profile, builds the request/response pipelines (so type
errors surface at load, not mid-request), enforces scope fail-closed, and wires
variable extraction + hooks.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

from .context import Context, HttpMessage
from .engine import ChannelPipeline
from .errors import ProfileError, ScopeViolation, DecryptError
from .hooks import load_hook
from .variables import Renderer, VarStore, json_path_get


@dataclass
class Scope:
    hosts: List[str] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)

    def matches(self, host: str, path: str) -> bool:
        host_ok = any(re.search(h, host) for h in self.hosts)
        path_ok = (not self.paths) or any(re.search(p, path) for p in self.paths)
        return host_ok and path_ok


class Profile:
    def __init__(self, data: dict, base_dir: str = "."):
        self.base_dir = base_dir
        self.name: str = data.get("name", "unnamed")
        self.raw = data
        self.allow_python_hooks: bool = bool(
            (data.get("security") or {}).get("allow_python_hooks", False)
        )
        self.view: dict = data.get("view") or {}
        self._var_specs: Dict[str, dict] = data.get("vars") or {}

        # -- scope: FAIL-CLOSED ------------------------------------------
        scope_raw = data.get("scope") or {}
        hosts = scope_raw.get("hosts") or []
        if not hosts:
            raise ProfileError(
                f"profile '{self.name}': scope.hosts is required (fail-closed). "
                f"Refusing to load a profile with no authorized hosts."
            )
        self.scope = Scope(hosts=hosts, paths=scope_raw.get("paths") or [])

        # -- reject python hooks in untrusted profiles -------------------
        self._guard_hooks(data)

        # -- build pipelines (validates steps + types at load) -----------
        self.pipelines: Dict[str, ChannelPipeline] = {}
        for channel in ("request", "response"):
            if channel in data:
                self.pipelines[channel] = ChannelPipeline(data[channel])
        if "request" not in self.pipelines:
            raise ProfileError(f"profile '{self.name}': a 'request' pipeline is required")

    # -- loading ----------------------------------------------------------
    @classmethod
    def load(cls, path: str) -> "Profile":
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            raise ProfileError(f"{path}: profile must be a YAML mapping")
        return cls(data, base_dir=os.path.dirname(os.path.abspath(path)))

    @classmethod
    def loads(cls, text: str, base_dir: str = ".") -> "Profile":
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            raise ProfileError("profile must be a YAML mapping")
        return cls(data, base_dir=base_dir)

    # -- scope ------------------------------------------------------------
    def check_scope(self, host: str, path: str = "/") -> None:
        if not self.scope.matches(host, path):
            raise ScopeViolation(
                f"profile '{self.name}': host '{host}' path '{path}' is outside "
                f"authorized scope {self.scope.hosts}"
            )

    def pipeline(self, channel: str) -> Optional[ChannelPipeline]:
        return self.pipelines.get(channel)

    # -- variables --------------------------------------------------------
    def new_varstore(self, ctx: Context) -> VarStore:
        vs = VarStore()
        for name, spec in self._var_specs.items():
            src = (spec or {}).get("from")
            if src == "hook":
                fn = load_hook(self._hook_file(spec), spec["name"], self.base_dir)
                if spec.get("live"):
                    vs.set_live(name, lambda fn=fn, ctx=ctx: fn(ctx))
                else:
                    vs.set(name, fn(ctx))
            # 'extraction' vars are populated by feed() when the matching
            # handshake message is seen.
        return vs

    def feed(self, message: HttpMessage, source: str, vs: VarStore) -> None:
        """Populate extraction vars from a request/response message."""
        for name, spec in self._var_specs.items():
            if (spec or {}).get("from") != "extraction":
                continue
            if spec.get("source", "response") != source:
                continue
            match = spec.get("match")
            if match and not re.search(match, message.path):
                continue
            value = self._extract(spec, message)
            if value is not None:
                for t in spec.get("transform") or []:
                    value = self._apply_var_transform(t, value)
                vs.set(name, value)

    def _extract(self, spec: dict, message: HttpMessage):
        try:
            body_json = None
            for loc in spec.get("locate") or []:
                if "json_path" in loc:
                    if body_json is None:
                        import json
                        body_json = json.loads(message.body.decode("utf-8"))
                    try:
                        return json_path_get(body_json, loc["json_path"])
                    except KeyError:
                        continue
                if "header" in loc:
                    v = message.header(loc["header"])
                    if v:
                        return v
                if "regex" in loc:
                    m = re.search(loc["regex"], message.body.decode("utf-8", "replace"))
                    if m:
                        return m.group(1)
        except Exception:  # noqa: BLE001
            return None
        return None

    @staticmethod
    def _apply_var_transform(t: str, value):
        import base64
        if t == "base64_decode":
            if isinstance(value, str):
                value = value.encode("ascii")
            return base64.b64decode(value)
        if t == "hex_decode":
            return bytes.fromhex(value if isinstance(value, str) else value.decode())
        return value

    # -- helpers ----------------------------------------------------------
    def _hook_file(self, spec: dict) -> str:
        f = spec.get("file")
        if not f:
            # convention: hooks/<profile>.py
            return os.path.join("hooks", f"{self.name}.py")
        return f

    def _guard_hooks(self, data: dict) -> None:
        if self.allow_python_hooks:
            return
        if _has_python(data):
            raise ProfileError(
                f"profile '{self.name}': contains Python hooks but "
                f"allow_python_hooks is false. Untrusted/community profiles "
                f"must be declarative-only. Set security.allow_python_hooks: true "
                f"only for local profiles you trust."
            )


def _has_python(data: dict) -> bool:
    for ch in ("request", "response"):
        for step in (data.get(ch) or {}).get("transform") or []:
            if isinstance(step, dict) and "python" in step:
                return True
        for step in (data.get(ch) or {}).get("reseal") or []:
            if isinstance(step, dict) and "python" in step:
                return True
    for _, spec in (data.get("vars") or {}).items():
        if (spec or {}).get("from") == "hook":
            return True
    return False
