"""Profile v1 — Frozen Contract #1.

Loads and validates a profile, builds the request/response pipelines (so type
errors surface at load, not mid-request), enforces scope fail-closed, and wires
variable extraction + hooks.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import yaml

from .context import Context, HttpMessage
from .engine import ChannelPipeline
from .errors import DecryptError, ProfileError, ScopeViolation
from .hooks import load_hook
from .variables import VarStore, json_path_get


@dataclass
class Scope:
    hosts: List[str] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)

    def matches_host(self, host: str) -> bool:
        return any(re.search(h, host) for h in self.hosts)

    def matches(self, host: str, path: str) -> bool:
        path_ok = (not self.paths) or any(re.search(p, path) for p in self.paths)
        return self.matches_host(host) and path_ok


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
                self.pipelines[channel] = ChannelPipeline(data[channel], self.base_dir)
        if "request" not in self.pipelines:
            raise ProfileError(f"profile '{self.name}': a 'request' pipeline is required")

    # -- loading ----------------------------------------------------------
    @classmethod
    def load(cls, path: str) -> "Profile":
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except OSError as e:
            raise ProfileError(f"{path}: cannot read profile ({e.strerror or e})")
        except yaml.YAMLError as e:
            raise ProfileError(f"{path}: invalid YAML{_yaml_where(e)}: {_yaml_why(e)}")
        if not isinstance(data, dict):
            raise ProfileError(f"{path}: profile must be a YAML mapping")
        return cls(data, base_dir=os.path.dirname(os.path.abspath(path)))

    @classmethod
    def loads(cls, text: str, base_dir: str = ".") -> "Profile":
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as e:
            raise ProfileError(f"invalid YAML{_yaml_where(e)}: {_yaml_why(e)}")
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

    def authorize(self, host: str, path: Optional[str] = None) -> None:
        """Per-request, fail-closed authorization — call this from a frontend.

        ``path=None`` authorizes the HOST only. A frontend that knows the host
        but not the path (the Burp bridge, ``relay run --host``) must not be
        refused by the profile's ``paths:`` regexes, which would make the check
        unusable and so leave it unwired — which is how it stayed narrative.
        When a path IS supplied, both halves are checked (``check_scope``).
        """
        if path is None:
            if not self.scope.matches_host(host):
                raise ScopeViolation(
                    f"profile '{self.name}': host '{host}' is outside "
                    f"authorized scope {self.scope.hosts}"
                )
            return
        self.check_scope(host, path)

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
        """Populate extraction vars from a request/response message.

        Every var that CAN be extracted is set before anything is reported, so
        one missing field never costs the operator the vars that did resolve.
        Whatever is still missing is then raised as one ``extraction_failed``.
        """
        missing = []
        for name, spec in self._var_specs.items():
            if (spec or {}).get("from") != "extraction":
                continue
            if spec.get("source", "response") != source:
                continue
            match = spec.get("match")
            if match and not _search(match, message.path, name):
                continue
            value = self._extract(spec, message, name)
            if value is None:
                missing.append(name)
                continue
            for t in spec.get("transform") or []:
                value = self._apply_var_transform(t, value)
            vs.set(name, value)
        if missing:
            # The handshake message for these vars arrived but none of their
            # locate strategies matched. Say so here: swallowing it surfaces
            # later as tag_mismatch/padding and points the operator at the
            # cipher step instead of at the handshake.
            names = ", ".join(f"'{n}'" for n in missing)
            raise DecryptError(
                category="extraction_failed",
                message=f"var {names}: no locate strategy matched on "
                        f"{message.path or '<no path>'}")

    def _extract(self, spec: dict, message: HttpMessage, name: str = "?"):
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
                    m = _search(loc["regex"],
                                message.body.decode("utf-8", "replace"), name)
                    if m:
                        return m.group(1)
        except (KeyError, ValueError, UnicodeDecodeError):
            # Malformed handshake body: report it as "not found" so feed() raises
            # one extraction_failed naming the var, rather than a bare traceback.
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


def _search(pattern: str, text: str, var: str):
    """``re.search`` whose bad-pattern failure names the offending profile var."""
    try:
        return re.search(pattern, text)
    except re.error as e:
        raise DecryptError(category="config_error",
                           message=f"var '{var}': bad regex {pattern!r}: {e}")


def _yaml_where(e: Exception) -> str:
    """'' or ' at line N, column M' from a PyYAML mark, for an actionable error."""
    mark = getattr(e, "problem_mark", None) or getattr(e, "context_mark", None)
    if mark is None:
        return ""
    return f" at line {mark.line + 1}, column {mark.column + 1}"


def _yaml_why(e: Exception) -> str:
    return str(getattr(e, "problem", None) or e).strip()


def _has_python(data: dict) -> bool:
    for ch in ("request", "response"):
        chan = data.get(ch) or {}
        for step in chan.get("transform") or []:
            if isinstance(step, dict) and "python" in step:
                return True
        for step in chan.get("reseal") or []:
            if isinstance(step, dict) and "python" in step:
                return True
        # header sub-pipelines (full-envelope class) can also carry python steps
        for h in (chan.get("envelope") or {}).get("headers") or []:
            for step in (h or {}).get("transform") or []:
                if isinstance(step, dict) and "python" in step:
                    return True
    for _, spec in (data.get("vars") or {}).items():
        if (spec or {}).get("from") == "hook":
            return True
    return False
