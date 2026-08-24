"""Envelope phase — the structural, asymmetric bookend.

``locate`` (forward) pulls the encrypted payload out of the wire body and
remembers everything else on the context. ``rebuild`` (backward) puts the
re-encrypted payload back where it came from. Multiple locate strategies are
tried in order; the first that matches wins.
"""
from __future__ import annotations

import json
import re
from typing import Any, List

from .context import Context
from .errors import DecryptError


class Envelope:
    def __init__(self, spec: dict | None):
        spec = spec or {}
        loc = spec.get("locate")
        if loc is None:
            # default: the whole body is the payload
            self.strategies: List[dict] = [{"in": "raw"}]
        elif isinstance(loc, dict):
            self.strategies = [loc]
        else:
            self.strategies = list(loc)

    # -- forward: extract payload, stash skeleton -------------------------
    def locate(self, body: bytes, ctx: Context):
        for strat in self.strategies:
            kind = strat.get("in", "raw")
            try:
                if kind == "raw":
                    ctx._scratch["envelope"] = {"kind": "raw"}
                    return body
                if kind == "json_field":
                    obj = json.loads(body.decode("utf-8"))
                    field = strat["field"]
                    if not isinstance(obj, dict) or field not in obj:
                        continue
                    ctx._scratch["envelope"] = {"kind": "json_field", "field": field, "skeleton": obj}
                    return obj[field]
                if kind == "header":
                    name = strat["name"]
                    msg = ctx.response if ctx.channel == "response" else ctx.request
                    val = msg.header(name)
                    if not val:
                        continue
                    ctx._scratch["envelope"] = {"kind": "header", "name": name, "body": body}
                    return val
                if kind == "regex":
                    m = re.search(strat["pattern"], body.decode("utf-8", "replace"))
                    if not m:
                        continue
                    ctx._scratch["envelope"] = {
                        "kind": "regex", "pattern": strat["pattern"], "body": body,
                        "span": m.span(1),
                    }
                    return m.group(1)
            except (json.JSONDecodeError, KeyError, IndexError):
                continue
        raise DecryptError(category="locate_failed",
                           message="no envelope locate strategy matched",
                           channel=ctx.channel, direction="forward")

    # -- backward: put payload back --------------------------------------
    def rebuild(self, payload, ctx: Context):
        env = ctx._scratch.get("envelope")
        if env is None:
            # No prior locate (encrypt-from-scratch, e.g. `validate --sample`).
            # Synthesize a skeleton from the first declared strategy.
            env = self._synthesize_env()
        kind = env["kind"]
        if kind == "raw":
            return payload
        if kind == "json_field":
            skeleton = dict(env["skeleton"])
            skeleton[env["field"]] = payload
            return skeleton  # dict; reseal.serialize turns it into bytes
        if kind == "header":
            # payload lived in a header; body is unchanged
            return env["body"]
        if kind == "regex":
            body = env["body"].decode("utf-8", "replace")
            s, e = env["span"]
            return (body[:s] + str(payload) + body[e:]).encode("utf-8")
        raise DecryptError(category="internal", message=f"unknown envelope kind {kind}")

    def _synthesize_env(self) -> dict:
        first = self.strategies[0]
        kind = first.get("in", "raw")
        if kind == "json_field":
            return {"kind": "json_field", "field": first["field"], "skeleton": {}}
        if kind == "raw":
            return {"kind": "raw"}
        raise DecryptError(
            category="internal",
            message=f"cannot encrypt from scratch with envelope '{kind}' "
                    f"(needs a prior decrypt to capture the envelope)",
        )
