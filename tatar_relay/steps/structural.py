"""Boundary step: bytes <-> parsed JSON. This is where 'plaintext' begins."""
from __future__ import annotations

import json

from ..context import Context
from ..datatypes import DataType
from ..errors import DecryptError
from .base import Step, register


@register("as_json")
class AsJson(Step):
    in_type = DataType.BYTES
    out_type = DataType.JSON

    def forward(self, data, ctx: Context):
        raw = data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else data
        try:
            return json.loads(raw)
        except json.JSONDecodeError as e:
            raise DecryptError(category="type_mismatch",
                               message=f"as_json: not valid JSON: {e}",
                               step=self.name, direction="forward")

    def backward(self, data, ctx: Context) -> bytes:
        # compact, stable separators; reseal.serialize handles fancier modes.
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@register("as_text")
class AsText(Step):
    in_type = DataType.BYTES
    out_type = DataType.TEXT

    def forward(self, data, ctx: Context) -> str:
        return data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else str(data)

    def backward(self, data, ctx: Context) -> bytes:
        return data.encode("utf-8") if isinstance(data, str) else bytes(data)
