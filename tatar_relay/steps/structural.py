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
        try:
            raw = data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else data
            return json.loads(raw)
        except UnicodeDecodeError as e:
            raise DecryptError(category="type_mismatch",
                               message=f"as_json: plaintext is not valid UTF-8 ({e.reason} at byte {e.start})",
                               step=self.name, direction="forward")
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
        try:
            return data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else str(data)
        except UnicodeDecodeError as e:
            # attacker-influenced plaintext: classify, and never echo its bytes
            raise DecryptError(category="type_mismatch",
                               message=f"as_text: plaintext is not valid UTF-8 ({e.reason} at byte {e.start})",
                               step=self.name, direction="forward")

    def backward(self, data, ctx: Context) -> bytes:
        return data.encode("utf-8") if isinstance(data, str) else bytes(data)
