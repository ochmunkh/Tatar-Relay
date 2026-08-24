"""Encoding steps: base64, hex, gzip. All reversible."""
from __future__ import annotations

import base64
import binascii
import gzip

from ..context import Context
from ..datatypes import DataType
from ..errors import DecryptError
from .base import Step, register


def _as_bytes(data) -> bytes:
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    if isinstance(data, str):
        return data.encode("utf-8")
    raise DecryptError(category="type_mismatch", message="expected bytes/text")


@register("base64_decode")
class Base64Decode(Step):
    in_type = DataType.TEXT
    out_type = DataType.BYTES

    def forward(self, data, ctx: Context) -> bytes:
        try:
            return base64.b64decode(_as_bytes(data), validate=False)
        except (binascii.Error, ValueError) as e:
            raise DecryptError(category="config_error", message=f"base64 decode: {e}",
                               step=self.name, direction="forward")

    def backward(self, data, ctx: Context) -> str:
        return base64.b64encode(_as_bytes(data)).decode("ascii")


@register("hex_decode")
class HexDecode(Step):
    in_type = DataType.TEXT
    out_type = DataType.BYTES

    def forward(self, data, ctx: Context) -> bytes:
        try:
            return bytes.fromhex(_as_bytes(data).decode("ascii").strip())
        except ValueError as e:
            raise DecryptError(category="config_error", message=f"hex decode: {e}",
                               step=self.name, direction="forward")

    def backward(self, data, ctx: Context) -> str:
        return _as_bytes(data).hex()


@register("gunzip")
class Gunzip(Step):
    in_type = DataType.BYTES
    out_type = DataType.BYTES

    def forward(self, data, ctx: Context) -> bytes:
        try:
            return gzip.decompress(_as_bytes(data))
        except (OSError, EOFError) as e:
            raise DecryptError(category="config_error", message=f"gunzip: {e}",
                               step=self.name, direction="forward")

    def backward(self, data, ctx: Context) -> bytes:
        return gzip.compress(_as_bytes(data))
