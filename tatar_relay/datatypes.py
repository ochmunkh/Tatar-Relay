"""The small type lattice values flow through the pipeline as.

Steps declare ``in_type``/``out_type`` so the profile loader can check that a
pipeline chains correctly *before* any traffic is touched (fail early, not in
the middle of a live request).
"""
from __future__ import annotations

from enum import Enum


class DataType(str, Enum):
    BYTES = "bytes"
    TEXT = "text"
    JSON = "json"   # dict or list
    FORM = "form"   # urlencoded mapping
    ANY = "any"     # matches anything (used by hooks)

    def accepts(self, other: "DataType") -> bool:
        """Can a value produced as ``other`` be fed into an input of ``self``?"""
        return self is DataType.ANY or other is DataType.ANY or self is other


def runtime_type(value) -> DataType:
    if isinstance(value, (bytes, bytearray)):
        return DataType.BYTES
    if isinstance(value, str):
        return DataType.TEXT
    if isinstance(value, (dict, list)):
        return DataType.JSON
    return DataType.ANY
