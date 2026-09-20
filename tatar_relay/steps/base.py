"""Step interface + registry — Frozen Contract #3.

A Step is a pure, reversible transform. ``forward`` is the decrypt direction
(wire → plaintext); ``backward`` is the exact inverse (plaintext → wire). The
engine runs the transform list forward to decrypt and in reverse (calling
``backward``) to re-encrypt.
"""
from __future__ import annotations

from typing import Callable, Dict, Type

from ..datatypes import DataType
from ..context import Context


class Step:
    name: str = "step"
    in_type: DataType = DataType.ANY
    out_type: DataType = DataType.ANY

    def __init__(self, params: dict | None = None):
        self.params = params or {}
        self.configure()

    def configure(self) -> None:
        """Validate/parse params at load time. Override as needed."""

    def forward(self, data, ctx: Context):  # wire → plaintext
        raise NotImplementedError

    def backward(self, data, ctx: Context):  # plaintext → wire
        raise NotImplementedError


_REGISTRY: Dict[str, Type[Step]] = {}


def register(name: str) -> Callable[[Type[Step]], Type[Step]]:
    def deco(cls: Type[Step]) -> Type[Step]:
        cls.name = name
        if name in _REGISTRY:
            raise ValueError(f"duplicate step registration: {name}")
        _REGISTRY[name] = cls
        return cls
    return deco


def build_step(spec, base_dir: str = ".") -> Step:
    """Build a Step from a profile spec.

    A spec is either ``"base64_decode"`` (bare name) or ``{"aes_decrypt": {...}}``.
    ``base_dir`` is the profile's directory, used to resolve Python hook files.
    """
    if isinstance(spec, str):
        name, params = spec, {}
    elif isinstance(spec, dict) and len(spec) == 1:
        name, params = next(iter(spec.items()))
        params = dict(params or {})
    else:
        raise ValueError(f"invalid step spec: {spec!r}")
    if name not in _REGISTRY:
        raise ValueError(f"unknown step: {name}")
    if name == "python":
        params.setdefault("_base_dir", base_dir)
    return _REGISTRY[name](params)


def known_steps() -> list:
    return sorted(_REGISTRY)
