"""Step interface + registry — Frozen Contract #3.

A Step is a pure, reversible transform. ``forward`` is the decrypt direction
(wire → plaintext); ``backward`` is the exact inverse (plaintext → wire). The
engine runs the transform list forward to decrypt and in reverse (calling
``backward``) to re-encrypt.
"""
from __future__ import annotations

import difflib
from typing import Callable, Dict, Sequence, Type

from ..datatypes import DataType
from ..context import Context
from ..errors import DecryptError, ProfileError
from ..variables import Renderer, coerce_key


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
        raise ProfileError(
            f"invalid step spec: {spec!r} — a step is either a bare name "
            f"('base64_decode') or a single-key mapping "
            f"('{{ aes_decrypt: {{ key: ... }} }}')")
    if name not in _REGISTRY:
        raise ProfileError(_unknown_step(name))
    if name == "python":
        params.setdefault("_base_dir", base_dir)
    return _REGISTRY[name](params)


def known_steps() -> list:
    return sorted(_REGISTRY)


def _unknown_step(name) -> str:
    """Turn a step-name typo into an actionable message, not a traceback."""
    known = known_steps()
    close = difflib.get_close_matches(str(name), known, n=1)
    hint = f" — did you mean '{close[0]}'?" if close else ""
    return f"unknown step: {name}{hint} (known: {', '.join(known)})"


_KEY_PREFIXES = ("str:", "hex:", "b64:")


def _read_as_bare_hex(rendered) -> bool:
    """True when ``rendered`` is a bare string that ``coerce_key`` hex-decodes.

    The hex reading is deliberate (see ``variables.coerce_key``) and it is what
    ``hmac_verify``, reseal ``sign``, ``--var`` and the bridge already did — but
    it is invisible in the resulting bytes. A text key made only of hex digits
    is therefore halved silently, and the operator is shown a ``padding`` /
    ``tag_mismatch`` that points at the cipher instead of at the key. Both the
    breadcrumb and the size hint below exist to name the reading that was taken.
    """
    if not isinstance(rendered, str) or rendered.startswith(_KEY_PREFIXES):
        return False
    try:
        bytes.fromhex(rendered)
    except ValueError:
        return False
    return True


def resolve_key(params: dict, ctx: Context, *, sizes: Sequence[int], label: str,
                size_label: str | None = None) -> bytes:
    """Render and validate a cipher step's ``key`` param.

    One implementation for every symmetric step: the AES and ChaCha20 copies had
    drifted apart. ``coerce_key`` supplies the shared ``str:``/``hex:``/``b64:``
    reading, so a key var means the same bytes here as in ``hmac_verify`` and
    reseal ``sign`` — which for a hex-looking string it did NOT before (the
    shipped acme-bank-mobile.yaml feeds one ``${session_key}`` to both).
    """
    tmpl = params.get("key")
    if tmpl is None:
        raise DecryptError(category="config_error", message=f"{label}: missing 'key'")
    rendered = Renderer(ctx.vars).render(tmpl)
    val = coerce_key(rendered, label)
    bare_hex = _read_as_bare_hex(rendered)
    if bare_hex:
        # Surfaces in `relay preview` and in the bridge's error detail.logs, so
        # the chosen reading is on the record even when the decrypt then fails.
        ctx.log(f"{label}: key var read as hex — {len(rendered)} bare hex "
                f"characters -> {len(val)} bytes (prefix it 'str:' for UTF-8 text)")
    if len(val) not in sizes:
        # Base text kept byte-for-byte; the clause is added only in the one case
        # where the length alone would misdirect.
        hint = (f" — the bare {len(rendered)}-character hex string was read as "
                f"hex; prefix it 'str:' if it is UTF-8 text") if bare_hex else ""
        raise DecryptError(
            category="wrong_key_size",
            message=f"{size_label or label}: key must be "
                    f"{'/'.join(str(n) for n in sizes)} bytes, got {len(val)}{hint}")
    return val
