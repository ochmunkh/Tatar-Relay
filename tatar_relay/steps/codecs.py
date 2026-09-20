"""Encoding steps: base64, hex, gzip, nonce_body, strip_prefix. All reversible."""
from __future__ import annotations

import base64
import binascii
import gzip

from ..context import Context
from ..datatypes import DataType
from ..errors import DecryptError
from ..variables import Renderer
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


def _dec_seg(s: str, enc: str) -> bytes:
    if enc == "hex":
        return bytes.fromhex(s)
    if enc == "base64":
        pad = (4 - len(s) % 4) % 4
        return base64.b64decode(s + "=" * pad)
    if enc == "raw":
        return s.encode("latin-1")
    raise DecryptError(category="config_error", message=f"nonce_body: bad encoding {enc!r}")


def _enc_seg(b: bytes, enc: str) -> str:
    if enc == "hex":
        return b.hex()
    if enc == "base64":
        return base64.b64encode(b).decode("ascii")
    if enc == "raw":
        return b.decode("latin-1")
    raise DecryptError(category="config_error", message=f"nonce_body: bad encoding {enc!r}")


@register("nonce_body")
class NonceBody(Step):
    """Split/join a field encoded as ``<nonce><body>`` into raw ``nonce||body`` bytes.

    Many apps put a per-message nonce in front of the ciphertext as a *string*
    (e.g. a hex nonce immediately followed by a base64 ciphertext+tag). Chain
    this before ``aes_decrypt``/``chacha20_decrypt`` with ``iv.source: prefix``
    so the cipher sees the raw ``nonce || ciphertext`` it expects — no Python
    hook needed.

        transform:
          - nonce_body: { nonce_encoding: hex, nonce_length: 12, body_encoding: base64 }
          - aes_decrypt: { mode: gcm, key: "${session_key}", iv: { source: prefix, length: 12 } }
          - as_json

    forward:  "<enc nonce><enc body>"  ->  nonce_bytes || body_bytes
    backward: nonce_bytes || body_bytes ->  "<enc nonce><enc body>"
    """

    in_type = DataType.TEXT
    out_type = DataType.BYTES

    _ENCODINGS = ("hex", "base64", "raw")

    def configure(self) -> None:
        self.nonce_encoding = self.params.get("nonce_encoding", "hex")
        self.body_encoding = self.params.get("body_encoding", "base64")
        self.nonce_length = int(self.params.get("nonce_length", 12))
        for name, enc in (("nonce_encoding", self.nonce_encoding),
                          ("body_encoding", self.body_encoding)):
            if enc not in self._ENCODINGS:
                raise DecryptError(category="config_error",
                                   message=f"nonce_body: {name} must be one of {self._ENCODINGS}")

    def _prefix_chars(self) -> int:
        """How many encoded characters the nonce occupies at the front."""
        if self.nonce_encoding == "hex":
            return 2 * self.nonce_length
        if self.nonce_encoding == "base64":
            return 4 * ((self.nonce_length + 2) // 3)  # padded base64 length
        return self.nonce_length  # raw: one char per byte (latin-1)

    def forward(self, data, ctx: Context) -> bytes:
        s = data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else str(data)
        s = s.strip()
        n = self._prefix_chars()
        if len(s) < n:
            raise DecryptError(category="config_error",
                               message="nonce_body: field shorter than the nonce prefix",
                               step=self.name, direction="forward")
        try:
            nonce = _dec_seg(s[:n], self.nonce_encoding)
            body = _dec_seg(s[n:], self.body_encoding)
        except (ValueError, binascii.Error) as e:
            raise DecryptError(category="config_error", message=f"nonce_body: decode failed: {e}",
                               step=self.name, direction="forward")
        return nonce + body

    def backward(self, data, ctx: Context) -> str:
        b = _as_bytes(data)
        nonce, body = b[: self.nonce_length], b[self.nonce_length:]
        return _enc_seg(nonce, self.nonce_encoding) + _enc_seg(body, self.body_encoding)


@register("strip_prefix")
class StripPrefix(Step):
    """Remove a fixed leading segment from a blob (forward) and restore it (backward).

    Some envelopes prepend a constant header before the ciphertext — a fixed IV,
    a version/key-wrapping tag, or a magic marker that is identical on every
    message. Strip it declaratively instead of writing a Python hook.

    Two modes:

      # constant value known ahead of time (fully stateless, reversible from
      # scratch — the recommended form):
      - strip_prefix: { value: "0a1b2c...", encoding: hex }

      # fixed length, value captured per-flow on decrypt and replayed on encrypt
      # (needs a prior decrypt in the same flow, like the header envelope):
      - strip_prefix: { length: 8 }

    forward:  <prefix><body>  ->  <body>
    backward: <body>          ->  <prefix><body>
    """

    in_type = DataType.BYTES
    out_type = DataType.BYTES

    _SESSION_KEY = "_strip_prefix"

    def configure(self) -> None:
        self.value_tmpl = self.params.get("value")
        self.encoding = self.params.get("encoding", "hex")
        self.length = self.params.get("length")
        if self.value_tmpl is None and self.length is None:
            raise DecryptError(category="config_error",
                               message="strip_prefix: needs 'value' or 'length'")
        if self.encoding not in ("hex", "base64", "raw"):
            raise DecryptError(category="config_error",
                               message="strip_prefix: encoding must be hex/base64/raw")

    def _static_prefix(self, ctx: Context) -> bytes:
        val = Renderer(ctx.vars).render(self.value_tmpl)
        if isinstance(val, (bytes, bytearray)):
            return bytes(val)
        s = str(val)
        if self.encoding == "hex":
            return bytes.fromhex(s)
        if self.encoding == "base64":
            return base64.b64decode(s)
        return s.encode("latin-1")

    def forward(self, data, ctx: Context) -> bytes:
        data = _as_bytes(data)
        if self.value_tmpl is not None:
            pref = self._static_prefix(ctx)
            if not data.startswith(pref):
                raise DecryptError(category="config_error",
                                   message="strip_prefix: expected constant prefix not present",
                                   step=self.name, direction="forward")
            return data[len(pref):]
        n = int(self.length)
        if len(data) < n:
            raise DecryptError(category="config_error",
                               message="strip_prefix: blob shorter than prefix length",
                               step=self.name, direction="forward")
        ctx.session.setdefault(self._SESSION_KEY, {})[id(self)] = data[:n]
        return data[n:]

    def backward(self, data, ctx: Context) -> bytes:
        data = _as_bytes(data)
        if self.value_tmpl is not None:
            return self._static_prefix(ctx) + data
        saved = ctx.session.get(self._SESSION_KEY, {}).get(id(self))
        if saved is None:
            raise DecryptError(
                category="config_error",
                message="strip_prefix: no captured prefix to restore "
                        "(length mode needs a prior decrypt in this flow; use "
                        "'value' to encrypt from scratch)",
                step=self.name, direction="backward")
        return saved + data
