"""ChaCha20-Poly1305 AEAD transform step. Reversible.

Layout on the wire: nonce (12 bytes) prepended to ciphertext||tag, matching the
convention used by ``aes_decrypt`` GCM with ``iv.source: prefix``.

    transform:
      - base64_decode
      - chacha20_decrypt: { key: "${session_key}" }   # nonce_length defaults to 12
      - as_json

ChaCha20-Poly1305 requires a 32-byte key.
"""
from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from ..context import Context
from ..datatypes import DataType
from ..errors import DecryptError
from ..variables import Renderer
from .base import Step, register


def _resolve_key(params, ctx) -> bytes:
    tmpl = params.get("key")
    if tmpl is None:
        raise DecryptError(category="config_error", message="chacha20: missing 'key'")
    val = Renderer(ctx.vars).render(tmpl)
    if isinstance(val, str):
        val = val.encode("utf-8")
    if not isinstance(val, (bytes, bytearray)):
        raise DecryptError(category="config_error", message="chacha20: key did not resolve to bytes")
    val = bytes(val)
    if len(val) != 32:
        raise DecryptError(category="wrong_key_size",
                           message=f"chacha20-poly1305: key must be 32 bytes, got {len(val)}")
    return val


@register("chacha20_decrypt")
class ChaCha20Decrypt(Step):
    in_type = DataType.BYTES
    out_type = DataType.BYTES

    def configure(self) -> None:
        self.nonce_len = int(self.params.get("nonce_length", 12))

    def forward(self, data, ctx: Context) -> bytes:
        key = _resolve_key(self.params, ctx)
        data = bytes(data)
        if len(data) < self.nonce_len:
            raise DecryptError(category="config_error",
                               message="chacha20: data too short for nonce",
                               step=self.name, direction="forward")
        nonce, ct = data[: self.nonce_len], data[self.nonce_len:]
        try:
            return ChaCha20Poly1305(key).decrypt(nonce, ct, None)
        except InvalidTag:
            raise DecryptError(category="tag_mismatch",
                               message="chacha20-poly1305: authentication tag mismatch (wrong key?)",
                               step=self.name, direction="forward")

    def backward(self, data, ctx: Context) -> bytes:
        key = _resolve_key(self.params, ctx)
        nonce = os.urandom(self.nonce_len)
        ct = ChaCha20Poly1305(key).encrypt(nonce, bytes(data), None)
        return nonce + ct
