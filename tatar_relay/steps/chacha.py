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
from .base import Step, register, resolve_key


def _resolve_key(params, ctx) -> bytes:
    return resolve_key(params, ctx, sizes=(32,), label="chacha20",
                       size_label="chacha20-poly1305")


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
