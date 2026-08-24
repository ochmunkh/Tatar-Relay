"""Symmetric cipher steps: AES-CBC and AES-GCM. Reversible."""
from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.padding import PKCS7

from ..context import Context
from ..datatypes import DataType
from ..errors import DecryptError
from ..variables import Renderer
from .base import Step, register

_VALID_KEY_SIZES = (16, 24, 32)


def _resolve_key(params, ctx) -> bytes:
    tmpl = params.get("key")
    if tmpl is None:
        raise DecryptError(category="config_error", message="aes: missing 'key'")
    val = Renderer(ctx.vars).render(tmpl)
    if isinstance(val, str):
        val = val.encode("utf-8")
    if not isinstance(val, (bytes, bytearray)):
        raise DecryptError(category="config_error", message="aes: key did not resolve to bytes")
    val = bytes(val)
    if len(val) not in _VALID_KEY_SIZES:
        raise DecryptError(category="wrong_key_size",
                           message=f"aes: key must be 16/24/32 bytes, got {len(val)}")
    return val


@register("aes_decrypt")
class AesDecrypt(Step):
    in_type = DataType.BYTES
    out_type = DataType.BYTES

    def configure(self) -> None:
        self.mode = self.params.get("mode", "cbc").lower()
        if self.mode not in ("cbc", "gcm"):
            raise DecryptError(category="config_error", message=f"aes: bad mode {self.mode}")
        iv = self.params.get("iv", {})
        self.iv_source = (iv or {}).get("source", "prefix")
        self.iv_len = int((iv or {}).get("length", 16 if self.mode == "cbc" else 12))
        self.tag_len = int(self.params.get("tag_length", 16))

    # ---- CBC ----
    def _iv_from(self, ctx: Context) -> bytes:
        """IV supplied by a template value (source: value)."""
        val = Renderer(ctx.vars).render(self.params["iv"]["value"])
        return val if isinstance(val, (bytes, bytearray)) else bytes.fromhex(str(val))

    def _cbc_forward(self, data: bytes, key: bytes, ctx: Context) -> bytes:
        if self.iv_source == "prefix":
            iv, ct = data[: self.iv_len], data[self.iv_len:]
        elif self.iv_source == "value":
            iv, ct = self._iv_from(ctx), data
        else:
            raise DecryptError(category="config_error",
                               message=f"aes-cbc: unknown iv source {self.iv_source}")
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpadder = PKCS7(128).unpadder()
        try:
            return unpadder.update(padded) + unpadder.finalize()
        except ValueError:
            raise DecryptError(category="padding",
                               message="aes-cbc: invalid PKCS7 padding (wrong key?)",
                               step=self.name, direction="forward")

    def _cbc_backward(self, data: bytes, key: bytes, ctx: Context) -> bytes:
        padder = PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        if self.iv_source == "value":
            iv = self._iv_from(ctx)
            prepend = False
        else:
            iv = os.urandom(self.iv_len)
            prepend = True
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        ct = enc.update(padded) + enc.finalize()
        return (iv + ct) if prepend else ct

    # ---- GCM ----
    def _gcm_forward(self, data: bytes, key: bytes) -> bytes:
        nonce, ct = data[: self.iv_len], data[self.iv_len:]
        try:
            return AESGCM(key).decrypt(nonce, ct, None)
        except InvalidTag:
            raise DecryptError(category="tag_mismatch",
                               message="aes-gcm: authentication tag mismatch (wrong key?)",
                               step=self.name, direction="forward")

    def _gcm_backward(self, data: bytes, key: bytes) -> bytes:
        nonce = os.urandom(self.iv_len)
        ct = AESGCM(key).encrypt(nonce, data, None)
        return nonce + ct

    def forward(self, data, ctx: Context) -> bytes:
        key = _resolve_key(self.params, ctx)
        data = bytes(data)
        return self._cbc_forward(data, key, ctx) if self.mode == "cbc" else self._gcm_forward(data, key)

    def backward(self, data, ctx: Context) -> bytes:
        key = _resolve_key(self.params, ctx)
        data = bytes(data)
        return self._cbc_backward(data, key, ctx) if self.mode == "cbc" else self._gcm_backward(data, key)
