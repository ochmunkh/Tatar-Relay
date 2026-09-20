"""KDF-based cipher steps.

`evp_aes_decrypt` handles the passphrase/KDF envelope format:

    { "ct": base64(ciphertext), "iv": hex(iv), "s": hex(8-byte salt) }

A passphrase and an 8-byte random salt are used to derive the key (and iv) via
the passphrase + random salt with OpenSSL's EVP_BytesToKey (MD5, 1 iteration),
then AES-256-CBC + PKCS7. The provided ``iv`` field is decorative — the library
re-derives the iv from the KDF on decrypt, so this step does the same.

    transform:
      - evp_aes_decrypt: { passphrase: "${ecode}" }   # 32-byte key, EVP_BytesToKey/MD5
      - as_json

The passphrase is a template — supply it as a var at runtime (never hardcode a
secret in the profile). Authorized testing only.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from ..context import Context
from ..datatypes import DataType
from ..errors import DecryptError
from ..variables import Renderer
from .base import Step, register

_HASHES = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256}


def evp_bytes_to_key(passphrase: bytes, salt: bytes, key_len: int, iv_len: int, hasher):
    """EVP_BytesToKey — 1 iteration, MD5 hash. Derives key+IV from passphrase+salt."""
    data = b""
    prev = b""
    while len(data) < key_len + iv_len:
        prev = hasher(prev + passphrase + salt).digest()
        data += prev
    return data[:key_len], data[key_len:key_len + iv_len]


@register("evp_aes_decrypt")
class EvpAesDecrypt(Step):
    in_type = DataType.BYTES
    out_type = DataType.BYTES

    def configure(self) -> None:
        if self.params.get("passphrase") is None:
            raise DecryptError(category="config_error",
                               message="evp_aes_decrypt: 'passphrase' is required")
        self.passphrase_tmpl = self.params["passphrase"]
        self.key_size = int(self.params.get("key_size", 32))
        self.iv_size = int(self.params.get("iv_size", 16))
        h = str(self.params.get("hash", "md5")).lower()
        if h not in _HASHES:
            raise DecryptError(category="config_error",
                               message=f"evp_aes_decrypt: hash must be one of {tuple(_HASHES)}")
        self.hasher = _HASHES[h]
        self.f_ct = self.params.get("ct_field", "ct")
        self.f_iv = self.params.get("iv_field", "iv")
        self.f_s = self.params.get("salt_field", "s")

    def _passphrase(self, ctx: Context) -> bytes:
        v = Renderer(ctx.vars).render(self.passphrase_tmpl)
        return v if isinstance(v, (bytes, bytearray)) else str(v).encode("utf-8")

    def forward(self, data, ctx: Context) -> bytes:
        raw = data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else str(data)
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as e:
            raise DecryptError(category="type_mismatch",
                               message=f"evp_aes_decrypt: body is not JSON: {e}",
                               step=self.name, direction="forward")
        try:
            ct = base64.b64decode(obj[self.f_ct])
            salt = bytes.fromhex(obj[self.f_s])
        except (KeyError, ValueError) as e:
            raise DecryptError(category="config_error",
                               message=f"evp_aes_decrypt: bad ct/salt fields: {e}",
                               step=self.name, direction="forward")
        key, iv = evp_bytes_to_key(self._passphrase(ctx), salt, self.key_size, self.iv_size, self.hasher)
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpadder = PKCS7(128).unpadder()
        try:
            return unpadder.update(padded) + unpadder.finalize()
        except ValueError:
            raise DecryptError(category="padding",
                               message="evp_aes_decrypt: invalid PKCS7 padding (wrong passphrase?)",
                               step=self.name, direction="forward")

    def backward(self, data, ctx: Context) -> str:
        pt = data if isinstance(data, (bytes, bytearray)) else str(data).encode("utf-8")
        salt = os.urandom(8)
        key, iv = evp_bytes_to_key(self._passphrase(ctx), salt, self.key_size, self.iv_size, self.hasher)
        padder = PKCS7(128).padder()
        padded = padder.update(bytes(pt)) + padder.finalize()
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        ct = enc.update(padded) + enc.finalize()
        obj = {self.f_ct: base64.b64encode(ct).decode("ascii"),
               self.f_iv: iv.hex(),
               self.f_s: salt.hex()}
        return json.dumps(obj, separators=(",", ":"))
