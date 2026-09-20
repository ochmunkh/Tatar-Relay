# Шинэ Алгоритм Нэмэх — Алхам Алхмаар Заавар

Tatar Relay нь хоёр аргаар сунгагдана: **native step** (бүртгэлийн систем) ба **Python hook** (ажиллах цагт). Native нь хурдан, тестлэхэд хялбар; hook нь аль ч Python код ажиллуулж чадна.

---

## Арга А: Native Transform Step

### A-1. Шинэ файл үүсгэх

`tatar_relay/steps/` дотор файл нэмнэ. Доорх ChaCha20 нь **зөвхөн заах жишээ** —
`chacha20_decrypt` нь одоо суурьт багтсан (`tatar_relay/steps/chacha.py`). Шинэ
алгоритм нэмэхдээ энэ загварыг дага:

```python
"""ChaCha20-Poly1305 AEAD transform step."""
from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from ..context import Context
from ..datatypes import DataType
from ..errors import DecryptError
from ..variables import Renderer
from .base import Step, register


@register("chacha20_decrypt")           # ← YAML-д ашиглах нэр
class ChaCha20Decrypt(Step):
    in_type  = DataType.BYTES
    out_type = DataType.BYTES

    def configure(self) -> None:
        """Build time шалгалт — алдаа энд гарах ёстой, request үед биш."""
        if "key" not in self.params:
            raise DecryptError(category="config_error",
                               message="chacha20_decrypt: 'key' is required")
        self.nonce_len = int(self.params.get("nonce_length", 12))

    def forward(self, data: Any, ctx: Context) -> bytes:
        """Decrypt direction: ciphertext → plaintext."""
        rnd = Renderer(ctx.vars)
        raw_key = rnd.render(self.params["key"])
        key = bytes.fromhex(raw_key) if isinstance(raw_key, str) else bytes(raw_key)

        if len(data) < self.nonce_len:
            raise DecryptError(category="config_error",
                               message="chacha20_decrypt: data too short for nonce")
        nonce, ct = data[:self.nonce_len], data[self.nonce_len:]
        try:
            return ChaCha20Poly1305(key).decrypt(nonce, ct, None)
        except Exception as exc:
            raise DecryptError(category="tag_mismatch",
                               message=f"chacha20: decryption failed: {exc}") from exc

    def backward(self, data: bytes, ctx: Context) -> bytes:
        """Encrypt direction: plaintext → ciphertext."""
        import os
        rnd = Renderer(ctx.vars)
        raw_key = rnd.render(self.params["key"])
        key = bytes.fromhex(raw_key) if isinstance(raw_key, str) else bytes(raw_key)
        nonce = os.urandom(self.nonce_len)
        ct = ChaCha20Poly1305(key).encrypt(nonce, data, None)
        return nonce + ct
```

### A-2. Import нэмэх

`tatar_relay/steps/__init__.py`:

```python
from . import codecs, crypto, structural, pyhook, auth, chacha  # noqa: F401
```

### A-3. Тест бичих

`tests/test_chacha.py`:

```python
import os
import pytest
from tatar_relay.context import Context
from tatar_relay.steps.base import build_step
from tatar_relay.variables import VarStore

KEY = os.urandom(32)   # ChaCha20 32-байт key шаарддаг

def ctx():
    c = Context()
    vs = VarStore()
    vs.set("session_key", KEY)
    c.vars = vs
    return c

def test_roundtrip():
    step = build_step({"chacha20_decrypt": {"key": "${session_key}"}})
    plaintext = b'{"amount":100}'
    ciphertext = step.backward(plaintext, ctx())
    assert step.forward(ciphertext, ctx()) == plaintext

def test_wrong_key():
    from tatar_relay.errors import DecryptError
    step = build_step({"chacha20_decrypt": {"key": "${session_key}"}})
    ciphertext = step.backward(b"hello", ctx())
    wrong_c = Context()
    vs = VarStore()
    vs.set("session_key", os.urandom(32))
    wrong_c.vars = vs
    with pytest.raises(DecryptError) as ei:
        step.forward(ciphertext, wrong_c)
    assert ei.value.category == "tag_mismatch"
```

### A-4. YAML profile-д ашиглах

```yaml
transform:
  - base64_decode
  - chacha20_decrypt:
      key: "${session_key}"
      nonce_length: 12
  - as_json
```

### A-5. Алдааны категори сонгох

| Нөхцөл | Категори |
|--------|---------|
| Буруу key / tag mismatch | `tag_mismatch` |
| Буруу key size | `wrong_key_size` |
| Тохиргоо буруу | `config_error` |
| PKCS7 padding буруу | `padding` |
| Гарын үсэг тохирохгүй | `signature_invalid` |

---

## Арга Б: Python Hook

Hook нь native step хийх шаардлагагүйгээр аль ч Python код ажиллуулна. Зөвхөн `allow_python_hooks: true` profile-д ашиглана.

### B-1. Hook файл бичих

`hooks/rsa_oaep.py`:

```python
"""RSA-OAEP + AES-256-GCM хосолсон шифрлэлт."""
from cryptography.hazmat.primitives.asymmetric import padding as asym_pad
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tatar_relay.context import Context
import os, json


def decrypt(data: bytes, ctx: Context, params: dict) -> dict:
    """forward: wire bytes → plaintext dict"""
    import base64
    body = json.loads(data)

    # Private key-г хувьсагчаас авна
    pem_bytes = ctx.vars.get("rsa_private_key")
    private_key = serialization.load_pem_private_key(pem_bytes, password=None)

    # RSA-OAEP-р wrapped AES key тайлах
    enc_aes_key = base64.b64decode(body["key"])
    aes_key = private_key.decrypt(
        enc_aes_key,
        asym_pad.OAEP(mgf=asym_pad.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # AES-GCM-р өгөгдөл тайлах
    payload = base64.b64decode(body["data"])
    nonce, ct = payload[:12], payload[12:]
    plaintext = AESGCM(aes_key).decrypt(nonce, ct, None)
    return json.loads(plaintext)


def encrypt(data: dict, ctx: Context, params: dict) -> bytes:
    """backward: plaintext dict → wire bytes"""
    import base64
    plaintext = json.dumps(data).encode()

    # Public key-г хувьсагчаас авна
    pem_bytes = ctx.vars.get("rsa_public_key")
    public_key = serialization.load_pem_public_key(pem_bytes)

    # Random AES key үүсгэж RSA-OAEP-р wrap хийх
    aes_key = os.urandom(32)
    enc_aes_key = public_key.encrypt(
        aes_key,
        asym_pad.OAEP(mgf=asym_pad.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # AES-GCM-р шифрлэх
    nonce = os.urandom(12)
    ct = AESGCM(aes_key).encrypt(nonce, plaintext, None)

    return json.dumps({
        "key":  base64.b64encode(enc_aes_key).decode(),
        "data": base64.b64encode(nonce + ct).decode(),
    }).encode()
```

### B-2. Profile тохиргоо

```yaml
name: rsa-hybrid
security:
  allow_python_hooks: true        # заавал

scope:
  hosts: ["secure\\.api\\.example\\.com"]

request:
  envelope:
    locate:
      - in: raw
  transform:
    - python:
        file: hooks/rsa_oaep.py
        forward: decrypt
        backward: encrypt
  reseal:
    - serialize:
        mode: compact
```

### B-3. Key-г VarStore-т тавих

```python
from tatar_relay.variables import VarStore

vs = VarStore()
with open("private.pem", "rb") as f:
    vs.set("rsa_private_key", f.read())
with open("public.pem", "rb") as f:
    vs.set("rsa_public_key", f.read())
ctx.vars = vs
```

---

## Арга В: Reseal Step нэмэх

Reseal нь `reseal.py`-д нэмэгддэг (зөвхөн backward):

```python
# reseal.py — apply() аргын elif-ийн дотор

elif name == "timestamp":
    _require_dict(carrier, "timestamp")
    carrier[params.get("field", "ts")] = int(time.time() * 1000)
```

YAML:
```yaml
reseal:
  - timestamp:
      field: created_at
```

---

## Нийтлэг Алдааны Загвар

```python
# Тохиргооны алдаа — build time-д илрэх ёстой
raise DecryptError(category="config_error",
                   message="my_step: 'key' parameter is required")

# Гүйцэтгэлийн алдаа — forward/backward-д
raise DecryptError(category="tag_mismatch",
                   message="my_step: authentication failed",
                   step=self.name,
                   direction="forward")
```

Алдааны категори нь `CATEGORIES` tuple-д бүртгэгдсэн байх ёстой (`errors.py`). Бүртгэгдээгүй категори ашиглавал `ValueError` гаргана.

---

## Шалгах Жагсаалт

- [ ] `@register("нэр")` — YAML-д ашиглах нэртэй таарч байна уу?
- [ ] `configure()` — бүх тохиргооны алдаа энд гарч байна уу?
- [ ] `forward()` — decrypt/decode зөв ажиллаж байна уу?
- [ ] `backward()` → `forward()` round-trip тест давсан уу?
- [ ] Буруу key/алдаатай данс → зөв category-тэй `DecryptError` гаргаж байна уу?
- [ ] `steps/__init__.py`-д import нэмсэн үү?
- [ ] YAML profile жишгийг `user-guide.md`-д нэмсэн үү?
