# Tatar Relay — Дэмжигдсэн Алгоритм ба Step-үүд

## 1. Transform Steps

Transform step бүр **forward** (decrypt) болон **backward** (encrypt) чиглэлтэй. Зарим нь нэг чиглэлд pass-through байдаг.

---

### `aes_decrypt` — AES Симметрик Шифр

**Файл:** `tatar_relay/steps/crypto.py`

#### CBC (Cipher Block Chaining)

```yaml
- aes_decrypt:
    mode: cbc
    key: "${session_key}"       # 16 / 24 / 32 байт
    iv:
      source: prefix            # prefix | value
      length: 16                # байт (анхдагч: 16)
      # value: "${iv_var}"      # source=value үед
```

| Талбар | Тайлбар |
|--------|---------|
| `mode` | `cbc` (анхдагч) |
| `key` | template — 16/24/32 байт |
| `iv.source` | `prefix` — ciphertext-ийн эхнээс IV авна; `value` — template-ээс |
| `iv.length` | IV урт байт (CBC: 16) |

- **forward:** IV + ciphertext → AES-CBC decrypt → PKCS7 unpad → plaintext
- **backward:** plaintext → PKCS7 pad → AES-CBC encrypt → IV prepend → ciphertext
- **Алдаа:** `padding` (буруу key), `wrong_key_size`

#### GCM (Galois/Counter Mode)

```yaml
- aes_decrypt:
    mode: gcm
    key: "${session_key}"
    iv:
      source: prefix
      length: 12                # байт (анхдагч: 12)
    tag_length: 16              # байт (анхдагч: 16)
```

- **forward:** nonce + ciphertext+tag → AES-GCM decrypt → plaintext
- **backward:** plaintext → AES-GCM encrypt → nonce prepend → nonce + ciphertext+tag
- **Алдаа:** `tag_mismatch` (буруу key эсвэл өөрчлөгдсөн data)

#### Key шаардлага

| Key урт | AES хувилбар |
|---------|-------------|
| 16 байт | AES-128 |
| 24 байт | AES-192 |
| 32 байт | AES-256 |

---

### `chacha20_decrypt` — ChaCha20-Poly1305 AEAD

**Файл:** `tatar_relay/steps/chacha.py`

```yaml
- chacha20_decrypt:
    key: "${session_key}"     # ЗААВАЛ 32 байт
    nonce_length: 12          # байт (анхдагч: 12)
```

- **forward:** nonce(prefix) + ciphertext+tag → plaintext
- **backward:** plaintext → ChaCha20-Poly1305 encrypt → nonce prepend
- **Nonce:** GCM-тэй адил ciphertext-ийн урд prefix байрлана
- **Алдаа:** `tag_mismatch` (буруу key/өөрчлөгдсөн data), `wrong_key_size` (32 байт биш)

---

### `nonce_body` — Nonce+Body талбар задлах/угсрах

**Файл:** `tatar_relay/steps/codecs.py`

Олон апп нь per-message nonce-ыг ciphertext-ийн урд **тэмдэгт мөр** болгон залгадаг
(жишээ: hex nonce + base64 ciphertext+tag). Энэ step нь тэрийг задалж raw
`nonce || ciphertext` болгоно — дараа нь `aes_decrypt`/`chacha20_decrypt`-ийг
`iv.source: prefix`-тэй залгана. **Python hook хэрэггүй.**

```yaml
- nonce_body:
    nonce_encoding: hex       # hex | base64 | raw  (анхдагч: hex)
    nonce_length: 12          # nonce-ийн байт урт (анхдагч: 12)
    body_encoding: base64     # base64 | hex | raw  (анхдагч: base64)
- aes_decrypt: { mode: gcm, key: "${session_key}", iv: { source: prefix, length: 12 } }
```

- **forward:** `"<enc nonce><enc body>"` → `nonce_bytes || body_bytes`
- **backward:** `nonce_bytes || body_bytes` → `"<enc nonce><enc body>"`
- **Алдаа:** `config_error` (буруу encoding / богино талбар)

---

### `strip_prefix` — Тогтмол угтвар салгах/сэргээх

**Файл:** `tatar_relay/steps/codecs.py`

Зарим envelope нь ciphertext-ийн урд **тогтмол угтвар** (fixed IV, version/wrapping
tag, magic marker) залгадаг — энэ нь мессеж бүрт ижил байдаг. Python hook бичихгүйгээр
declarative-аар салгана.

```yaml
# 1) угтвар урьдчилан мэдэгдэж байвал (бүрэн stateless, хамгийн зөв хэлбэр):
- strip_prefix: { value: "0a1b2c...", encoding: hex }   # hex | base64 | raw

# 2) зөвхөн урт мэдэгдэж байвал (decrypt дээр барьж, encrypt дээр сэргээнэ):
- strip_prefix: { length: 8 }
```

- **forward:** `<prefix><body>` → `<body>`
- **backward:** `<body>` → `<prefix><body>`
- `value` горим stateless — scratch-ээс шифрлэж болно. `length` горим нь тухайн flow-д
  урьд decrypt хийсэн байхыг шаардана (угтварыг `ctx.session`-д хадгална).
- **Алдаа:** `config_error` (угтвар олдоогүй / value|length аль нь ч алга / богино blob)

---

### `hmac_verify` — HMAC Бүрэн Бүтэн Байдал Шалгалт

**Файл:** `tatar_relay/steps/auth.py`

```yaml
- hmac_verify:
    algo: sha256                # sha256 (анхдагч) | sha512 | sha1
    key: "${session_key}"
    input: "${payload}"         # шалгах өгөгдөл — template
    field: signature            # payload-аас MAC унших
    # expected: "${mac_var}"    # хувьсагчаас MAC авах (field= биш)
    encoding: hex               # hex (анхдагч) | base64
    strip_field: false          # MAC-аас field-г хасах эсэх
```

**Дүрэм:** `field` ба `expected` хоёроос яг нэгийг тодорхойлох ёстой.

| Талбар | Тайлбар |
|--------|---------|
| `algo` | Hash функц |
| `key` | HMAC key — template |
| `input` | MAC-г тооцоолох өгөгдөл — template |
| `field` | Payload JSON-оос MAC унших талбарын нэр |
| `expected` | MAC утгыг template/хувьсагчаас авна |
| `encoding` | MAC-г decode хийх формат |
| `strip_field` | `true` бол `field`-г payload-аас хасаад MAC тооцоолно (canonical sorted JSON) |

- **forward:** MAC тооцоолж `expected`/`field`-тай `hmac.compare_digest()` харьцуулна
- **backward:** pass-through (re-sign нь reseal-ийн ажил)
- **Алдаа:** `signature_invalid`, `config_error`

#### strip_field зарчим

```
payload = {"amount": 100, "sig": "aabbcc..."}
strip_field = true, field = "sig"

MAC input = json.dumps({"amount": 100}, sort_keys=True, separators=(",", ":"))
          = b'{"amount":100}'
```

Canonical формат: key эрэмбэлэгдсэн, хоосон зай байхгүй.

#### ${payload} template

`hmac_verify.forward()` дотор `${payload}` ба `${payload_b64}` нь step-ийн **оролт** байт дээр тооцогдоно. Reseal-ийн `sign` step дотор ч мөн адил — хоёр phase-д ижил convention ашигладаг.

---

### `base64_decode` — Base64 Decode

**Файл:** `tatar_relay/steps/codecs.py`

```yaml
- base64_decode
```

- **forward:** base64 string/bytes → raw bytes (padding автоматаар нэмэгдэнэ)
- **backward:** raw bytes → base64 bytes

---

### `hex_decode` — Hex Decode

**Файл:** `tatar_relay/steps/codecs.py`

```yaml
- hex_decode
```

- **forward:** hex string → raw bytes
- **backward:** raw bytes → hex bytes

---

### `gunzip` — Gzip Decompress

**Файл:** `tatar_relay/steps/codecs.py`

```yaml
- gunzip
```

- **forward:** gzip bytes → decompressed bytes
- **backward:** bytes → gzip bytes

---

### `as_json` — JSON Parse / Serialize

**Файл:** `tatar_relay/steps/structural.py`

```yaml
- as_json
```

- **forward:** bytes → dict / list
- **backward:** dict / list → bytes (compact JSON)

---

### `as_text` — Text Decode / Encode

**Файл:** `tatar_relay/steps/structural.py`

```yaml
- as_text
```

- **forward:** bytes → str (UTF-8)
- **backward:** str → bytes (UTF-8)

---

## 1a. Бүрэн envelope — Encrypted headers

Body-гоос гадна **тусад нь шифрлэгдсэн header-уудтай** target-д (full symmetric
envelope) `envelope.headers[]` доор header тус бүрд мини-transform дараалал өгнө.
Header тус бүр body-тэй ижил step-үүдийг ашиглаж, `as_text`-ээр ил текст болгож
дуусгах нь тохиромжтой:

```yaml
request:
  envelope:
    locate: [ { in: raw } ]
    headers:
      - name: "X-Meta"
        transform: [ base64_decode, aes_decrypt: { mode: gcm, key: "${session_key}", iv: { source: prefix, length: 12 } }, as_text ]
  transform: [ base64_decode, aes_decrypt: {...}, as_json ]
```

decrypt үед header ил болж, encrypt үед дахин шифрлэгдэнэ. Жишээ:
[`examples/full-envelope.yaml`](../examples/full-envelope.yaml).

---

## 2. Reseal Steps

Reseal нь зөвхөн **backward** (encrypt) чиглэлд ажилладаг.

---

### `set` — Талбар Тавих

```yaml
- set:
    field: nonce
    value: "${random_hex(8)}"
```

Dict carrier дээр нэг талбар нэмж/дарна. Template дэмжинэ.

---

### `sign` — HMAC Гарын Үсэг

```yaml
- sign:
    algo: hmac_sha256           # hmac_sha256 | hmac_sha512
    key: "${session_key}"
    input: "${payload_b64}"
    into: sig                   # хадгалах талбарын нэр
    encoding: hex               # hex | base64
```

| Algo | Hash |
|------|------|
| `hmac_sha256` | HMAC-SHA256 |
| `hmac_sha512` | HMAC-SHA512 |

Тооцоолсон MAC-г carrier dict-ийн `into` талбарт хийнэ.

---

### `serialize` — JSON Bytes болгох

```yaml
- serialize:
    mode: preserve              # preserve | canonical | compact
```

| Mode | Тайлбар |
|------|---------|
| `preserve` | Анхны key дараалал хадгална (dict insertion order) |
| `canonical` | Key эрэмбэлэгдсэн, хоосон зай байхгүй |
| `compact` | Хоосон зай байхгүй, insertion order |

---

## 3. Python Hook — ECDH + AES-GCM (Дэвшилтэт)

Profile-д `allow_python_hooks: true` тохируулбал custom Python hook ашиглана. Дээрх native step-ийн зэрэгцэж ажиллана.

```yaml
transform:
  - python:
      file: hooks/ecdh_gcm.py
      forward: decrypt_field
      backward: encrypt_field
      params:
        field: data
        key_var: session_key
```

Hook функц signature:

```python
def decrypt_field(data: bytes, ctx, params: dict) -> bytes:
    """forward direction."""
    ...

def encrypt_field(data: bytes, ctx, params: dict) -> bytes:
    """backward direction."""
    ...
```

### ECDH P-256 + AES-128-GCM жишиг

```python
from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json, base64, os

def decrypt_field(data: bytes, ctx, params: dict) -> dict:
    body = json.loads(data)
    # ... ECDH key agreement, HKDF, AESGCM decrypt ...
    return plaintext_dict
```

---

## 4. Encoding Reference

| Нэр | forward input | forward output |
|-----|---------------|----------------|
| `base64_decode` | base64 str/bytes | raw bytes |
| `hex_decode` | hex str | raw bytes |
| `gunzip` | gzip bytes | plaintext bytes |
| `strip_prefix` | `<prefix><body>` bytes | `<body>` bytes |
| `hmac_verify encoding=hex` | hex MAC string | compare |
| `hmac_verify encoding=base64` | base64 MAC string | compare |
| `sign encoding=hex` | computed HMAC | hex string |
| `sign encoding=base64` | computed HMAC | base64 string |

---

## 5. Алгоритм Нэмэх Хурдан Жагсаалт

| Алгоритм нэмэх | Хаана |
|---------------|-------|
| Шинэ transform step | `tatar_relay/steps/<файл>.py` + `__init__.py` import |
| Шинэ reseal step | `tatar_relay/reseal.py` — `apply()` аргын if-elif |
| Python hook алгоритм | `hooks/<нэр>.py` — зөвшөөрөлтэй profile-д |
| Шинэ envelope strategy | `tatar_relay/envelope.py` — `locate()` / `rebuild()` |

Дэлгэрэнгүй: [how-to-add-algorithm.md](how-to-add-algorithm.md)
