# Tatar Relay — Хэрэглэгчийн Гарын Авлага

> **Зорилго:** Tatar Relay бол зөвшөөрөлтэй аюулгүй байдлын шалгалт хийхэд зориулсан application-layer протоколын адаптер юм. Шифрлэгдсэн, гарын үсэглэгдсэн HTTP урсгалыг шифрийг нь тайлж, нөгөө тал руу дамжуулж, дахин шифрлэн буцаана — бүгдийг нэг profile тохиргоогоор.

---

## 1. Хурдан Эхлэл (Quickstart)

### Суулгалт

```bash
pip install tatar-relay        # PyPI-ээс (ирэх хувилбар)
# Эсвэл эх кодоос
git clone https://github.com/ochmunkh/Tatar-Relay
cd tatar-relay
pip install -e ".[dev]"
```

### Анхны profile үүсгэх

`profiles/my-api.yaml` нэртэй файл үүсгэнэ:

```yaml
name: my-api
scope:
  hosts:
    - "api\\.example\\.com"  # зөвшөөрөгдсөн host (regex)

request:
  envelope:
    locate:
      - in: raw               # бүхэл body = payload
  transform:
    - aes_decrypt:
        mode: cbc
        key: "${session_key}"
        iv:
          source: prefix
          length: 16
    - as_json
  reseal:
    - serialize:
        mode: compact
```

### Profile шалгах

```bash
tatar-relay validate profiles/my-api.yaml
```

### Proxy ажиллуулах

```bash
tatar-relay run --profile profiles/my-api.yaml --port 8080
```

Burp Suite-д proxy `127.0.0.1:8080` руу чиглүүлнэ. Шифрлэгдсэн request ирэхэд Relay тайлж өгч, хариуг дахин шифрлэн буцаана.

---

## 2. Ажиллах Зарчим

```
Incoming wire bytes
      │
      ▼
┌─────────────┐
│  Envelope   │ locate — payload-г салгаж авна
│  (locate)   │ skeleton (хүрээ) context-д хадгалагдана
└─────┬───────┘
      │ payload bytes / str
      ▼
┌─────────────┐
│  Transform  │ forward direction — серийн дэс дараалал
│  steps      │ decrypt / decode / verify / parse
└─────┬───────┘
      │ plaintext dict / bytes
      ▼
 ← Burp Suite харна →
      │
      ▼ backward direction
┌─────────────┐
│  Transform  │ backward — урвуу дэс дараалал
│  steps      │ serialize / encode / encrypt
└─────┬───────┘
      │
      ▼
┌─────────────┐
│  Envelope   │ rebuild — skeleton-д payload-г буцааж суулгана
│  (rebuild)  │
└─────┬───────┘
      │
      ▼
┌─────────────┐
│   Reseal    │ backward only — timestamp/nonce нэмэх, HMAC гарын үсэглэх
└─────────────┘
      │
      ▼
Outgoing wire bytes
```

---

## 3. Profile YAML Бүрэн Жишиг

```yaml
# ── Заавал талбарууд ────────────────────────────────────────────────────────
name: my-profile          # нэр (log-д харагдана)

scope:
  hosts:                  # regex жагсаалт — ЗААВАЛ, хоосон бол ачаалахгүй
    - "api\\.example\\.com"
  paths:                  # заавал биш; байвал regex шүүлтүүр
    - "^/v2/payment"

# ── Хувьсагч тодорхойлол ───────────────────────────────────────────────────
vars:
  session_key:            # байт утга — VarStore-оор дамжуулна (ажиллах үед)
    # `from: hook` эсвэл `from: extraction` дэмжинэ

  incoming_sig:           # HTTP request-аас автоматаар татна
    from: extraction
    source: request       # request | response
    locate:
      - json_path: "$.sig"          # JSONPath
      - header: "X-Signature"       # HTTP header
      - regex: '"sig":"([^"]+)"'    # regex capture group 1
    transform:
      - hex_decode                  # заавал биш дамжуулга

# ── Аюулгүй байдал ─────────────────────────────────────────────────────────
security:
  allow_python_hooks: false   # Python hook дэмжихгүй (анхдагч)

# ── Request channel ────────────────────────────────────────────────────────
request:
  envelope:
    locate:
      - in: raw                     # бүхэл body = payload (анхдагч)
      - in: json_field              # JSON талбар
        field: data
      - in: header                  # HTTP header
        name: X-Encrypted-Body
      - in: regex                   # regex group 1
        pattern: 'payload=([A-Za-z0-9+/=]+)'

  transform:
    # Encoding
    - base64_decode                 # base64 → bytes
    - hex_decode                    # hex → bytes  (заавал биш)
    - gunzip                        # gzip decompress

    # Integrity verify (forward direction)
    - hmac_verify:
        algo: sha256                # sha256 (анхдагч) | sha512 | sha1
        key: "${session_key}"
        input: "${payload}"         # шалгах өгөгдөл — template
        field: signature            # payload-аас MAC унших (expected= бол биш)
        # expected: "${incoming_sig}"   # хувьсагчаас MAC авах
        encoding: hex               # hex (анхдагч) | base64
        strip_field: false          # MAC-аас signature талбарыг хасах

    # Decryption
    - aes_decrypt:
        mode: cbc                   # cbc | gcm
        key: "${session_key}"
        iv:
          source: prefix            # prefix | value
          length: 16
        # tag_length: 16            # GCM-д (анхдагч 16 байт)

    # Parsing
    - as_json                       # bytes → dict
    - as_text                       # bytes → str

  reseal:
    # Нэмэлт талбар тавих
    - set:
        field: timestamp
        value: "${timestamp_ms()}"
    - set:
        field: nonce
        value: "${random_hex(8)}"

    # HMAC гарын үсэглэх
    - sign:
        algo: hmac_sha256           # hmac_sha256 | hmac_sha512
        key: "${session_key}"
        input: "${payload_b64}"     # гарын үсэглэх өгөгдөл
        into: sig                   # хаана хадгалах талбар
        encoding: hex               # hex | base64

    # Сериалчлах
    - serialize:
        mode: preserve              # preserve | canonical | compact

# ── Response channel ───────────────────────────────────────────────────────
response:
  envelope:
    locate:
      - in: raw
  transform:
    - aes_decrypt:
        mode: gcm
        key: "${session_key}"
        iv:
          source: prefix
          length: 12
    - as_json
  reseal:
    - serialize:
        mode: compact
```

---

## 4. Хувьсагч Тогтолцоо

### Template синтакс

| Template | Тайлбар |
|----------|---------|
| `${session_key}` | VarStore-оос утга авна |
| `${payload}` | Одоогийн step-ийн оролт байт (latin-1) |
| `${payload_b64}` | Одоогийн step-ийн оролт base64 |
| `${timestamp_ms()}` | Одоогийн Unix millisecond |
| `${random_hex(N)}` | N байт санамсаргүй hex |
| `${header.X-Foo}` | HTTP header утга |

### VarStore API (Python)

```python
from tatar_relay.variables import VarStore

vs = VarStore()
vs.set("session_key", bytes.fromhex("00112233..."))   # bytes
vs.set("my_flag", True)
vs.set_live("token", lambda: fetch_token())           # lazy evaluation

ctx.vars = vs
```

---

## 5. Python Hook (Дэвшилтэт)

```yaml
security:
  allow_python_hooks: true   # итгэдэг profile дээр л зөвшөөрнө

vars:
  session_key:
    from: hook
    file: hooks/my_api.py
    name: get_session_key
```

```python
# hooks/my_api.py
from tatar_relay.context import Context

def get_session_key(ctx: Context) -> bytes:
    """ECDH handshake-аас гарсан session key авна."""
    return ctx.request.header("X-Session-Id").encode()
```

---

## 6. Нийтлэг Тохиолдлууд

### CBC + prefix IV + HMAC verify

```yaml
request:
  envelope:
    locate:
      - in: json_field
        field: data
  transform:
    - base64_decode
    - hmac_verify:
        key: "${session_key}"
        input: "${payload}"
        expected: "${incoming_sig}"
    - aes_decrypt:
        mode: cbc
        key: "${session_key}"
        iv:
          source: prefix
          length: 16
    - as_json
  reseal:
    - sign:
        algo: hmac_sha256
        key: "${session_key}"
        input: "${payload_b64}"
        into: sig
    - serialize:
        mode: preserve
```

### GCM режим

```yaml
transform:
  - aes_decrypt:
      mode: gcm
      key: "${session_key}"
      iv:
        source: prefix
        length: 12
```

### Signature body дотор (strip_field)

Server MAC-г `{"amount":100,"sig":"..."}` гэж бодвол:

```yaml
transform:
  - hmac_verify:
      key: "${session_key}"
      input: "${payload}"
      field: sig
      strip_field: true    # MAC = canonical({"amount":100}) — sig талбаргүй
```

---

## 7. Алдааны Ангилал

| Категори | Тайлбар |
|----------|---------|
| `signature_invalid` | HMAC тохирохгүй |
| `padding` | AES-CBC PKCS7 padding буруу |
| `tag_mismatch` | AES-GCM authentication tag буруу |
| `wrong_key_size` | Key урт буруу |
| `locate_failed` | Envelope locate strategy тохирсонгүй |
| `config_error` | Profile тохиргоо буруу |
| `internal` | Ангилагдаагүй алдаа |

---

## 8. CLI Тушаалууд

```bash
tatar-relay validate <profile.yaml>    # profile шалгана
tatar-relay run --profile <file> --port <N>
tatar-relay inspect --profile <file> --request <file>
```

> **Burp дотор ашиглах бүрэн урсгал** (bridge асаах, jar ачаалах, key барих,
> request/response задлах, алдаа шийдэх) — [`QUICKSTART-MN.md`](QUICKSTART-MN.md)-г үз.

## 9. Bridge Authentication (заавал биш)

Bridge нь `127.0.0.1`-д сонсдог ч анхдагчаар токен шалгадаггүй. Хэрэв нэг
машин дээр өөр процессууд ажилладаг бол shared-secret токен идэвхжүүлж болно:

```bash
relay bridge myprofile.yaml --token "$(openssl rand -hex 16)"
# эсвэл орчны хувьсагчаар:
export TATAR_RELAY_TOKEN=<secret>
relay bridge myprofile.yaml
```

Токен идэвхжсэн үед bridge нь `X-Relay-Token` header-гүй, эсвэл буруу токентой
хүсэлтийг `401` буцаана (харьцуулалт нь constant-time). Burp extension нь мөн
токеныг илгээхийн тулд Java-д `-Dtatar.relay.token=<secret>` эсвэл
`TATAR_RELAY_TOKEN` env-г уншина. Токен өгөхгүй бол урьдын адил auth байхгүй
(backward-compatible).

## 10. Шифр илрүүлэх — "энэ ямар encryption вэ?"

Алгоритм солигдоход хоёр давхаргаар танина.

### Crypto observer (бодит илрүүлэлт)

`relay bridge … --capture` үед JS hook нь крипто дуудалт бүрийн **fingerprint**-ыг
`/observe` руу илгээнэ. Bridge цонхонд:

```
[tatar-relay] ⚠ NEW SCHEME: AES-GCM · 12B nonce · 16B tag · 32B key
```

Схем солигдвол `⚠ NEW SCHEME` шууд гарна. Бүх ажиглалт `observations.jsonl`-д
бичигдэнэ. Одоо мэдэгдэж буй схемүүдийг `http://127.0.0.1:9091/schemes`-ээс харна.

### `relay inspect` (blob-оос draft profile)

Captured blob-ыг шинжилж (base64/hex, gzip, урт mod 16, AEAD/nonce-prefix, ECB,
JSON талбарын дохио) **draft profile YAML** гаргана. `observations.jsonl` байвал
нэгтгэж cipher/nonce-уртыг бодит утгаар дүүргэнэ:

```bash
relay inspect capture.bin --emit-profile draft.yaml --observations observations.jsonl
relay validate draft.yaml            # → шалгаад засаад ашиглана
```

Гаралт нь **магадлал, батламж биш** — хүн хараад баталгаажуулна.
