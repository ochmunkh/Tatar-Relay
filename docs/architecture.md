# Tatar Relay — Архитектур

## 1. Ерөнхий Тойм

Tatar Relay нь **vendor-independent application-layer protocol adapter** буюу хэрэглэгчийн давхаргын протоколын адаптер юм. Зорилго нь зөвшөөрөлтэй аюулгүй байдлын шалгалт хийхэд шифрлэгдсэн HTTP урсгалыг ил харагдахуйц болгох явдал.

```
┌──────────────────────────────────────────────────────────────┐
│                       Tatar Relay                            │
│                                                              │
│  HTTP Client ──► Proxy Listener ──► Pipeline Engine          │
│                                          │                   │
│                              ┌───────────┴───────────┐       │
│                              │  Envelope             │       │
│                              │  Transform steps      │       │
│                              │  Reseal               │       │
│                              └───────────────────────┘       │
│                                          │                   │
│                        Target Server ◄───┘                   │
└──────────────────────────────────────────────────────────────┘
```

---

## 2. Үндсэн Компонентүүд

### 2.1 Profile (`profile.py`)

Profile нь бүх тохиргооны эх сурвалж. YAML-аас ачаалагдаж, нэг удаа шалгагдана (build time validation). Ачааллах үед:

- **Scope шалгалт** (fail-closed): `scope.hosts` хоосон бол ачаалахгүй
- **Pipeline бүтэх**: transform step бүрийн `configure()` дуудагдана — тохиргооны алдаа энд гарна
- **Python hook хориг**: `security.allow_python_hooks: false` (анхдагч) бол Python step ачаалахгүй
- **Хувьсагч тодорхойлол**: `vars:` блок → `VarStore` суурийг бэлдэнэ

```
Profile.loads(yaml_text)
    ├── Scope шалгана
    ├── _guard_hooks() — Python hook хориг
    ├── ChannelPipeline("request") — бүтэх + шалгах
    └── ChannelPipeline("response") — байвал
```

### 2.2 Engine (`engine.py`)

Engine нь Profile-г хүлээн авч, encrypt/decrypt үйлдлүүдийг гүйцэтгэнэ.

**decrypt (forward direction)**:
```
wire_bytes
  → envelope.locate()       ← payload гаргаж авна, skeleton хадгална
  → transform[0].forward()  ← base64_decode
  → transform[1].forward()  ← hmac_verify
  → transform[2].forward()  ← aes_decrypt
  → transform[3].forward()  ← as_json
  → plaintext dict
```

**encrypt (backward direction)**:
```
plaintext dict
  → transform[3].backward() ← as_json.backward (no-op — dict pass-through)
  → transform[2].backward() ← aes_encrypt
  → transform[1].backward() ← hmac_verify.backward (pass-through)
  → transform[0].backward() ← base64_encode
  → envelope.rebuild()      ← skeleton-д буцааж суулгана
  → reseal.apply()          ← nonce/timestamp/sign/serialize
  → wire_bytes
```

### 2.3 Envelope (`envelope.py`)

Envelope нь wire bytes-аас **payload**-г салгаж авах, буцааж суулгах үүрэгтэй. Locate strategy-ууд дэс дарааллаар туршигдана, анхных тохирсон нь ялна.

| Strategy | Тайлбар |
|----------|---------|
| `raw` | Бүхэл body = payload |
| `json_field` | JSON объектын нэг талбар |
| `header` | HTTP header утга (rebuild дээр re-encrypt хийж буцааж бичнэ) |
| `regex` | Regex capture group 1 |

Тохирсон стратегийн **skeleton** (хүрээ) `ctx._scratch["envelope"]`-д хадгалагдана. `rebuild()` дуудагдахад skeleton ашиглан дахин угсардаг.

#### Encrypted header дэд-pipeline (бүрэн симметрик envelope)

Зарим target нь **body-г бүхэлд нь БА олон custom header-ыг тус тусад нь** шифрлэдэг ("full symmetric envelope" ангилал). Үүнд `envelope.headers[]` доор header тус бүрд жижиг transform дараалал (мини-pipeline) тодорхойлно:

```yaml
envelope:
  locate: [ { in: raw } ]
  headers:
    - name: "X-Meta"
      transform: [ base64_decode, aes_decrypt: {...}, as_text ]
    - name: "X-Op"
      transform: [ base64_decode, aes_decrypt: {...}, as_text ]
```

`ChannelPipeline.decrypt()` нь body-г задалсны дараа эдгээр header-ыг **байрд нь** decrypt хийж ил болгоно; `encrypt()` нь буцаад дахин шифрлэнэ (`_decrypt_headers` / `_encrypt_headers`). Тухайн header байхгүй бол алгасна. Header доторх `python` step-ийг мөн `allow_python_hooks` хамгаална.

### 2.4 Transform Steps (`steps/`)

Step бүр `Step` base class-аас удамшина. Хоёр чиглэл бий:

```python
class Step:
    in_type:  DataType   # оролтын төрөл — шалгагдана
    out_type: DataType   # гаралтын төрөл — шалгагдана

    def configure(self) -> None:
        """Build time шалгалт. Алдаа энд гарна, request үед биш."""

    def forward(self, data: Any, ctx: Context) -> Any:
        """Decrypt direction: wire → plaintext."""

    def backward(self, data: Any, ctx: Context) -> Any:
        """Encrypt direction: plaintext → wire."""
```

**Step бүртгэл:**

```python
@register("my_step")
class MyStep(Step):
    ...
```

`@register` decorator нь global `_STEP_REGISTRY` dict-д нэрээр бүртгэнэ. `build_step({"my_step": {...}})` дуудахад энэ registry-аас хайна.

**DataType шалгалт:**

```
DataType.BYTES  — байт урсгал
DataType.TEXT   — unicode string
DataType.JSON   — dict / list
DataType.ANY    — аль ч төрөл
```

Step-үүдийн хооронд төрлийн тохиромжгүй байдал `type_mismatch` алдаа үүсгэнэ.


### 2.4b KDF / Passphrase Steps (`steps/kdf.py`)

The `evp_aes_decrypt` step handles **EVP_BytesToKey passphrase-mode** bodies — the
format many web banking apps produce when encrypting with a passphrase + salt KDF.

**Body format:** `{ct: "<base64>", iv: "<hex>", s: "<hex 8B salt>"}`.
The `iv` field in the body is decorative — the KDF re-derives both key and IV
from the passphrase and salt.

**KDF:** `EVP_BytesToKey(passphrase, salt, MD5, 1 iter)` → 32-byte key + 16-byte IV.
The resulting cipher is AES-256-CBC + PKCS7, matching OpenSSL's default.

```yaml
- evp_aes_decrypt:
    passphrase: "${ecode}"   # template — raw string (use str: prefix in --var)
```

`forward`: JSON parse → salt extract → EVP_BytesToKey → AES-CBC decrypt → text/json.
`backward`: re-derive same key (passphrase+salt unchanged) → AES-CBC encrypt → JSON wrap.

The passphrase is supplied as a **`str:` typed var** to avoid hex-decoding:
```bash
relay bridge profile.yaml --var "ecode=str:<passphrase>"
```

### 2.5 Reseal (`reseal.py`)

Reseal нь зөвхөн **backward** (encrypt) чиглэлд ажилладаг. envelope.rebuild() дуусмагц дуудагдана.

Carrier төрөл:
- `json_field` envelope → carrier = **dict** (объект өөрчлөлт хийнэ)
- `raw` / `header` / `regex` envelope → carrier = **bytes** (шууд буцаана)

| Reseal step | Тайлбар |
|-------------|---------|
| `set` | Dict carrier-д талбар нэмнэ/дарна |
| `sign` | HMAC тооцоолж талбарт хийнэ |
| `serialize` | Dict → bytes (payload гаргах) |

`${payload}` ба `${payload_b64}` template-ийн утга нь reseal-ийн **payload** аргументаас (re-encrypted data) тооцогдоно.

### 2.6 Variables (`variables.py`)

**VarStore** — key-value дэлгүүр. `set(name, value)` болон `set_live(name, fn)` дэмжинэ. Live vars request ирэх бүр дахин тооцогдоно.

**Renderer** — `${...}` template-г задална:

```python
rnd = Renderer(ctx.vars, extras)
rnd.render("${session_key}")          # → bytes / str / ...
rnd.render_bytes("${payload}")        # → bytes заавал
```

`extras` dict нь VarStore-ийн дээр давхарлагдана — step дотор нэмэлт context утга дамжуулахад ашиглана.

### 2.7 Context (`context.py`)

```python
@dataclass
class Context:
    request:  HttpMessage
    response: HttpMessage
    vars:     VarStore
    channel:  str           # "request" | "response"
    _scratch: dict          # pipeline дотоод хадгалалт
```

`HttpMessage` нь host, path, headers, body талбартай. Header утга `msg.header("Name")` аргаар авна; `msg.set_header("Name", value)` нь header-ыг case-insensitive-ээр тавина (v0.5-д Contract #2-т additive-аар нэмэгдсэн — header envelope болон header дэд-pipeline энэ аргаар re-encrypt утгыг буцааж бичдэг).

---

## 3. Pipeline Гүйцэтгэлийн Дэс Дараалал

```
Engine.decrypt("request", wire_bytes, ctx)
│
├─ Profile.check_scope(host, path)          # fail-closed
│
├─ ChannelPipeline.decrypt(body, ctx)
│    │
│    ├─ envelope.locate(body, ctx)          # → payload
│    │
│    └─ for step in self.steps:
│          _run(step.forward, payload, ctx) # fail-safe wrapper
│          # → payload updated
│
└─ returns plaintext

Engine.encrypt("request", plaintext, ctx)
│
├─ ChannelPipeline.encrypt(plaintext, ctx)
│    │
│    ├─ for step in reversed(self.steps):
│    │     _run(step.backward, payload, ctx)
│    │
│    ├─ envelope.rebuild(payload, ctx)      # → carrier
│    │
│    └─ reseal.apply(carrier, payload, ctx) # → wire_bytes
│
└─ returns wire_bytes
```

`_run()` нь бүх `Exception`-г `DecryptError(category="internal")` болгон хувиргана — pipeline хэзээ ч нуранги унахгүй.

---

## 4. Алдааны Зохион Байгуулалт

```
RelayError (base)
├── DecryptError        — pipeline алдаа (category + step + direction + channel)
├── ScopeViolation      — зөвшөөрөгдөөгүй host/path
└── ProfileError        — profile ачаалах алдаа
```

Алдааны ангилал нь **Frozen Contract** — хувилбар нэмэх нь MINOR өөрчлөлт, нэр өөрчлөх нь BREAKING.

---

## 5. Extension Points (Сунгах цэгүүд)

### 5.1 Native Step нэмэх

`tatar_relay/steps/` доторх дурын файлд:

```python
from tatar_relay.steps.base import Step, register
from tatar_relay.datatypes import DataType

@register("my_algo")
class MyAlgo(Step):
    in_type  = DataType.BYTES
    out_type = DataType.BYTES

    def configure(self) -> None:
        self.param = self.params.get("param", "default")

    def forward(self, data, ctx):
        ...

    def backward(self, data, ctx):
        ...
```

`steps/__init__.py`-д import нэмнэ:

```python
from . import codecs, crypto, structural, pyhook, auth, my_module  # noqa
```

### 5.2 Python Hook (ажиллах цагт)

```yaml
security:
  allow_python_hooks: true

vars:
  my_var:
    from: hook
    file: hooks/my.py
    name: get_value
```

```python
def get_value(ctx) -> bytes:
    return ...
```

### 5.3 Extraction Variable

```yaml
vars:
  token:
    from: extraction
    source: response
    locate:
      - json_path: "$.token"
    transform:
      - base64_decode
```

`Profile.feed(message, source, vs)` дуудагдахад автоматаар утга татна.

---

## 6. Аюулгүй Байдлын Хамгаалалт

| Хамгаалалт | Яаж хэрэгжсэн |
|-----------|---------------|
| Fail-closed scope | `scope.hosts` хоосон бол ачаалахгүй |
| Python hook хориг | `allow_python_hooks: false` (анхдагч) |
| Constant-time compare | `hmac.compare_digest()` — timing attack хориг |
| Алдаа нууцалдаггүй | Бүх алдаа category + message-тэй |
| Template injection | Renderer зөвхөн VarStore ба extras-аас авна |
