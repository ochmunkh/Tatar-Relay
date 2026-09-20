# Changelog

Бүх тэмдэглэлтэй өөрчлөлтүүд энд бүртгэгдэнэ.
Формат: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Хувилбар: [Semantic Versioning](https://semver.org/)

---

## [0.6.0] — Native EVP_BytesToKey passphrase mode + bridge typed vars

### Нэмэгдсэн зүйлс
- **`evp_aes_decrypt`** native transform step (`tatar_relay/steps/kdf.py`):
  EVP_BytesToKey passphrase-mode (`{ct, iv, s}`) body-г hook-гүйгээр задалдаг.
  KDF: `EVP_BytesToKey(passphrase, salt, MD5, 1 iter)` → 32B key + 16B IV →
  AES-256-CBC + PKCS7. Passphrase-ийг `str:` typed var-аар дамжуулна.
  OpenSSL-ийн pinned test vector-оор баталгаажсан.
- **Bridge typed var coercion** (`str:` / `b64:` / `hex:` / bare = hex):
  passphrase (string) болон session key (hex) хоёрыг нэг bridge дотор хэрэглэх
  боломжтой болсон. Өмнөх хувилбарт бүх var-г hex гэж таасан нь passphrase-ийн
  `bytes.fromhex()` алдаа үүсгэдэг байсан.
- **`examples/evp-aes-passphrase.yaml`** — algorithm-only Class B demo profile.
- **Windows console Unicode fix** — `relay validate` дэх `✓✗→⚠` тэмдэгтүүд
  cp1252 консолд UnicodeEncodeError үүсгэж байсан; ASCII equivalent-аар сольсон.

### Тест
- 6 шинэ тест (`tests/test_evp_aes.py`): OpenSSL vector, round-trip, wrong passphrase.
- 2 шинэ тест (`tests/test_bridge_vars.py`): str: prefix, bare=hex regression.
- Нийт: **83 тест**, бүгд давна.

---

## [0.5.0] — Full symmetric envelope (body + encrypted headers)

### Нэмэгдсэн зүйлс
- **Encrypted-header дэд-pipeline** — `envelope.headers[]` доор header тус бүрд
  мини transform дараалал өгч, **body БА тусад нь шифрлэгдсэн олон header**-ыг хамт
  задалж/засаж/дахин шифрлэдэг боллоо ("full symmetric envelope" ангилал).
  `ChannelPipeline._decrypt_headers` / `_encrypt_headers` (`engine.py`). Header
  доторх `python` step-ийг `_has_python` guard мөн хамгаална.
- **Header envelope re-encrypt write-back** — `HttpMessage.set_header()` (Contract #2-т
  additive) нэмж, `header` envelope-ийн `rebuild()` нь re-encrypt хийсэн утгыг header
  руу буцааж бичдэг болсон. Өмнө нь header засвар чимээгүй алдагддаг байсан.
- **`strip_prefix`** codec — тогтмол угтвар (fixed IV / wrapping tag) салгаж/сэргээж
  урвуутай. `value` (stateless) эсвэл `length` (flow-д барих) горим. `tatar_relay/steps/codecs.py`.
- **`examples/full-envelope.yaml`** — алгоритм-only demo (body + 2 encrypted header + strip_prefix).
- 10 шинэ тест (нийт 75 pass): `tests/test_class_c.py`.

---

## [0.4.0] — Crypto detection & profile drafting

### Нэмэгдсэн зүйлс
- **Crypto observer** — JS hook нь одоо key-ийн зэрэгцээ крипто дуудалт бүрийн
  **fingerprint** (algorithm, mode, IV/nonce урт, key урт, tag урт)-ыг `/observe`
  руу илгээнэ. WebCrypto `encrypt`/`decrypt` + passphrase-mode `encrypt`/`decrypt` ажиглана.
  Bridge нь `Detected: AES-GCM · 12B nonce …` гэж хэвлэж, схем солигдвол
  **`⚠ NEW SCHEME`** гэж сэрэмжлүүлж, `observations.jsonl`-д бичнэ.
  (`capture.py: ObservationLog`, `/observe`, `/schemes`.)
- **Smart `relay inspect`** — урт mod 16, AEAD/nonce-prefix, ECB давталт, base64
  variant, JSON талбарын нэрсийн дохиог шинжилж **draft profile YAML** гаргана
  (`--emit-profile`). `observations.jsonl` байвал нэгтгэж cipher/nonce-уртыг бодит
  утгаар дүүргэнэ (`--observations`). "Магадлал, батламж биш" зарчим хэвээр.
- 8 шинэ тест (нийт 65 pass).

---

## [0.3.0] — Native ciphers өргөтгөл

### Нэмэгдсэн зүйлс
- **`chacha20_decrypt`** — ChaCha20-Poly1305 AEAD native transform step (32-байт key,
  nonce prefix, `tag_mismatch`/`wrong_key_size` алдаа). `tatar_relay/steps/chacha.py`.
- **`nonce_body`** codec — `<enc nonce><enc body>` хэлбэрийн талбарыг задалж raw
  `nonce||body` болгоно (nonce_encoding hex/base64/raw, body_encoding base64/hex/raw).
  Ингэснээр hex-nonce + base64 GCM/ChaCha талбарыг **Python hook-гүйгээр** declarative-аар
  задлах боломжтой боллоо. `tatar_relay/steps/codecs.py`.
- 7 шинэ тест (нийт 57 pass).

---

## [0.2.1] — Burp response editor tab

### Нэмэгдсэн зүйлс
- **Burp response editor tab** — Burp дотор response body-г profile-ийн `response`
  pipeline-аар задалж, plaintext-ээр харах/засах боломжтой боллоо. Request/response
  хоёулаа Burp дотроос гаралгүй задарна. (`RelayHttpResponseEditor` +
  `RelayResponseEditorProvider`; extension хоёр editor provider бүртгэнэ.)
  `response` pipeline-гүй profile нь tab дотор шалтгаанаа харуулна (fail-safe).
- Rebuilt `tatar-relay-burp.jar` (Java 17 bytecode, gson bundled).

---

## [0.1.1] — Correctness fixes

### Засагдсан зүйлс
- **`reseal.sign`** одоо `hmac_sha512` ба `hmac_sha1`-г бодитоор дэмжинэ
  (өмнө нь код зөвхөн `hmac_sha256` зөвшөөрч, документтэй зөрчилдөж байсан).
- **`serialize: preserve`** одоо `compact`-аас ялгаатай — стандарт зайтай JSON
  (`", "` / `": "`) гаргана. Өмнө нь хоёул compact гаргадаг байв. Spaced JSON
  илгээдэг server-ийн байтад илүү тохирно.

### Нэмэгдсэн зүйлс
- **Bridge shared-secret auth** (заавал биш): `relay bridge --token <secret>`
  эсвэл `TATAR_RELAY_TOKEN`. Идэвхжсэн үед `X-Relay-Token` header шаардана
  (constant-time), эс тэгвээс `401`. Анхдагчаар auth байхгүй — backward-compatible.
  Burp Java client `-Dtatar.relay.token` / `TATAR_RELAY_TOKEN` уншина.

---

## [0.1.0] — 2024 оны эхний хувилбар

### Нэмэгдсэн зүйлс

#### Үндсэн архитектур
- **Envelope / Transform / Reseal** pipeline загвар
- **ChannelPipeline**: decrypt (forward) болон encrypt (backward) чиглэл
- **Fail-closed scope**: `scope.hosts` хоосон бол profile ачаалахгүй
- **DataType шалгалт**: step хоорондын төрлийн зохицол compile time-д шалгагдана
- **Алдааны taxonomy** (Frozen Contract #4): `category + step + direction + channel`

#### Transform Steps
- `aes_decrypt` — AES-CBC ба AES-GCM (bidirectional, PKCS7/AEAD)
- `base64_decode` — Base64 decode/encode (bidirectional)
- `hex_decode` — Hex decode/encode (bidirectional)
- `gunzip` — Gzip decompress/compress (bidirectional)
- `as_json` — JSON bytes ↔ dict (bidirectional)
- `as_text` — bytes ↔ str (bidirectional)
- **`hmac_verify`** — HMAC шалгалт (forward), pass-through (backward)
  - Алгоритм: SHA-256 (анхдагч), SHA-512, SHA-1
  - Encoding: hex (анхдагч), base64
  - Source: `field=` (payload дотроос) эсвэл `expected=` (хувьсагчаас)
  - `strip_field=true`: MAC canonical sorted JSON-оос тооцогдоно

#### Reseal Steps
- `set` — dict carrier-д талбар нэмэх/дарах
- `sign` — HMAC-SHA256/SHA512 гарын үсэг (hmac_sha256, hmac_sha512)
- `serialize` — JSON dict → bytes (preserve / canonical / compact)

#### Envelope Strategies
- `raw` — бүхэл body = payload
- `json_field` — JSON объектын нэг талбар
- `header` — HTTP header утга
- `regex` — regex capture group 1

#### Variables & Templates
- `VarStore` — typed key-value store (bytes, str, bool, live vars)
- `Renderer` — `${...}` template engine
- Built-in functions: `${timestamp_ms()}`, `${random_hex(N)}`
- Built-in extras: `${payload}`, `${payload_b64}`, `${header.Name}`

#### Profile
- YAML дэмжих (`Profile.load()`, `Profile.loads()`)
- Extraction vars: JSONPath, header, regex — `Profile.feed()` автоматаар татна
- Python hook: `allow_python_hooks: true` зөвшөөрлийн хяналт
- Build-time шалгалт: configure() бүгд profile ачаалах үед дуудагдана

#### Python Hook (дэвшилтэт)
- `pyhook` step: `forward` / `backward` Python функц
- ECDH P-256 + AES-128-GCM жишиг hook
- `allow_python_hooks: false` (анхдагч аюулгүй тохиргоо)

#### Тест хамрах хүрээ
- 64 тест — бүгд давна
- `test_hmac_verify.py` — 16 тест (hex/base64/sha512, field/expected/strip_field, config errors, backward pass-through, engine integration)
- `test_engine.py`, `test_crypto.py`, `test_codecs.py`, `test_profile.py`, `test_variables.py`

#### Документаци
- `docs/user-guide.md` — quickstart, workflow, бүрэн YAML reference
- `docs/architecture.md` — pipeline загвар, component diagram, extension points
- `docs/algorithms.md` — бүх step болон алгоритмын reference
- `docs/how-to-add-algorithm.md` — native step, Python hook, reseal step нэмэх заавар

---

### Алдааны ангилал (errors.py)

| Категори | Тайлбар |
|----------|---------|
| `padding` | AES-CBC PKCS7 unpad алдаа |
| `tag_mismatch` | AES-GCM auth tag буруу |
| `wrong_key_size` | Key урт буруу |
| `signature_invalid` | HMAC тохирохгүй |
| `type_mismatch` | Step хооронд төрөл тохирохгүй |
| `locate_failed` | Envelope locate strategy тохирсонгүй |
| `extraction_failed` | Хувьсагч татаж чадаагүй |
| `scope_violation` | Зөвшөөрөгдөөгүй host/path |
| `profile_invalid` | Profile ачаалах алдаа |
| `hook_error` | Python hook алдаа |
| `config_error` | Step тохиргоо буруу |
| `internal` | Ангилагдаагүй алдаа |

---

### Мэдэгдэж буй хязгаарлалтууд

- Multipart/form-data envelope дэмжигдэхгүй (v0.2 зорилт)
- WebSocket урсгал дэмжигдэхгүй
- JWE / JWT native step байхгүй (Python hook-оор хийж болно)
- RSA native step байхгүй (Python hook-оор хийж болно)

---

[0.1.0]: https://github.com/ochmunkh/Tatar-Relay/releases/tag/v0.1.0
