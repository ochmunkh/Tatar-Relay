# Target classes — what Tatar Relay must handle

*Authorized testing only. Vendor-neutral: this note describes shapes of
app-layer encryption seen in the wild, not any specific product or target.*

A profile is only as good as the class of envelope it fits. This note catalogs
the app-over-TLS encryption shapes we've validated against, so contributors can
tell at a glance whether a new target is already covered or needs new machinery.

## The four classes

### A. Field-wise AEAD envelope
One (or a few) JSON field(s) hold the ciphertext; the rest of the body is
plaintext structure. Each field is `<hex nonce> + base64(AES-GCM ct‖tag)` (or
similar). The session key is derived per login (e.g. ECDH → AES-GCM).

- **Envelope:** `json_field` on the encrypted field.
- **Transform:** `nonce_body` (or a hook) → `aes_decrypt(gcm)` → `as_json`.
- **Status:** ✅ fully supported (native `nonce_body` codec + `aes_decrypt`).

### B. Passphrase / KDF envelope
The whole body is one blob wrapped from a passphrase: `{ct, iv, s}` (salt) with
the key derived via a KDF (e.g. `EVP_BytesToKey` / PBKDF2 from passphrase+salt).

- **Envelope:** `raw` or `json_field`.
- **Transform:** Python hook (KDF derive) → `aes_decrypt(cbc)` → `as_json`.
- **Status:** ✅ fully supported — native `evp_aes_decrypt` step (EVP_BytesToKey/MD5 KDF, v0.6).

### C. Full symmetric envelope (body **and** headers)
The **entire request/response body** is a single symmetric blob, **and** many
custom headers are each independently encrypted base64 blobs (device metadata,
client id, an operation code, etc.). Responses often share a **constant leading
prefix** — a hint of a fixed IV/nonce or a key-wrapping/version header that must
be split off before decryption.

- **Envelope:** body via `raw`; **plus** each encrypted header — this is the gap
  (see below).
- **Transform:** `base64_decode` → `aes_decrypt` (mode TBD from the prefix
  analysis) → `as_json`.
- **Status:** ✅ **supported (v0.5).** The body path plus per-header sub-pipelines
  (`envelope.headers[]`) decrypt and re-encrypt together; the constant response
  prefix is handled by `strip_prefix`. This is the broadest class — it encrypts
  more surface than A. See `examples/full-envelope.yaml`.

### D. Opaque token / no app-layer crypto
Bearer/JWT tokens, RSA-wrapped one-shots, or plain TLS-only traffic. Nothing to
decrypt in-place — Tatar Relay adds little here and shouldn't pretend otherwise.

- **Status:** ➖ out of scope by design (this is the honest value boundary).

## Gap analysis for class C — resolved in v0.5

Two limits used to block full class-C support. Both lived in frozen-contract
areas (`Envelope`, `Context`); the fixes were **additive** (new fields and
strategies only) and shipped in v0.5:

**Gap 1 — header rebuild was a no-op → fixed.** `HttpMessage.set_header()` was
added, and `Envelope.rebuild(kind="header")` now writes the re-encrypted payload
back, so an edit to a decrypted header reseals.

**Gap 2 — one envelope per pipeline → fixed.** `envelope.headers[]` sub-pipelines
let a channel decrypt "the body **and** header X **and** header Y" in one pass,
each with its own transform. `ChannelPipeline._decrypt_headers` /
`_encrypt_headers` run them in place; the `_has_python` guard covers them too.

**Constant response prefix → `strip_prefix` codec.** A reversible codec that
removes a fixed prefix (a fixed IV or wrapping/version header) forward and
restores it backward — declarative instead of a hook.

All three are covered by `decrypt(encrypt(x)) == x` tests (`tests/test_class_c.py`,
10 tests, 75 total). None broke a frozen contract.

---

# Монгол — зорилтот ангиллууд

*Зөвхөн зөвшөөрөлтэй тест. Vendor-neutral: энэ нь бодит бүтээгдэхүүн/target биш,
харин app-layer шифрлэлтийн ерөнхий хэлбэрүүдийг тодорхойлно.*

Профайл нь тохирох envelope-ийн ангиллаасаа хамаарна. Доор бид баталгаажуулсан
дөрвөн ангиллыг жагсаав.

**A. Талбар түвшний AEAD envelope.** JSON талбар(ууд) л ciphertext агуулна;
`<hex nonce> + base64(AES-GCM ct‖tag)`. Session key login бүрт (ECDH→AES-GCM).
→ Envelope `json_field`, transform `nonce_body`→`aes_decrypt(gcm)`. **✅ бүрэн.**

**B. Passphrase/KDF envelope.** Бүтэн body нэг blob, passphrase-аас KDF-ээр key
гаргана: `{ct, iv, s}`. → Python hook (KDF)→`aes_decrypt(cbc)`. **✅ бүрэн дэмжсэн — native `evp_aes_decrypt` (v0.6).**

**C. Бүрэн симметрик envelope (body БА headers).**. Бүтэн body нэг
симметрик blob, мөн олон custom header тус бүр тусдаа шифрлэгдсэн base64 blob.
Response-ууд ихэвчлэн **тогтмол угтвартай** (fixed IV/nonce эсвэл wrapping header
байж болзошгүй — задлахын өмнө салгах хэрэгтэй). → body `raw`, нэмээд encrypted
header бүр. **✅ дэмжсэн (v0.5):** body + `envelope.headers[]` дэд-pipeline хамт
задарч дахин шифрлэгдэнэ, тогтмол угтварыг `strip_prefix` салгана. Хамгийн өргөн
ангилал. Жишээ: `examples/full-envelope.yaml`.

**D. Opaque token / app-layer крипто байхгүй.** Bearer/JWT, RSA-wrap, эсвэл цэвэр
TLS. Задлах юм алга — Tatar Relay энд бага үнэ цэнэтэй, дүр эсгэхгүй. **➖ scope-оос
гадуур (үнэн value boundary).**

**Зөрүү (v0.5-д шийдэгдсэн):** (1) `HttpMessage.set_header` нэмж, header envelope-ийн
rebuild нь re-encrypt утгыг буцааж бичдэг болсон (header засвар reseal хийгдэнэ);
(2) `envelope.headers[]` дэд-pipeline нь body + олон header-ыг нэг дор задалж/дахин
шифрлэнэ (`_has_python` guard header-ыг ч хамгаална); (3) `strip_prefix` codec
тогтмол угтвар салгаж/сэргээнэ. Гурвуулаа additive, `decrypt(encrypt(x))==x`
тестээр батлагдсан (`tests/test_class_c.py`, 10 тест, нийт 75). Frozen contract эвдээгүй.
