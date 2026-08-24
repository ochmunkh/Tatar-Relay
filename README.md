# Tatar Relay

**Application-Layer Protocol Adaptation Layer** — work with encrypted APIs as if
they were plain HTTP.

> Stop writing `decrypt.py → edit → encrypt.py` loops.

*[Монгол хувилбар доор байна ↓](#монгол)*

---

## English

Many apps add their own encryption layer *on top of* TLS: the request body you
see in Burp is an opaque blob (`base64(gzip(aes(json)))`, a custom envelope,
HMAC, …). To test it today you drop out of Burp, run a `decrypt.py`, hand-edit
the JSON, run an `encrypt.py`, and rebuild the envelope by hand — for every
target, every engineer, every time.

Tatar Relay collapses that into **one reusable profile**. The proxy decrypts the
body to plaintext JSON automatically, you edit it like a normal request, and it
re-encrypts and re-seals (HMAC, nonce, timestamp) on the way out.

> ⚠️ **Authorized testing only.** Do not use against systems you do not own or
> do not have explicit permission to test. Tatar Relay works with keys *you*
> legitimately hold for testing you are authorized to perform.

### Install

```bash
git clone https://github.com/ochmunkh/Tatar-Relay
cd Tatar-Relay
pip install -e .            # add [mitmproxy] for the proxy frontend, [dev] for tests
```

### Quickstart (no proxy needed)

```bash
relay inspect capture.bin                       # suggest a pipeline (with confidence)
relay validate profile.yaml --sample plain.json # validate + round-trip
relay preview profile.yaml -i wire.bin --var session_key=<hex>   # step-by-step decrypt
```

### Use it live

- **mitmproxy** (v0.1 reference frontend):
  ```bash
  TATAR_RELAY_PROFILE=examples/acme-bank-mobile.yaml \
  mitmdump -s tatar_relay/frontends/mitmproxy_addon.py
  ```
- **Burp Suite** (v0.2, primary target) — see [`burp/README.md`](burp/README.md).
  Start the bridge, load the jar, edit decrypted JSON in Repeater:
  ```bash
  relay bridge examples/acme-bank-mobile.yaml --var session_key=<hex>
  ```

### How it works — three phases

```
Wire body
  ①  Envelope   locate the payload, remember the rest        (structural)
  ②  Transform  base64 → gunzip → aes_decrypt  → plaintext    (pure, reversible)
        … you edit the plaintext JSON …
  ②  Transform  aes_encrypt → gzip → base64                   (runs in reverse)
  ①  Envelope   put the payload back
  ③  Reseal     set ts/nonce, recompute HMAC                  (integrity)
Wire body → server
```

- **Transform** steps are pure and reversible: `decrypt(encrypt(x)) == x` is the
  core invariant, enforced by the test suite.
- **Reseal** recomputes signatures. Re-serializing JSON can reorder keys and
  silently break an HMAC even with the right key, so serialize modes are
  explicit: `preserve` / `canonical` / `compact`.

See [`examples/acme-bank-mobile.yaml`](examples/acme-bank-mobile.yaml) for a full
profile and [`CONTRACTS.md`](CONTRACTS.md) for the five frozen contracts
(Profile schema, Context API, Step interface, Error taxonomy, Bridge JSON-RPC).

### Security & Python hooks

When declarative YAML isn't enough, drop to Python — a hook is a user-written
step with the same `(data, ctx)` signature. But a community profile that ships
Python is arbitrary code execution: untrusted profiles must be
**declarative-only** (the loader refuses hooks unless
`security.allow_python_hooks: true`), and you should run Python hooks only from
**local profiles you trust**. A real sandbox is a later roadmap item.

### Development

```bash
pip install -e .[dev]
pytest            # unit + round-trip + golden regression
```

### Roadmap

- **v0.1** — core engine, profile v1, CLI (`run`/`validate`/`init`/`inspect`/`preview`/`bridge`), mitmproxy addon, tests.
- **v0.2** — Burp extension via the bridge, Repeater integration, Live Preview, byte-diff.
- **v0.3** — RSA/ECDH key extraction, more ciphers, Frida hook helper, real hook sandbox.
- **v0.4** — Intruder, Protobuf, WebSocket, response reseal.

### License

MIT © 2026 Enkhbat.O — Security Analyst

---

## Монгол

Олон апп нь TLS **дээр нэмээд** өөрсдийн шифрлэлтийн давхарга үүсгэдэг: Burp дээр
харагдах request body нь ойлгомжгүй blob (`base64(gzip(aes(json)))`, custom
envelope, HMAC …) байдаг. Үүнийг тестлэхийн тулд өнөөдөр Burp-ээ орхиж,
`decrypt.py` ажиллуулж, JSON-оо гараар засаж, `encrypt.py` ажиллуулж, envelope-оо
гараар угсардаг — target бүрт, engineer бүрт, удаа болгонд.

Tatar Relay үүнийг **нэг дахин ашиглагдах профайл** болгож хураадаг. Proxy нь
body-г автоматаар plaintext JSON болгож тайлж, чи энгийн request шиг засаад,
илгээхэд буцаагаад re-encrypt + reseal (HMAC, nonce, timestamp) хийдэг.

> ⚠️ **Зөвхөн зөвшөөрөлтэй тест.** Өөрийн эзэмшдэггүй, эсвэл тест хийх тодорхой
> зөвшөөрөлгүй систем дээр бүү ашигла. Tatar Relay нь чиний хууль ёсоор
> эзэмшдэг түлхүүрээр, зөвшөөрөгдсөн тестэд зориулагдсан.

### Суулгах

```bash
git clone https://github.com/ochmunkh/Tatar-Relay
cd Tatar-Relay
pip install -e .            # proxy-д [mitmproxy], тестэд [dev] нэмнэ
```

### Хурдан эхлэл (proxy хэрэггүй)

```bash
relay inspect capture.bin                       # pipeline санал (магадлалтай)
relay validate profile.yaml --sample plain.json # шалгах + round-trip
relay preview profile.yaml -i wire.bin --var session_key=<hex>   # алхам алхмаар тайлах
```

### Амьдаар нь ашиглах

- **mitmproxy** (v0.1 reference frontend):
  ```bash
  TATAR_RELAY_PROFILE=examples/acme-bank-mobile.yaml \
  mitmdump -s tatar_relay/frontends/mitmproxy_addon.py
  ```
- **Burp Suite** (v0.2, үндсэн зорилт) — [`burp/README.md`](burp/README.md)-г үз.
  Bridge-ээ асааж, jar-аа ачаалж, Repeater дээр тайлсан JSON-оо зас:
  ```bash
  relay bridge examples/acme-bank-mobile.yaml --var session_key=<hex>
  ```

### Хэрхэн ажилладаг — гурван фаз

```
Wire body
  ①  Envelope   payload-ыг олж, үлдсэнийг нь санана          (бүтцийн)
  ②  Transform  base64 → gunzip → aes_decrypt → plaintext     (цэвэр, урвуутай)
        … plaintext JSON-оо засна …
  ②  Transform  aes_encrypt → gzip → base64                   (урвуугаар)
  ①  Envelope   payload-ыг буцааж тавина
  ③  Reseal     ts/nonce тавьж, HMAC дахин бодно              (integrity)
Wire body → server
```

- **Transform** алхмууд цэвэр, урвуутай: `decrypt(encrypt(x)) == x` нь цөм
  инвариант бөгөөд тестээр батлагдсан.
- **Reseal** нь гарын үсгийг дахин бодно. JSON-ыг дахин serialize хийхэд key-ийн
  дараалал өөрчлөгдөж, зөв түлхүүртэй байсан ч HMAC эвдэрдэг — тиймээс serialize
  горим тодорхой: `preserve` / `canonical` / `compact`.

Бүрэн профайлын жишээг [`examples/acme-bank-mobile.yaml`](examples/acme-bank-mobile.yaml),
хөлдөөсөн 5 контрактыг [`CONTRACTS.md`](CONTRACTS.md)-с үз.

### Аюулгүй байдал ба Python hook

Declarative YAML хүрэлцэхгүй үед Python руу шилжинэ — hook гэдэг нь ижил
`(data, ctx)` гарын үсэгтэй хэрэглэгчийн бичсэн Step. Гэвч Python агуулсан
community профайл нь дурын код ажиллуулах эрсдэлтэй: итгэмжлэгдээгүй профайл
заавал **declarative-only** байх ёстой (`security.allow_python_hooks: true`
байхгүй бол loader hook-ийг татгалзана), Python hook-ийг зөвхөн **итгэдэг local
профайлаас** ажиллуул. Жинхэнэ sandbox нь дараагийн roadmap.

### Хөгжүүлэлт

```bash
pip install -e .[dev]
pytest            # unit + round-trip + golden regression
```

### Лиценз

MIT © 2026 Enkhbat.O — Security Analyst
