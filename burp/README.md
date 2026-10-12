# Tatar Relay — Burp extension (v0.2)

<b><a href="#english">English</a> · <a href="#монгол">Монгол</a></b>

---

<a id="english"></a>

## English

A Burp Suite (Montoya API) frontend for Tatar Relay. It adds a **Tatar Relay**
tab to the request editor (Repeater, Proxy, etc.) that shows the **decrypted
plaintext** of an encrypted body, lets you edit it like normal HTTP, and
**re-encrypts + reseals** it on send.

The heavy lifting stays in the Python core; the extension is a thin client that
talks to the local bridge over JSON-RPC (Frozen Contract #5). This is why we do
not reimplement any crypto in Java.

```
Burp (Java)  ──HTTP JSON-RPC──►  relay bridge (Python)  ──►  pipeline engine
   Repeater tab                    localhost:8799              (decrypt/encrypt)
```

## 1. Start the bridge (Python side)

```bash
pip install -e .            # from the repo root
relay bridge examples/acme-bank-mobile.yaml --var session_key=<hex>
# serves http://127.0.0.1:8799
```

`--var` supplies the session key for now (live key extraction from the handshake
is v0.3). You can pass several profiles; the extension can name one, or if only
one is loaded it is used automatically.

## 2. Build the extension jar

Requires a JDK 17+ (`javac` + `jar`). Two ways below; [`BUILD.md`](BUILD.md) has
the full, copy-pasteable version — including the plain-`javac` route for
Linux/macOS, where `build.ps1` does not work, and how to verify the extension
loaded.

**No Gradle needed (recommended on Windows):**

```powershell
cd burp
powershell -ExecutionPolicy Bypass -File build.ps1
# downloads Montoya + Gson, compiles, bundles -> build\libs\tatar-relay-burp.jar
```

**Or with Gradle 8:**

```bash
cd burp
gradle build          # or: ./gradlew build
# -> build/libs/tatar-relay-burp.jar   (Gson bundled)
```

## 3. Load in Burp

Burp → **Extensions** → **Add** → Extension type **Java** →
select `build/libs/tatar-relay-burp.jar`.

Optional config (JVM args in Burp, or environment):

```
-Dtatar.bridge=http://127.0.0.1:8799
-Dtatar.profile=acme-bank-mobile
```

## 4. Use it

Send an in-scope encrypted request to **Repeater**, open the **Tatar Relay 🔓**
tab: you'll see plaintext JSON. Edit it, hit **Send** — the extension
re-encrypts and reseals automatically. If the bridge is down or the key is
wrong, the tab shows the reason and the original request is sent unchanged.

The **response** side has its own **Tatar Relay 🔓** tab: it decrypts the
response body through the profile's `response` pipeline, so you can read (and
edit) decrypted responses without leaving Burp. A profile with no `response`
pipeline just shows a reason in the tab.

## Notes / roadmap

- v0.2 shows a raw plaintext editor. Live Preview (per-step view) and a byte-diff
  panel are next.
- Response editor tab — **done** (decrypt/edit responses in Burp).
- Intruder support and in-Burp key extraction come later.
- The extension never sends a broken request: any bridge/pipeline error falls
  back to the original bytes and logs a reason.

---

<a id="монгол"></a>

## Монгол

Tatar Relay-ийн Burp Suite (Montoya API) frontend. Request editor (Repeater,
Proxy гэх мэт) дээр **Tatar Relay** таб нэмж, шифрлэгдсэн body-гийн **тайлсан
plaintext**-ийг харуулна. Түүнийг энгийн HTTP шиг засварлаж, илгээх үед нь
**дахин encrypt + reseal** хийнэ.

Хүнд ажил нь Python цөмд үлдэнэ; extension нь локал bridge-тэй JSON-RPC-ээр
(Frozen Contract #5) харилцдаг нимгэн client. Яг иймээс Java дээр ямар ч крипто
дахин бичээгүй.

```
Burp (Java)  ──HTTP JSON-RPC──►  relay bridge (Python)  ──►  pipeline engine
   Repeater таб                    localhost:8799              (decrypt/encrypt)
```

### 1. Bridge асаах (Python тал)

```bash
pip install -e .            # repo-гийн үндсээс
relay bridge examples/acme-bank-mobile.yaml --var session_key=<hex>
# http://127.0.0.1:8799 дээр үйлчилнэ
```

Одоогоор session key-г `--var`-аар өгнө (handshake-аас амьдаар салгаж авах нь
v0.3). Хэд хэдэн профайл дамжуулж болно; extension нэгийг нь нэрлэж болох ба
зөвхөн нэг профайл ачаалагдсан бол автоматаар түүнийг ашиглана.

### 2. Extension jar-ыг build хийх

JDK 17+ (`javac` + `jar`) шаардана. Доор хоёр арга байгаа ба
[`BUILD.md`](BUILD.md) дотор бүрэн, хуулж тавихад бэлэн хувилбар бий —
`build.ps1` ажиллахгүй Linux/macOS дээрх энгийн `javac` зам, мөн extension
ачаалагдсаныг хэрхэн шалгахыг оруулаад.

**Gradle хэрэггүй (Windows дээр санал болгоно):**

```powershell
cd burp
powershell -ExecutionPolicy Bypass -File build.ps1
# Montoya + Gson татаж, compile хийж, багцална -> build\libs\tatar-relay-burp.jar
```

**Эсвэл Gradle 8-аар:**

```bash
cd burp
gradle build          # эсвэл: ./gradlew build
# -> build/libs/tatar-relay-burp.jar   (Gson багтсан)
```

### 3. Burp-д ачаалах

Burp → **Extensions** → **Add** → Extension type **Java** →
`build/libs/tatar-relay-burp.jar`-ыг сонго.

Нэмэлт тохиргоо (Burp дотрох JVM arg, эсвэл орчны хувьсагч):

```
-Dtatar.bridge=http://127.0.0.1:8799
-Dtatar.profile=acme-bank-mobile
```

### 4. Ашиглах

Scope доторх шифрлэгдсэн request-ийг **Repeater** рүү илгээж, **Tatar Relay 🔓**
табыг нээ: plaintext JSON харагдана. Засаад **Send** дар — extension автоматаар
дахин encrypt + reseal хийнэ. Bridge унтарсан эсвэл key буруу бол таб нь
шалтгааныг харуулж, анхны request өөрчлөгдөлгүй илгээгдэнэ.

**Response** тал нь өөрийн **Tatar Relay 🔓** табтай: профайлын `response`
pipeline-аар response body-г тайлдаг тул Burp-ээс гаралгүй тайлсан response-ыг
уншиж (мөн засварлаж) болно. `response` pipeline-гүй профайл дээр таб нь зөвхөн
шалтгааныг харуулна.

### Тэмдэглэл / замын зураг

- v0.2 нь түүхий plaintext editor харуулна. Live Preview (алхам тус бүрийн
  харагдац) ба byte-diff самбар дараагийнх.
- Response editor таб — **хийгдсэн** (Burp дотор response-ыг тайлж/засварлах).
- Intruder дэмжлэг ба Burp дотроос key салгах нь дараа нь.
- Extension нь эвдэрсэн request хэзээ ч илгээхгүй: bridge/pipeline-ийн ямар ч
  алдаа гарвал анхны байт руу буцаж, шалтгааныг бичнэ.
