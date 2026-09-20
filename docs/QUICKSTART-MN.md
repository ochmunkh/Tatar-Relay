# Tatar Relay — Хурдан эхлэх гарын авлага (Burp)

Энэ гарын авлага нь **Burp Suite дотроос гаралгүй** шифрлэгдсэн request/response-ыг
plaintext болгож харах ажлын урсгалыг алхам алхмаар тайлбарлана.

> ⚠️ Зөвхөн зөвшөөрөлтэй тест. Өөрийн эзэмшдэггүй, эсвэл тест хийх зөвшөөрөлгүй
> систем дээр бүү ашигла.

---

## Ажиллах бүрдэл (архитектур, товчхон)

```
Burp (extension)  ──JSON-RPC──►  relay bridge (Python)  ──►  pipeline engine
   Tatar Relay tab                127.0.0.1:8799              (decrypt / encrypt)
                                        ▲
                          session key   │  ──  JS hook (browser)
                          127.0.0.1:9091 (--capture)
```

Гурван зүйл зэрэг ажиллаж байх ёстой: **(1) bridge**, **(2) Burp extension (jar)**,
**(3) session key** (JS hook-оор автоматаар барих).

---

## Нэг удаагийн бэлтгэл

1. **Core суулгах** (нэг удаа):
   ```powershell
   cd "C:\Users\Admin\Desktop\Project\Tatar Relay"
   pip install -e .
   relay --version
   ```
2. **Extension ачаалах** (нэг удаа): Burp → **Extensions → Add** → Type **Java** →
   `burp\build\libs\tatar-relay-burp.jar`.
   Output tab-д `Tatar Relay loaded. bridge=http://127.0.0.1:8799` гэж гарна.

---

## Өдөр тутмын ажлын урсгал

### 1. Bridge асаах

```powershell
cd "C:\Users\Admin\Desktop\Project\Tatar Relay"
relay bridge <profile>.yaml --capture
```

Эсвэл дагалдах **`start-bridge.bat`**-ыг даблдах (доор үз).

Амжилттай бол:
```
tatar-relay capture  on http://127.0.0.1:9091/key  (var='session_key')
tatar-relay bridge   on http://127.0.0.1:8799  profiles=['<profile>']
```
> Энэ цонхыг **нээлттэй үлдээ** — хаавал bridge унтарна.

### 2. Session key барих (JS hook)

Login бүрт key өөрчлөгддөг тул hook-оор автоматаар барина. Хамгийн амар:

- Burp-ийн browser → target-ийн login хуудас → **F12 → Console** →
  `examples\js-hooks\session_key_capture.js`-ийн **бүх агуулгыг paste → Enter**.
- Эсвэл Burp **Proxy → Match and replace**-д hook-оо тогтмол дүрэм болгож тарь
  (`examples\js-hooks\BURP_INJECT_GUIDE.md` үз) — нэг удаа тохируулбал дараа автомат.

Дараа нь **апп руугаа нэвтэр.** Console-д `Key captured (…-bit)` гарна.

**Шалгах:** browser-т `http://127.0.0.1:9091/status` → `"ready":true` бол key орсон.

### 3. Request / Response задлаж харах

1. Target руу явсан encrypted request-ээ **Proxy → HTTP history**-оос ол.
2. Right-click → **Send to Repeater**.
3. Repeater дотор **request** дээрх **`Tatar Relay 🔓`** tab → plaintext JSON.
4. **Response** дээрх **`Tatar Relay 🔓`** tab → decrypt хийсэн response.
5. Plaintext-ээ засаад **Send** → буцаагаад re-encrypt + reseal хийж илгээнэ.

---

## `start-bridge.bat` (нэг даблаар асаах)

Repo-д багтсан `start-bridge.bat` нь bridge-ийг `--capture`-тэй асаана.

- **Даблдах** → анхдагч profile (`examples\acme-bank-mobile.yaml`) ашиглана.
- **Өөрийн profile-оор:** cmd-д `start-bridge.bat examples\<profile>.yaml`,
  эсвэл `.yaml` файлаа `start-bridge.bat` дээр чирж тавь (drag & drop).
- **Байнгын хувийн хувилбар:** `start-bridge.bat`-ыг хуулж `start-bridge.local.bat`
  болгож, дотор нь өөрийн profile-оо бич. Энэ нэр `.gitignore`-т орсон тул
  public repo-д орохгүй.

---

## Асуудал шийдэх (Troubleshooting)

| Шинж тэмдэг | Шалтгаан | Засвар |
|---|---|---|
| `bridge unreachable` (tab дотор) | Bridge асаагүй, эсвэл өөр порт | `relay bridge <profile> --capture` асаа. Extension нь **8799** хайдаг (Burp proxy порт биш) |
| `tag_mismatch` / `padding` | Session key буруу эсвэл хуучирсан | Дахин нэвтэрч key-гээ шинэчил (login бүрт өөрчлөгддөг) |
| `"ready":false` (/status) | JS hook key илгээгээгүй | Hook-оо тарьсан эсэх, дахин нэвтэрсэн эсэхээ шалга |
| `could not decrypt this response` | Profile-д `response` pipeline алга | Profile-дээ `response:` блок нэм, эсвэл зөвхөн request талд ажилла |
| `unknown profile` | Нэр таарахгүй | Bridge-д ганц profile ачаалбал автоматаар сонгогдоно; олон бол Burp-д `-Dtatar.profile=<нэр>` өг |
| Extension `bridge=...` буруу | Өөр порт тохируулсан | Burp-д `-Dtatar.bridge=http://127.0.0.1:8799` |

---

## Bridge зогсоох

- Асаасан цонхыг хаах, эсвэл:
  ```powershell
  Get-Process relay | Stop-Process
  ```

---

## CLI-аар (Burp-гүйгээр туршихад)

```powershell
relay validate <profile>.yaml
relay run     <profile>.yaml -i wire.bin --roundtrip --var session_key=<HEX>
relay run     <profile>.yaml --channel response -i resp.bin --var session_key=<HEX>
```
