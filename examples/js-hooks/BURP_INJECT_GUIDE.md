# Tatar Relay — Burp JS Inject Guide

<b><a href="#english">English</a> · <a href="#монгол">Монгол</a></b>

---

<a id="english"></a>

## English

Inject the session-key capture hook into the target app's page using Burp Suite
Pro's **Match and Replace** feature.  No new extension needed.

---

## Prerequisites

1. `relay capture` (or `relay bridge --capture`) is running on port 9091
2. Burp's browser has the target app's root page loaded (login page)

---

## Method A — Inject into `</head>` (recommended)

The hook is embedded as a base64 `data:` URI in a `<script>` tag so it survives
Content-Security-Policy headers that would block external `src=` URLs.

### Step 1 — Base64-encode the hook

```bash
# Linux / macOS
base64 -w 0 examples/js-hooks/session_key_capture.js > /tmp/hook.b64

# Windows PowerShell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("examples\js-hooks\session_key_capture.js")) |
  Out-File -NoNewline /tmp/hook.b64
```

### Step 2 — Add Burp Match & Replace rule

Burp Suite → **Proxy** → **Proxy settings** → **Match and replace rules** → **Add**

| Field        | Value                                                                 |
|--------------|-----------------------------------------------------------------------|
| Rule type    | `Response body`                                                      |
| Match (regex)| `</head>`                                                            |
| Replace      | `<script src="data:text/javascript;base64,PASTE_B64_HERE"></script></head>` |
| Comment      | `Tatar Relay key capture hook`                                       |

> Paste the content of `/tmp/hook.b64` in place of `PASTE_B64_HERE`.

### Step 3 — Enable the rule and reload the target page

Make sure the rule is **enabled** (checkbox on the left).
Reload the login page in Burp's browser — the hook will be injected on the
next response.

### Step 4 — Log in

Open DevTools (F12) in Burp's browser → Console.  You should see:

```
[Tatar Relay] Loaded — waiting for crypto operations…
[Tatar Relay] Passphrase hook installed (1 cipher(s))
```

After login:

```
[Tatar Relay] Key captured (256-bit) from AES.encrypt  →  a3f4c7d8…
```

The key is automatically sent to `http://127.0.0.1:9091/key`.

---

## Method B — Inject into a specific JS file

If the passphrase library is loaded as a separate file (e.g.
`cryptojs.min.js`, `crypto-bundle.js`), you can inject only into that file's
response to minimise footprint.

| Field        | Value                                           |
|--------------|-------------------------------------------------|
| Rule type    | `Response body`                                |
| Match (regex)| `^(var CryptoJS\s*=)` or `^(["']use strict["'])` |
| Replace      | `HOOK_CONTENT_INLINE\n$1`                      |

> Replace `HOOK_CONTENT_INLINE` with the full minified content of the hook.

---

## Method C — DevTools Console (manual, no rule needed)

The simplest approach for one-off testing:

1. Open Burp's browser → navigate to the target login page
2. Open DevTools → **Console** tab
3. Paste the contents of `session_key_capture.js` and press **Enter**
4. Log in — the key is captured and sent to port 9091

---

## Verify capture

```bash
# Check if the key arrived (readiness only — /status never returns the key:
# the sidecar allows cross-origin requests, so any page open in the same
# browser could otherwise read the live session key out of it)
curl http://127.0.0.1:9091/status
# → {"ok":true,"ready":true}

# Or watch relay capture output
relay capture --port 9091
# → ✅  Session key captured (256-bit AES):
#       a3f4c7d8e9f01234...
```

---

## After capture

```bash
# Option 1: one-shot decrypt
relay run myprofile.yaml -i captured_request.bin --var session_key=a3f4c7d8...

# Option 2: bridge with key already set
relay bridge myprofile.yaml --var session_key=a3f4c7d8...

# Option 3: bridge auto-captures on each new session
relay bridge myprofile.yaml --capture --capture-port 9091
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Hook not injected | Rule not enabled or wrong path | Check rule is active; reload page |
| No console output | CSP blocks inline scripts | Use `data:` URI method (Method A) |
| `fetch` fails silently | CORS or mixed-content block | Hook falls back to XHR; check port 9091 is up |
| `InvalidTag` on decrypt | Wrong key (from noise) | The hook logs multiple keys — use the last 256-bit one |
| Passphrase hook missing | Library loads after hook | Hook retries every 800ms — wait a moment after page load |

---

<a id="монгол"></a>

## Монгол

Session key барих hook-ийг Burp Suite Pro-гийн **Match and Replace** ашиглан
target аппын хуудсанд оруулна. Шинэ extension хэрэггүй.

---

### Урьдчилсан нөхцөл

1. `relay capture` (эсвэл `relay bridge --capture`) нь 9091 порт дээр ажиллаж байгаа
2. Burp-ийн хөтөч дээр target аппын нэвтрэх хуудас нээгдсэн байх

---

### А арга — `</head>` дотор оруулах (санал болгож буй)

Hook-ийг `<script>` тагт base64 `data:` URI хэлбэрээр суулгана. Ингэснээр
гадаад `src=` URL-ыг хориглодог Content-Security-Policy header-ийг давж гарна.

#### 1-р алхам — Hook-ийг base64 болгох

```bash
# Linux / macOS
base64 -w 0 examples/js-hooks/session_key_capture.js > /tmp/hook.b64

# Windows PowerShell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("examples\js-hooks\session_key_capture.js")) |
  Out-File -NoNewline /tmp/hook.b64
```

#### 2-р алхам — Burp-д Match & Replace дүрэм нэмэх

Burp Suite → **Proxy** → **Proxy settings** → **Match and replace rules** → **Add**

| Талбар | Утга |
|--------------|-----------------------------------------------------------------------|
| Rule type    | `Response body` |
| Match (regex)| `</head>` |
| Replace      | `<script src="data:text/javascript;base64,PASTE_B64_HERE"></script></head>` |
| Comment      | `Tatar Relay key capture hook` |

> `PASTE_B64_HERE` хэсэгт `/tmp/hook.b64`-ийн агуулгыг тавина.

#### 3-р алхам — Дүрмийг идэвхжүүлж, хуудсыг дахин ачаалах

Дүрмийн зүүн талын checkbox **идэвхтэй** эсэхийг шалга. Burp-ийн хөтөч дээр
нэвтрэх хуудсыг дахин ачаал — дараагийн response дээр hook орно.

#### 4-р алхам — Нэвтрэх

Burp-ийн хөтөч дээр DevTools (F12) → Console нээ. Дараах мөрүүд харагдана:

```
[Tatar Relay] Loaded — waiting for crypto operations…
[Tatar Relay] Passphrase hook installed (1 cipher(s))
```

Нэвтэрсний дараа:

```
[Tatar Relay] Key captured (256-bit) from AES.encrypt  →  a3f4c7d8…
```

Key нь `http://127.0.0.1:9091/key` рүү автоматаар илгээгдэнэ.

---

### Б арга — Тодорхой нэг JS файл дотор оруулах

Хэрэв passphrase-ийн сан тусдаа файлаар ачаалагддаг бол (ж: `cryptojs.min.js`,
`crypto-bundle.js`) зөвхөн тэр файлын response-д оруулж, ул мөрөө багасгаж болно.

| Талбар | Утга |
|--------------|-------------------------------------------------|
| Rule type    | `Response body` |
| Match (regex)| `^(var CryptoJS\s*=)` эсвэл `^(["']use strict["'])` |
| Replace      | `HOOK_CONTENT_INLINE\n$1` |

> `HOOK_CONTENT_INLINE`-ийн оронд hook-ийн бүтэн (minify хийсэн) агуулгыг тавина.

---

### В арга — DevTools Console (гараар, дүрэм хэрэггүй)

Нэг удаагийн тестэд хамгийн хялбар нь:

1. Burp-ийн хөтчөөр target нэвтрэх хуудас руу ор
2. DevTools → **Console** таб нээ
3. `session_key_capture.js`-ийн агуулгыг буулгаад **Enter** дар
4. Нэвтэр — key баригдаж 9091 порт руу илгээгдэнэ

---

### Барьсан эсэхийг шалгах

```bash
# Key ирсэн эсэхийг шалгах (зөвхөн бэлэн байдал — /status нь key-г ХЭЗЭЭ Ч
# буцаахгүй: sidecar нь cross-origin хүсэлт зөвшөөрдөг тул ижил хөтөч дээр
# нээлттэй байгаа дурын хуудас амьд session key-г уншиж чадах байсан)
curl http://127.0.0.1:9091/status
# → {"ok":true,"ready":true}

# Эсвэл relay capture-ийн гаралтыг хараарай
relay capture --port 9091
# → ✅  Session key captured (256-bit AES):
#       a3f4c7d8e9f01234...
```

---

### Барьсны дараа

```bash
# 1-р сонголт: нэг удаагийн decrypt
relay run myprofile.yaml -i captured_request.bin --var session_key=a3f4c7d8...

# 2-р сонголт: key-г урьдчилан өгсөн bridge
relay bridge myprofile.yaml --var session_key=a3f4c7d8...

# 3-р сонголт: session бүр дээр bridge өөрөө барина
relay bridge myprofile.yaml --capture --capture-port 9091
```

---

### Асуудал шийдвэрлэх

| Шинж тэмдэг | Шалтгаан | Засвар |
|---------|-------|-----|
| Hook ороогүй | Дүрэм идэвхгүй, эсвэл зам буруу | Дүрэм идэвхтэй эсэхийг шалга; хуудсыг дахин ачаал |
| Console дээр юу ч гарахгүй | CSP нь inline script-ийг хориглож байна | `data:` URI аргыг (А арга) хэрэглэ |
| `fetch` чимээгүй унана | CORS эсвэл mixed-content хориг | Hook нь XHR руу шилжинэ; 9091 порт асаалттай эсэхийг шалга |
| Decrypt дээр `InvalidTag` | Key буруу (чимээнээс авсан) | Hook хэд хэдэн key бичдэг — хамгийн сүүлийн 256-bit-ийг ашигла |
| Passphrase hook алга | Сан нь hook-оос хойш ачаалагдсан | Hook 800ms тутам дахин оролддог — хуудас ачаалагдсаны дараа хэсэг хүлээ |
