# Tatar Relay — Burp JS Inject Guide

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
# Check if the key arrived
curl http://127.0.0.1:9091/status
# → {"ok":true,"ready":true,"key":"a3f4c7d8..."}

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
